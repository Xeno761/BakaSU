// SPDX-License-Identifier: GPL-2.0-only
/*
 * Adapted from FinaSU's UTS namespace view, preserving its v1.6.4 ABI and field ownership rules.
 * https://github.com/LyraVoid/FinaSU/blob/ff0e34f1d9d5694ab7b4f1e318a77c781d65cb41/kernel/feature/uts_view.c
 */

#include "finasu_uts_view.h"

#include <linux/atomic.h>
#include <linux/build_bug.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "ksu.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "selinux/selinux.h"
#include "supercall/supercall.h"

static_assert(sizeof(struct ksu_uts_view_config) == 972);
static_assert(offsetof(struct ksu_uts_view_config, sysname) == 64);
static_assert(offsetof(struct ksu_uts_view_config, target_count) == 456);
static_assert(offsetof(struct ksu_uts_view_config, target_uids) == 460);
static_assert(sizeof_field(struct new_utsname, sysname) == KSU_UTS_NAME_LEN);
static_assert(KSU_FINASU_IOCTL_GET_UTS_VIEW_CONFIG == 0xc3cc4b19U);
static_assert(KSU_FINASU_IOCTL_SET_UTS_VIEW_CONFIG == 0x43cc4b1aU);
static_assert(__same_type(&ksu_finasu_uts_view_get_config_handler, (ksu_ioctl_handler_t)NULL));
static_assert(__same_type(&ksu_finasu_uts_view_set_config_handler, (ksu_ioctl_handler_t)NULL));

struct uts_view_namespace {
    struct hlist_node node;
    struct rcu_head rcu;
    struct uts_namespace *ns;
    u32 field_mask;
    struct new_utsname last_applied;
};

static DEFINE_MUTEX(uts_view_lock);
static DECLARE_WAIT_QUEUE_HEAD(uts_view_waitq);
static DEFINE_HASHTABLE(owned_namespaces, 6);
static atomic_t active_callbacks = ATOMIC_INIT(0);
static struct ksu_uts_view_config template_cfg;
static struct new_utsname global_restore_uts;
static struct new_utsname global_last_applied;
static struct rw_semaphore *uts_sem_ptr;
static struct uts_namespace *init_uts_ns_ptr;
static u32 global_owned_mask;
static bool feature_enabled;
static bool selected_active;
static bool supported;
static bool stopping;

static void uts_view_namespace_gc(struct work_struct *work);
static DECLARE_DELAYED_WORK(uts_view_gc_work, uts_view_namespace_gc);

static void free_owned_namespace(struct rcu_head *rcu)
{
    struct uts_view_namespace *owned = container_of(rcu, struct uts_view_namespace, rcu);

#if defined(CONFIG_UTS_NS) && !defined(MODULE)
    put_uts_ns(owned->ns);
#endif
    kfree(owned);
}

static void retire_owned_namespaces_locked(bool all)
{
    struct uts_view_namespace *owned;
    struct hlist_node *tmp;
    unsigned int bucket;

    hash_for_each_safe (owned_namespaces, bucket, tmp, owned, node) {
        /* The extra reference prevents namespace-address reuse while an RCU reader still sees the record. */
        if (!all && refcount_read(&owned->ns->ns.count) != 1)
            continue;
        hash_del_rcu(&owned->node);
        call_rcu(&owned->rcu, free_owned_namespace);
    }
}

static void uts_view_namespace_gc(struct work_struct *work)
{
    mutex_lock(&uts_view_lock);
    retire_owned_namespaces_locked(false);
    if (!stopping && !hash_empty(owned_namespaces))
        schedule_delayed_work(&uts_view_gc_work, round_jiffies_relative(10 * HZ));
    mutex_unlock(&uts_view_lock);
}

static u32 matching_owned_fields(const struct new_utsname *name, const struct new_utsname *applied, u32 owned_mask)
{
    u32 mask = 0;

#define KSU_UTS_MATCH_FIELD(bit, field)                                                                                \
    do {                                                                                                               \
        if ((owned_mask & (bit)) && !strncmp(name->field, applied->field, sizeof(name->field)))                        \
            mask |= (bit);                                                                                             \
    } while (0)
    KSU_UTS_MATCH_FIELD(KSU_UTS_FIELD_SYSNAME, sysname);
    KSU_UTS_MATCH_FIELD(KSU_UTS_FIELD_NODENAME, nodename);
    KSU_UTS_MATCH_FIELD(KSU_UTS_FIELD_RELEASE, release);
    KSU_UTS_MATCH_FIELD(KSU_UTS_FIELD_VERSION, version);
    KSU_UTS_MATCH_FIELD(KSU_UTS_FIELD_MACHINE, machine);
    KSU_UTS_MATCH_FIELD(KSU_UTS_FIELD_DOMAINNAME, domainname);
#undef KSU_UTS_MATCH_FIELD
    return mask;
}

u32 ksu_finasu_uts_view_current_mask(void)
{
    struct uts_view_namespace *owned;
    struct rw_semaphore *sem = READ_ONCE(uts_sem_ptr);
    struct uts_namespace *ns;
    u32 mask = 0;

    if (!sem || !current->nsproxy || !current->nsproxy->uts_ns)
        return 0;
    /* Never take uts_view_lock here: controls acquire that mutex before uts_sem(W). */
    lockdep_assert_held(sem);
    ns = current->nsproxy->uts_ns;
    if (ns == READ_ONCE(init_uts_ns_ptr))
        return matching_owned_fields(&ns->name, &global_last_applied, global_owned_mask);

    rcu_read_lock();
    hash_for_each_possible_rcu (owned_namespaces, owned, node, (unsigned long)ns) {
        if (owned->ns == ns) {
            mask = matching_owned_fields(&ns->name, &owned->last_applied, owned->field_mask);
            break;
        }
    }
    rcu_read_unlock();
    return mask;
}

static int validate_config(const struct ksu_uts_view_config *config)
{
    u32 i, j;

    if (config->field_mask & ~KSU_UTS_FIELD_VALID_MASK)
        return -EINVAL;
    if (config->mode != KSU_UTS_MODE_GLOBAL && config->mode != KSU_UTS_MODE_SELECTED)
        return -EINVAL;
    if (config->target_count > KSU_UTS_MAX_TARGETS)
        return -EINVAL;
    for (i = 0; i < config->target_count; i++) {
        if (config->target_uids[i] < FIRST_APPLICATION_UID)
            return -EINVAL;
        for (j = 0; j < i; j++) {
            if (config->target_uids[i] == config->target_uids[j])
                return -EINVAL;
        }
    }

#define KSU_UTS_INVALID_FIELD(bit, field)                                                                              \
    ((config->field_mask & (bit)) && !memchr(config->field, '\0', sizeof(config->field)))
    if (KSU_UTS_INVALID_FIELD(KSU_UTS_FIELD_SYSNAME, sysname) ||
        KSU_UTS_INVALID_FIELD(KSU_UTS_FIELD_NODENAME, nodename) ||
        KSU_UTS_INVALID_FIELD(KSU_UTS_FIELD_RELEASE, release) ||
        KSU_UTS_INVALID_FIELD(KSU_UTS_FIELD_VERSION, version) ||
        KSU_UTS_INVALID_FIELD(KSU_UTS_FIELD_MACHINE, machine) ||
        KSU_UTS_INVALID_FIELD(KSU_UTS_FIELD_DOMAINNAME, domainname))
        return -EINVAL;
#undef KSU_UTS_INVALID_FIELD
    return 0;
}

static void apply_global_locked(const struct ksu_uts_view_config *tmpl)
{
    struct new_utsname *active_name = &init_uts_ns_ptr->name;
    u32 old_mask = global_owned_mask;
    u32 new_mask = tmpl->field_mask & KSU_UTS_FIELD_VALID_MASK;

    down_write(uts_sem_ptr);
    /* Preserve external writers, including changes made while a field was owned by this feature. */
#define KSU_UTS_UPDATE_FIELD(bit, field)                                                                               \
    do {                                                                                                               \
        if (new_mask & (bit)) {                                                                                        \
            if (!(old_mask & (bit)) ||                                                                                 \
                strncmp(active_name->field, global_last_applied.field, sizeof(active_name->field)))                    \
                strscpy(global_restore_uts.field, active_name->field, sizeof(active_name->field));                     \
            strscpy(active_name->field, tmpl->field, sizeof(active_name->field));                                      \
            strscpy(global_last_applied.field, tmpl->field, sizeof(global_last_applied.field));                        \
        } else if ((old_mask & (bit)) &&                                                                               \
                   !strncmp(active_name->field, global_last_applied.field, sizeof(active_name->field))) {              \
            strscpy(active_name->field, global_restore_uts.field, sizeof(active_name->field));                         \
        }                                                                                                              \
    } while (0)
    KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_SYSNAME, sysname);
    KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_NODENAME, nodename);
    KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_RELEASE, release);
    KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_VERSION, version);
    KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_MACHINE, machine);
    KSU_UTS_UPDATE_FIELD(KSU_UTS_FIELD_DOMAINNAME, domainname);
#undef KSU_UTS_UPDATE_FIELD
    global_owned_mask = new_mask;
    up_write(uts_sem_ptr);
}

static void restore_global_locked(void)
{
    struct ksu_uts_view_config empty = { .mode = KSU_UTS_MODE_GLOBAL };

    apply_global_locked(&empty);
    memset(&global_restore_uts, 0, sizeof(global_restore_uts));
    memset(&global_last_applied, 0, sizeof(global_last_applied));
}

static bool uts_view_active_locked(void)
{
    return supported && !stopping && feature_enabled && template_cfg.field_mask &&
           (template_cfg.mode & KSU_UTS_MODE_VALID_MASK);
}

static void refresh_active_locked(void)
{
    WRITE_ONCE(selected_active, uts_view_active_locked() && template_cfg.mode == KSU_UTS_MODE_SELECTED);
}

static void reset_observation_locked(void)
{
    if (!++template_cfg.generation)
        ++template_cfg.generation;
    template_cfg.state = 0;
    template_cfg.matched = 0;
    template_cfg.discarded = 0;
    template_cfg.last_pid = 0;
    template_cfg.last_uid = 0;
    template_cfg.skip_not_app = 0;
    template_cfg.skip_isolated = 0;
    template_cfg.skip_not_target = 0;
    template_cfg.skip_not_zygote = 0;
    template_cfg.skip_private_ns = 0;
    template_cfg.reserved0 = 0;
    template_cfg.unshare_failed = 0;
    template_cfg.merge_missing_ns = 0;
}

int ksu_finasu_uts_view_feature_get(u64 *value)
{
    int ret = 0;

    if (!value)
        return -EINVAL;
    mutex_lock(&uts_view_lock);
    if (!supported || stopping)
        ret = -ENODEV;
    else
        *value = feature_enabled ? 1 : 0;
    mutex_unlock(&uts_view_lock);
    return ret;
}

int ksu_finasu_uts_view_feature_set(u64 value)
{
    bool enable = value != 0;
    int ret = 0;

    mutex_lock(&uts_view_lock);
    if (!supported || stopping) {
        ret = -ENODEV;
        goto out;
    }
    if (enable &&
        (!template_cfg.field_mask || (template_cfg.mode == KSU_UTS_MODE_SELECTED && !template_cfg.target_count))) {
        ret = -ENODATA;
        goto out;
    }
    if (template_cfg.mode == KSU_UTS_MODE_GLOBAL) {
        if (enable && !feature_enabled)
            apply_global_locked(&template_cfg);
        else if (!enable && (feature_enabled || global_owned_mask))
            restore_global_locked();
    }
    feature_enabled = enable;
    reset_observation_locked();
    refresh_active_locked();
out:
    mutex_unlock(&uts_view_lock);
    return ret;
}

static struct ksu_feature_handler uts_view_handler = {
    .name = "uts_view",
    .get_handler = ksu_finasu_uts_view_feature_get,
    .set_handler = ksu_finasu_uts_view_feature_set,
};

int __init ksu_finasu_uts_view_init(u32 feature_id)
{
    /* This native backend relies on linked namespace internals, not a syscall-table patch. */
#if !defined(CONFIG_UTS_NS) || defined(MODULE)
    return -EOPNOTSUPP;
#else
    int ret;

    mutex_lock(&uts_view_lock);
    if (supported || stopping) {
        mutex_unlock(&uts_view_lock);
        return -EBUSY;
    }
    WRITE_ONCE(uts_sem_ptr, &uts_sem);
    WRITE_ONCE(init_uts_ns_ptr, &init_uts_ns);
    memset(&template_cfg, 0, sizeof(template_cfg));
    reset_observation_locked();
    supported = true;
    uts_view_handler.feature_id = feature_id;
    mutex_unlock(&uts_view_lock);

    ret = ksu_register_feature_handler(&uts_view_handler);
    if (ret) {
        mutex_lock(&uts_view_lock);
        supported = false;
        WRITE_ONCE(uts_sem_ptr, NULL);
        WRITE_ONCE(init_uts_ns_ptr, NULL);
        mutex_unlock(&uts_view_lock);
    }
    return ret;
#endif
}

void ksu_finasu_uts_view_exit(void)
{
    bool registered;

    mutex_lock(&uts_view_lock);
    registered = supported;
    stopping = true;
    WRITE_ONCE(selected_active, false);
    mutex_unlock(&uts_view_lock);
    cancel_delayed_work_sync(&uts_view_gc_work);
    wait_event(uts_view_waitq, atomic_read(&active_callbacks) == 0);
    if (registered)
        ksu_unregister_feature_handler(uts_view_handler.feature_id);

    mutex_lock(&uts_view_lock);
    if (global_owned_mask && uts_sem_ptr && init_uts_ns_ptr)
        restore_global_locked();
    retire_owned_namespaces_locked(true);
    memset(&template_cfg, 0, sizeof(template_cfg));
    feature_enabled = false;
    supported = false;
    WRITE_ONCE(uts_sem_ptr, NULL);
    WRITE_ONCE(init_uts_ns_ptr, NULL);
    mutex_unlock(&uts_view_lock);
}

int ksu_finasu_uts_view_get_config(struct ksu_uts_view_config *config)
{
    int ret = 0;

    if (!config)
        return -EINVAL;
    mutex_lock(&uts_view_lock);
    if (!supported || stopping) {
        ret = -ENODEV;
    } else {
        *config = template_cfg;
        config->state = KSU_UTS_STATE_SUPPORTED;
        if (uts_view_active_locked())
            config->state |= KSU_UTS_STATE_ACTIVE;
        if (selected_active && template_cfg.matched)
            config->state |= KSU_UTS_STATE_OBSERVED;
    }
    mutex_unlock(&uts_view_lock);
    return ret;
}

int ksu_finasu_uts_view_set_config(const struct ksu_uts_view_config *config)
{
    struct ksu_uts_view_config next;
    bool was_global, will_global;
    u32 generation;
    int ret;

    if (!config)
        return -EINVAL;
    next = *config;
    if (!next.mode)
        next.mode = KSU_UTS_MODE_SELECTED;
    ret = validate_config(&next);
    if (ret)
        return ret;

    mutex_lock(&uts_view_lock);
    if (!supported || stopping) {
        ret = -ENODEV;
        goto out;
    }
    was_global = uts_view_active_locked() && template_cfg.mode == KSU_UTS_MODE_GLOBAL;
    will_global = feature_enabled && next.field_mask && next.mode == KSU_UTS_MODE_GLOBAL;
    if (was_global && !will_global)
        restore_global_locked();
    generation = template_cfg.generation;
    template_cfg = next;
    template_cfg.generation = generation;
    if (will_global)
        apply_global_locked(&template_cfg);
    reset_observation_locked();
    refresh_active_locked();
    ret = 0;
out:
    mutex_unlock(&uts_view_lock);
    return ret;
}

int ksu_finasu_uts_view_get_config_handler(void __user *arg)
{
    struct ksu_uts_view_config config;
    int ret = ksu_finasu_uts_view_get_config(&config);

    if (ret)
        return ret;
    return copy_to_user(arg, &config, sizeof(config)) ? -EFAULT : 0;
}

int ksu_finasu_uts_view_set_config_handler(void __user *arg)
{
    struct ksu_uts_view_config config;

    if (copy_from_user(&config, arg, sizeof(config)))
        return -EFAULT;
    return ksu_finasu_uts_view_set_config(&config);
}

static void merge_template(struct new_utsname *dst, const struct ksu_uts_view_config *tmpl)
{
#define KSU_UTS_MERGE_FIELD(bit, field)                                                                                \
    do {                                                                                                               \
        if (tmpl->field_mask & (bit))                                                                                  \
            strscpy(dst->field, tmpl->field, sizeof(dst->field));                                                      \
    } while (0)
    KSU_UTS_MERGE_FIELD(KSU_UTS_FIELD_SYSNAME, sysname);
    KSU_UTS_MERGE_FIELD(KSU_UTS_FIELD_NODENAME, nodename);
    KSU_UTS_MERGE_FIELD(KSU_UTS_FIELD_RELEASE, release);
    KSU_UTS_MERGE_FIELD(KSU_UTS_FIELD_VERSION, version);
    KSU_UTS_MERGE_FIELD(KSU_UTS_FIELD_MACHINE, machine);
    KSU_UTS_MERGE_FIELD(KSU_UTS_FIELD_DOMAINNAME, domainname);
#undef KSU_UTS_MERGE_FIELD
}

void ksu_finasu_uts_view_apply_for_uid(u32 target_uid)
{
    struct ksu_uts_view_config snapshot;
    struct uts_view_namespace *owned;
    const struct cred *saved;
    u32 i;
    int ret;

    if (!READ_ONCE(selected_active))
        return;
    mutex_lock(&uts_view_lock);
    if (!selected_active || !supported || stopping)
        goto skip;
    if ((current->flags & PF_KTHREAD) || !current->nsproxy || !current->nsproxy->uts_ns || !ksu_cred)
        goto skip;
    if (is_isolated_process(target_uid)) {
        template_cfg.skip_isolated++;
        goto skip;
    }
    if (!is_appuid(target_uid)) {
        template_cfg.skip_not_app++;
        goto skip;
    }
    if (!is_zygote(current_cred())) {
        template_cfg.skip_not_zygote++;
        goto skip;
    }
    for (i = 0; i < template_cfg.target_count; i++) {
        if (template_cfg.target_uids[i] == target_uid)
            break;
    }
    if (i == template_cfg.target_count) {
        template_cfg.skip_not_target++;
        goto skip;
    }
    if (current->nsproxy->uts_ns != init_uts_ns_ptr) {
        template_cfg.skip_private_ns++;
        goto skip;
    }
    snapshot = template_cfg;
    atomic_inc(&active_callbacks);
    mutex_unlock(&uts_view_lock);

    /* Do not install untraceable fields: the uname precedence hook needs exact namespace ownership. */
    owned = kzalloc(sizeof(*owned), GFP_KERNEL);
    if (!owned) {
        ret = -ENOMEM;
        goto finish;
    }
    saved = override_creds(ksu_cred);
#if defined(CONFIG_UTS_NS) && !defined(MODULE)
    ret = ksys_unshare(CLONE_NEWUTS);
#else
    ret = -EOPNOTSUPP;
#endif
    revert_creds(saved);

finish:
    mutex_lock(&uts_view_lock);
    if (stopping || !selected_active || !feature_enabled || template_cfg.generation != snapshot.generation) {
        template_cfg.discarded++;
    } else if (ret) {
        template_cfg.unshare_failed++;
        pr_warn_ratelimited("finasu_uts_view: unshare failed pid=%d uid=%u error=%d\n", current->pid, target_uid, ret);
    } else if (!current->nsproxy || !current->nsproxy->uts_ns || current->nsproxy->uts_ns == init_uts_ns_ptr) {
        template_cfg.merge_missing_ns++;
    } else {
        down_write(uts_sem_ptr);
        merge_template(&current->nsproxy->uts_ns->name, &snapshot);
        owned->ns = current->nsproxy->uts_ns;
        owned->field_mask = snapshot.field_mask;
        owned->last_applied = owned->ns->name;
        get_uts_ns(owned->ns);
        hash_add_rcu(owned_namespaces, &owned->node, (unsigned long)owned->ns);
        up_write(uts_sem_ptr);
        owned = NULL;
        schedule_delayed_work(&uts_view_gc_work, round_jiffies_relative(10 * HZ));
        template_cfg.last_pid = current->pid;
        template_cfg.last_uid = target_uid;
        if (!template_cfg.matched++)
            pr_info("finasu_uts_view: observed pid=%d uid=%u generation=%u\n", current->pid, target_uid,
                    template_cfg.generation);
    }
    mutex_unlock(&uts_view_lock);
    kfree(owned);
    if (atomic_dec_and_test(&active_callbacks))
        wake_up(&uts_view_waitq);
    return;

skip:
    mutex_unlock(&uts_view_lock);
}
