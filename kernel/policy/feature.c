#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep

#include <linux/version.h>
#include <linux/bitmap.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/string.h>
#ifdef CONFIG_KSU_SUSFS
#include <linux/static_key.h>

extern struct static_key_false susfs_is_avc_log_spoofing_enabled;
extern u32 susfs_ksu_sid;
extern u32 susfs_priv_app_sid;
DEFINE_STATIC_KEY_FALSE(ksu_avc_log_spoof_full_enabled);
#endif

#include "compat/kernel_compat.h"

static const struct ksu_feature_handler *feature_handlers[KSU_FEATURE_SLOT_COUNT];

static DEFINE_MUTEX(feature_mutex);

static const char *const feature_names[KSU_FEATURE_SLOT_COUNT] = {
    [KSU_FEATURE_SU_COMPAT] = "su_compat",
    [KSU_FEATURE_KERNEL_UMOUNT] = "kernel_umount",
    [KSU_FEATURE_SULOG] = "sulog",
    [KSU_FEATURE_ADB_ROOT] = "adb_root",
    [KSU_FEATURE_SELINUX_HIDE] = "selinux_hide",
    [KSU_FEATURE_SHELL_SU_ADB_ONLY] = "shell_su_adb_only",
    [KSU_FEATURE_MAX] = "avc_spoof",
    [KSU_FEATURE_MAX + 1] = "avc_spoof_full",
    [KSU_FEATURE_MAX + 2] = "dynamic_manager",
    [KSU_FEATURE_MAX + 3] = "dynamic_manager_grants",
    [KSU_FEATURE_MAX + 4] = "uts_view",
    [KSU_FEATURE_MAX + 5] = "mount_view_filter",
};

static const u32 feature_ids[KSU_FEATURE_SLOT_COUNT] = {
    KSU_FEATURE_SU_COMPAT, KSU_FEATURE_KERNEL_UMOUNT, KSU_FEATURE_SULOG, KSU_FEATURE_ADB_ROOT,
    KSU_FEATURE_SELINUX_HIDE, 5, KSU_FEATURE_SHELL_SU_ADB_ONLY,
    KSU_FEATURE_AVC_SPOOF, KSU_FEATURE_AVC_SPOOF_FULL, KSU_FEATURE_FINASU_DYNAMIC_MANAGER,
    KSU_FEATURE_FINASU_DYNAMIC_MANAGER_GRANTS, KSU_FEATURE_FINASU_UTS_VIEW, KSU_FEATURE_FINASU_MOUNT_VIEW_FILTER,
};

static int feature_slot(u32 feature_id)
{
    int i;

    for (i = 0; i < KSU_FEATURE_SLOT_COUNT; i++) {
        if (feature_ids[i] == feature_id)
            return i;
    }
    return -EINVAL;
}

#ifdef CONFIG_KSU_SUSFS
static int avc_spoof_feature_get(u64 *value)
{
    *value = static_key_enabled(&susfs_is_avc_log_spoofing_enabled) ? 1 : 0;
    return 0;
}

static int set_avc_spoof(u64 value, bool full)
{
    u32 ksu_sid = READ_ONCE(susfs_ksu_sid);
    u32 cover_sid = READ_ONCE(susfs_priv_app_sid);

    if (value > 1)
        return -EINVAL;
    if (value && (!ksu_sid || !cover_sid || ksu_sid == cover_sid))
        return -EOPNOTSUPP;

    if (value && full)
        static_branch_enable(&ksu_avc_log_spoof_full_enabled);
    else
        static_branch_disable(&ksu_avc_log_spoof_full_enabled);
    if (value)
        static_branch_enable(&susfs_is_avc_log_spoofing_enabled);
    else
        static_branch_disable(&susfs_is_avc_log_spoofing_enabled);
    return 0;
}

static int avc_spoof_feature_set(u64 value)
{
    return set_avc_spoof(value, false);
}

static const struct ksu_feature_handler avc_spoof_handler = {
    .feature_id = KSU_FEATURE_AVC_SPOOF,
    .name = "avc_spoof",
    .get_handler = avc_spoof_feature_get,
    .set_handler = avc_spoof_feature_set,
};

#if IS_BUILTIN(CONFIG_KSU)
static int avc_spoof_full_feature_get(u64 *value)
{
    *value = static_key_enabled(&susfs_is_avc_log_spoofing_enabled) &&
        static_key_enabled(&ksu_avc_log_spoof_full_enabled) ? 1 : 0;
    return 0;
}

static int avc_spoof_full_feature_set(u64 value)
{
    return set_avc_spoof(value, true);
}

static const struct ksu_feature_handler avc_spoof_full_handler = {
    .feature_id = KSU_FEATURE_AVC_SPOOF_FULL,
    .name = "avc_spoof_full",
    .get_handler = avc_spoof_full_feature_get,
    .set_handler = avc_spoof_full_feature_set,
};
#endif
#endif

// Features forced by boot config. Written only while parsing module params
// (before kernelsu_init), read-only afterwards.
static u64 forced_values[KSU_FEATURE_SLOT_COUNT];
static DECLARE_BITMAP(forced_mask, KSU_FEATURE_SLOT_COUNT);
// Forced features whose value has not been applied successfully yet
static DECLARE_BITMAP(forced_pending, KSU_FEATURE_SLOT_COUNT);

static int parse_feature_id(const char *name, u32 *id)
{
    u32 i;
    int slot;

    if (!kstrtou32(name, 10, id)) {
        slot = feature_slot(*id);
        if (slot < 0)
            return slot;
        *id = slot;
        return 0;
    }

    for (i = 0; i < KSU_FEATURE_SLOT_COUNT; i++) {
        if (feature_names[i] && !strcasecmp(name, feature_names[i])) {
            *id = i;
            return 0;
        }
    }

    return -EINVAL;
}

// force_feature=<name|id>:<value>[,<name|id>:<value>...]
// May be specified multiple times. Invalid entries are skipped instead of
// failing, as a param error would prevent KernelSU from loading at all.
// This may run before the slab allocator is up (built-in), so don't allocate.
static int force_feature_param_set(const char *val, const struct kernel_param *kp)
{
    char name[32], num[24];
    const char *p = val, *end, *sep;
    size_t name_len, num_len;
    u32 id;
    u64 value;

    if (!val) {
        return 0;
    }

    for (; *p; p = *end ? end + 1 : end) {
        end = strchrnul(p, ',');
        if (end == p) {
            continue;
        }

        sep = memchr(p, ':', end - p);
        name_len = sep ? sep - p : 0;
        num_len = sep ? end - sep - 1 : 0;
        if (!name_len || name_len >= sizeof(name) || !num_len || num_len >= sizeof(num)) {
            pr_err("feature: invalid force_feature entry '%.*s'\n", (int)(end - p), p);
            continue;
        }

        memcpy(name, p, name_len);
        name[name_len] = '\0';
        memcpy(num, sep + 1, num_len);
        num[num_len] = '\0';

        if (parse_feature_id(name, &id) || kstrtou64(num, 0, &value)) {
            pr_err("feature: invalid force_feature entry '%s:%s'\n", name, num);
            continue;
        }

        if (feature_ids[id] == KSU_FEATURE_AVC_SPOOF || feature_ids[id] == KSU_FEATURE_AVC_SPOOF_FULL) {
            int other = feature_slot(feature_ids[id] == KSU_FEATURE_AVC_SPOOF ?
                                     KSU_FEATURE_AVC_SPOOF_FULL : KSU_FEATURE_AVC_SPOOF);

            if (test_bit(other, forced_mask) && forced_values[other] != value) {
                pr_warn("feature: conflicting forced AVC modes\n");
                continue;
            }
        }

        forced_values[id] = value;
        set_bit(id, forced_mask);
        set_bit(id, forced_pending);
        pr_info("feature: %s (id=%u) forced to %llu\n", feature_names[id], feature_ids[id], value);
    }

    return 0;
}

static const struct kernel_param_ops force_feature_param_ops = {
// A bare `force_feature` would otherwise fail parse_args() and the whole module load
// https://github.com/torvalds/linux/commit/6a4c264313c4ae32dc53821a9c57e0dc9696fb81
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0) || defined(KSU_COMPAT_HAS_KERNEL_PARAM_OPS_FL_NOARG)
    .flags = KERNEL_PARAM_OPS_FL_NOARG,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) || defined(KSU_COMPAT_HAS_KERNEL_PARAM_FL_NOARG)
    .flags = KERNEL_PARAM_FL_NOARG,
#endif
    .set = force_feature_param_set,
};
module_param_cb(force_feature, &force_feature_param_ops, NULL, 0);

int __init ksu_register_feature_handler(const struct ksu_feature_handler *handler)
{
    int slot;

    if (!handler) {
        pr_err("feature: register handler is NULL\n");
        return -EINVAL;
    }

    slot = feature_slot(handler->feature_id);
    if (slot < 0) {
        pr_err("feature: invalid feature_id %u\n", handler->feature_id);
        return -EINVAL;
    }

    if (!handler->get_handler && !handler->set_handler) {
        pr_err("feature: no handler provided for feature %u\n", handler->feature_id);
        return -EINVAL;
    }

    mutex_lock(&feature_mutex);

    if (feature_handlers[slot]) {
        pr_warn("feature: handler for %u already registered, overwriting\n", handler->feature_id);
    }

    feature_handlers[slot] = handler;

    pr_info("feature: registered handler for %s (id=%u)\n", handler->name ? handler->name : "unknown",
            handler->feature_id);

    mutex_unlock(&feature_mutex);
    return 0;
}

int ksu_unregister_feature_handler(u32 feature_id)
{
    int ret = 0;
    int slot = feature_slot(feature_id);

    if (slot < 0) {
        pr_err("feature: invalid feature_id %u\n", feature_id);
        return -EINVAL;
    }

    mutex_lock(&feature_mutex);

    if (!feature_handlers[slot]) {
        pr_warn("feature: no handler registered for %u\n", feature_id);
        ret = -ENOENT;
        goto out;
    }

    feature_handlers[slot] = NULL;

    pr_info("feature: unregistered handler for id=%u\n", feature_id);

out:
    mutex_unlock(&feature_mutex);
    return ret;
}

int ksu_get_feature(u32 feature_id, u64 *value, bool *supported)
{
    int ret = 0;
    int slot = feature_slot(feature_id);
    const struct ksu_feature_handler *handler;

    if (!value || !supported) {
        pr_err("feature: invalid parameters\n");
        return -EINVAL;
    }

    *value = 0;
    *supported = false;
    if (slot < 0) {
        pr_err("feature: invalid feature_id %u\n", feature_id);
        return -EINVAL;
    }

    mutex_lock(&feature_mutex);

    handler = feature_handlers[slot];

    if (!handler) {
        *supported = false;
        *value = 0;
        pr_debug("feature: feature %u not supported\n", feature_id);
        goto out;
    }

    *supported = true;

    if (!handler->get_handler) {
        pr_warn("feature: no get_handler for feature %u\n", feature_id);
        ret = -EOPNOTSUPP;
        goto out;
    }

    ret = handler->get_handler(value);
    if (ret) {
        pr_err("feature: get_handler for %u failed: %d\n", feature_id, ret);
    }

out:
    mutex_unlock(&feature_mutex);
    return ret;
}

int ksu_set_feature(u32 feature_id, u64 value)
{
    int ret = 0;
    int slot = feature_slot(feature_id);
    const struct ksu_feature_handler *handler;

    if (slot < 0) {
        pr_err("feature: invalid feature_id %u\n", feature_id);
        return -EINVAL;
    }

    if (ksu_feature_is_forced(feature_id)) {
        pr_warn("feature: feature %u is forced by boot config\n", feature_id);
        return -EPERM;
    }

    mutex_lock(&feature_mutex);

    handler = feature_handlers[slot];

    if (!handler) {
        pr_err("feature: feature %u not registered\n", feature_id);
        ret = -EOPNOTSUPP;
        goto out;
    }

    if (!handler->set_handler) {
        pr_warn("feature: no set_handler for feature %u\n", feature_id);
        ret = -EOPNOTSUPP;
        goto out;
    }

    ret = handler->set_handler(value);
    if (ret) {
        pr_err("feature: set_handler for %u failed: %d\n", feature_id, ret);
    }

out:
    mutex_unlock(&feature_mutex);
    return ret;
}

bool ksu_feature_is_forced(u32 feature_id)
{
    int slot = feature_slot(feature_id);

    if (slot < 0)
        return false;
    if (feature_id == KSU_FEATURE_AVC_SPOOF || feature_id == KSU_FEATURE_AVC_SPOOF_FULL)
        return test_bit(feature_slot(KSU_FEATURE_AVC_SPOOF), forced_mask) ||
            test_bit(feature_slot(KSU_FEATURE_AVC_SPOOF_FULL), forced_mask);
    return test_bit(slot, forced_mask);
}

void ksu_feature_apply_forced(void)
{
    const struct ksu_feature_handler *handler;
    unsigned int id;
    int ret;

    mutex_lock(&feature_mutex);

    for_each_set_bit (id, forced_pending, KSU_FEATURE_SLOT_COUNT) {
        handler = feature_handlers[id];
        if (!handler || !handler->set_handler) {
            continue;
        }

        ret = handler->set_handler(forced_values[id]);
        if (ret) {
            pr_warn("feature: apply forced %s=%llu failed: %d\n", feature_names[id], forced_values[id], ret);
            continue;
        }

        clear_bit(id, forced_pending);
        pr_info("feature: applied forced %s=%llu\n", feature_names[id], forced_values[id]);
    }

    mutex_unlock(&feature_mutex);
}

void __init ksu_feature_init(void)
{
    int i;

    for (i = 0; i < KSU_FEATURE_SLOT_COUNT; i++) {
        feature_handlers[i] = NULL;
    }

#ifdef CONFIG_KSU_SUSFS
    ksu_register_feature_handler(&avc_spoof_handler);
#if IS_BUILTIN(CONFIG_KSU)
    ksu_register_feature_handler(&avc_spoof_full_handler);
#endif
#endif

    pr_info("feature: feature management initialized\n");
}

void __exit ksu_feature_exit(void)
{
    int i;

    mutex_lock(&feature_mutex);

    for (i = 0; i < KSU_FEATURE_SLOT_COUNT; i++) {
        feature_handlers[i] = NULL;
    }

    mutex_unlock(&feature_mutex);

    pr_info("feature: feature management cleaned up\n");
}
