#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include "manager_identity.h"
#include "feature/finasu_dynamic_manager.h"
#include "ksu.h"
#include "uapi/supercall.h"
#include "compat/kernel_compat.h"

u32 ksu_last_manager_appid = KSU_INVALID_APPID;

struct ksu_manager_node {
    u8 signature_index;
    u32 uapi_version;
    u32 appid;
    struct list_head list;
    struct rcu_head rcu;
};

static LIST_HEAD(ksu_manager_appid_list);
static DEFINE_SPINLOCK(ksu_manager_list_write_lock);

/* Called with the write lock held, including after removing the selected UID. */
static void repair_manager_selection(void)
{
    struct ksu_manager_node *pos;
    u32 appid = READ_ONCE(ksu_last_manager_appid);
    u32 first = KSU_INVALID_APPID;

    list_for_each_entry (pos, &ksu_manager_appid_list, list) {
        if (!ksu_finasu_dynamic_manager_uid_allowed(pos->appid, pos->signature_index))
            continue;
        if (first == KSU_INVALID_APPID)
            first = pos->appid;
        if (pos->appid == appid)
            return;
    }

    WRITE_ONCE(ksu_last_manager_appid, first);
}

void ksu_mark_manager(u32 uid)
{
    struct ksu_manager_node *pos;
    u32 appid = uid % PER_USER_RANGE;

    spin_lock(&ksu_manager_list_write_lock);
    list_for_each_entry (pos, &ksu_manager_appid_list, list) {
        if (pos->appid == appid && ksu_finasu_dynamic_manager_uid_allowed(uid, pos->signature_index)) {
            WRITE_ONCE(ksu_last_manager_appid, appid);
            break;
        }
    }
    spin_unlock(&ksu_manager_list_write_lock);
}

u32 ksu_get_manager_appid(void)
{
    u32 appid = READ_ONCE(ksu_last_manager_appid);

    return ksu_is_manager_appid(appid) ? appid : KSU_INVALID_APPID;
}

bool ksu_is_manager_appid(u32 appid)
{
    bool found = false;
    struct ksu_manager_node *pos;

    rcu_read_lock();
    list_for_each_entry_rcu (pos, &ksu_manager_appid_list, list) {
        if (pos->appid == appid) {
            found = ksu_finasu_dynamic_manager_uid_allowed(appid, pos->signature_index);
            break;
        }
    }
    rcu_read_unlock();

    return found;
}

bool ksu_is_manager_uid(u32 uid)
{
    u32 appid = uid % PER_USER_RANGE;

    return ksu_is_manager_appid(appid);
}

bool is_manager(void)
{
    return ksu_is_manager_uid(ksu_get_uid_t(current_uid()));
}

void ksu_register_manager_with_uapi(u32 uid, u8 signature_index, u32 uapi)
{
    struct ksu_manager_node *node, *pos;
    u32 appid;

    node = kzalloc(sizeof(*node), GFP_ATOMIC);
    if (unlikely(!node))
        return;

    appid = uid % PER_USER_RANGE;

    node->appid = appid;
    node->signature_index = signature_index;
    node->uapi_version = uapi;

    spin_lock(&ksu_manager_list_write_lock);

    /* Raw presence remains unique even if a Fina grant has just been withdrawn. */
    list_for_each_entry (pos, &ksu_manager_appid_list, list) {
        if (pos->appid == appid) {
            spin_unlock(&ksu_manager_list_write_lock);
            kfree(node);
            return;
        }
    }

    list_add_tail_rcu(&node->list, &ksu_manager_appid_list);

    repair_manager_selection();

    spin_unlock(&ksu_manager_list_write_lock);
    return;
}

void ksu_register_manager(u32 uid, u8 signature_index)
{
    ksu_register_manager_with_uapi(uid, signature_index, 0);
}

u32 ksu_get_manager_uapi_by_appid(u32 appid)
{
    struct ksu_manager_node *pos;
    u32 uapi = 0;

    rcu_read_lock();
    list_for_each_entry_rcu (pos, &ksu_manager_appid_list, list) {
        if (pos->appid == appid) {
            uapi = pos->uapi_version;
            break;
        }
    }
    rcu_read_unlock();
    return uapi;
}

u32 ksu_get_manager_appid_by_signature(u8 signature_index)
{
    struct ksu_manager_node *pos;
    u32 selected = READ_ONCE(ksu_last_manager_appid);
    u32 appid = KSU_INVALID_APPID;

    rcu_read_lock();
    list_for_each_entry_rcu (pos, &ksu_manager_appid_list, list) {
        if (pos->signature_index != signature_index ||
            !ksu_finasu_dynamic_manager_uid_allowed(pos->appid, pos->signature_index))
            continue;
        if (appid == KSU_INVALID_APPID)
            appid = pos->appid;
        if (pos->appid == selected) {
            appid = selected;
            break;
        }
    }
    rcu_read_unlock();
    return appid;
}

void ksu_unregister_manager(u32 uid)
{
    struct ksu_manager_node *pos, *tmp;
    u32 appid = uid % PER_USER_RANGE;

    spin_lock(&ksu_manager_list_write_lock);

    list_for_each_entry_safe (pos, tmp, &ksu_manager_appid_list, list) {
        if (pos->appid == appid) {
            list_del_rcu(&pos->list);
            kfree_rcu(pos, rcu);
            break;
        }
    }

    repair_manager_selection();
    spin_unlock(&ksu_manager_list_write_lock);
    return;
}

void ksu_unregister_manager_by_signature_index(u8 signature_index)
{
    struct ksu_manager_node *pos, *tmp;

    spin_lock(&ksu_manager_list_write_lock);

    list_for_each_entry_safe (pos, tmp, &ksu_manager_appid_list, list) {
        if (pos->signature_index == signature_index) {
            list_del_rcu(&pos->list);
            kfree_rcu(pos, rcu);
        }
    }

    repair_manager_selection();
    spin_unlock(&ksu_manager_list_write_lock);
}

void ksu_unregister_all_manager(void)
{
    struct ksu_manager_node *pos, *tmp;

    spin_lock(&ksu_manager_list_write_lock);

    list_for_each_entry_safe (pos, tmp, &ksu_manager_appid_list, list) {
        list_del_rcu(&pos->list);
        kfree_rcu(pos, rcu);
    }

    WRITE_ONCE(ksu_last_manager_appid, KSU_INVALID_APPID);
    spin_unlock(&ksu_manager_list_write_lock);
}

bool ksu_has_manager(void)
{
    bool empty;

    rcu_read_lock();
    empty = list_empty(&ksu_manager_appid_list);
    rcu_read_unlock();

    return !empty;
}

int ksu_handle_get_managers_cmd(struct ksu_get_managers_cmd __user *arg, struct ksu_get_managers_cmd *cmd)
{
    struct ksu_manager_node *pos;
    struct ksu_manager_entry *entries;
    u16 max_allowed = cmd->count;
    int count = 0;
    int copy_count;

    entries = kcalloc(max_allowed, sizeof(*entries), GFP_KERNEL);
    if (!entries && max_allowed)
        return -ENOMEM;

    rcu_read_lock();
    list_for_each_entry_rcu (pos, &ksu_manager_appid_list, list) {
        if (count < max_allowed) {
            entries[count].uid = pos->appid;
            entries[count].signature_index = pos->signature_index;
        }

        count++;
    }
    rcu_read_unlock();

    cmd->total_count = count;

    copy_count = min_t(int, count, max_allowed);
    cmd->count = copy_count;

    if (copy_count && copy_to_user((char __user *)arg + sizeof(*cmd), entries, copy_count * sizeof(*entries))) {
        kfree(entries);
        return -EFAULT;
    }

    kfree(entries);
    return 0;
}

int ksu_get_manager_signature_index_by_appid(u32 appid)
{
    struct ksu_manager_node *pos;
    int signature_index = -ENODATA;

    rcu_read_lock();
    list_for_each_entry_rcu (pos, &ksu_manager_appid_list, list) {
        if (pos->appid == appid) {
            signature_index = pos->signature_index;
            break;
        }
    }
    rcu_read_unlock();
    return signature_index;
}
