// SPDX-License-Identifier: GPL-2.0-only
/*
 * Adapted from FinaSU v1.6.4; also wrap this native tree's SUSFS proc mount renderers.
 * https://github.com/LyraVoid/FinaSU/blob/ff0e34f1d9d5694ab7b4f1e318a77c781d65cb41/kernel/feature/mount_view_filter.c
 */

#include "finasu_mount_view_filter.h"

#include <linux/build_bug.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/seq_file.h>
#include <linux/string.h>

/* Consume the native private layout rather than inventing or changing a vendor-visible struct. */
#include "../../../fs/mount.h"
#include "feature/kernel_umount.h"
#include "hook/patch_memory.h"
#include "infra/symbol_resolver.h"
#include "manager/manager_identity.h"
#include "policy/allowlist.h"
#include "policy/feature.h"

typedef int (*ksu_mvf_open_fn)(struct inode *, struct file *);
typedef int (*ksu_mvf_show_fn)(struct seq_file *, struct vfsmount *);

static_assert(__same_type(((const struct file_operations *)0)->open, (ksu_mvf_open_fn)NULL));
static_assert(__same_type(((struct proc_mounts *)0)->show, (ksu_mvf_show_fn)NULL));

enum ksu_mvf_format {
    KSU_MVF_MOUNTS,
    KSU_MVF_MOUNTINFO,
    KSU_MVF_MOUNTSTATS,
};

struct ksu_mvf_hook {
    const char *ops_name;
    const char *show_names[2];
    const struct file_operations *ops;
    const ksu_mvf_open_fn *open_slot;
    ksu_mvf_open_fn original_open;
    ksu_mvf_show_fn original_show[2];
    bool patched;
};

static struct ksu_mvf_hook ksu_mvf_hooks[] = {
    {
        .ops_name = "proc_mounts_operations",
        .show_names = { "show_vfsmnt", "susfs_show_vfsmnt" },
    },
    {
        .ops_name = "proc_mountinfo_operations",
        .show_names = { "show_mountinfo", "susfs_show_mountinfo" },
    },
    {
        .ops_name = "proc_mountstats_operations",
        .show_names = { "show_vfsstat", "susfs_show_vfsstat" },
    },
};

static DEFINE_MUTEX(ksu_mvf_mutex);
/* Release/acquire publishes the immutable hook metadata before proc readers can filter. */
static bool ksu_mvf_enabled;
static bool ksu_mvf_initialized;
static bool ksu_mvf_stopping;
static bool ksu_mvf_backend_broken;

static bool ksu_mvf_char_equal(char a, char b)
{
    if (a >= 'A' && a <= 'Z')
        a += 'a' - 'A';
    if (b >= 'A' && b <= 'Z')
        b += 'a' - 'A';
    return a == b;
}

static bool ksu_mvf_has_marker(const char *text, size_t len)
{
    static const char *const markers[] = {
        "/adb/", "/data/adb", "kernelsu", "magisk", "zygisk", "/debug_ramdisk",
    };
    size_t i, j, k, marker_len;

    for (i = 0; i < ARRAY_SIZE(markers); i++) {
        marker_len = strlen(markers[i]);
        if (len < marker_len)
            continue;
        for (j = 0; j + marker_len <= len; j++) {
            for (k = 0; k < marker_len && ksu_mvf_char_equal(text[j + k], markers[i][k]); k++)
                ;
            if (k == marker_len)
                return true;
        }
    }
    return false;
}

static bool ksu_mvf_has_root_marker(struct vfsmount *mnt)
{
    char path[512];
    char *root;

    if (!mnt || !mnt->mnt_root || IS_ROOT(mnt->mnt_root))
        return false;
    root = dentry_path_raw(mnt->mnt_root, path, sizeof(path));
    return !IS_ERR(root) && ksu_mvf_has_marker(root, strlen(root));
}

static const char *ksu_mvf_token(const char *p, const char *end, unsigned int index, size_t *len)
{
    unsigned int field = 0;

    while (p < end) {
        const char *start;

        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n'))
            p++;
        if (p == end)
            break;
        start = p;
        while (p < end && *p != ' ' && *p != '\t' && *p != '\n')
            p++;
        if (field++ == index) {
            *len = p - start;
            return start;
        }
    }
    return NULL;
}

static const char *ksu_mvf_find(const char *text, size_t len, const char *needle)
{
    size_t needle_len = strlen(needle);
    size_t i;

    if (needle_len > len)
        return NULL;
    for (i = 0; i + needle_len <= len; i++) {
        if (!memcmp(text + i, needle, needle_len))
            return text + i;
    }
    return NULL;
}

static const char *ksu_mvf_mountpoint(const char *text, size_t len, enum ksu_mvf_format format, size_t *field_len)
{
    const char *end = text + len;

    switch (format) {
    case KSU_MVF_MOUNTS:
        return ksu_mvf_token(text, end, 1, field_len);
    case KSU_MVF_MOUNTINFO:
        return ksu_mvf_token(text, end, 4, field_len);
    case KSU_MVF_MOUNTSTATS: {
        const char *mounted_on = ksu_mvf_find(text, len, " mounted on ");

        if (mounted_on)
            return ksu_mvf_token(mounted_on + strlen(" mounted on "), end, 0, field_len);
        break;
    }
    }
    return NULL;
}

static int ksu_mvf_octal(char c)
{
    return c >= '0' && c <= '7' ? c - '0' : -1;
}

static bool ksu_mvf_path_equal(const char *field, size_t field_len, const char *path)
{
    size_t i = 0, j = 0;

    while (i < field_len) {
        char c = field[i++];

        if (c == '\\' && i + 2 < field_len) {
            int a = ksu_mvf_octal(field[i]);
            int b = ksu_mvf_octal(field[i + 1]);
            int d = ksu_mvf_octal(field[i + 2]);

            if (a >= 0 && b >= 0 && d >= 0) {
                c = (char)((a << 6) | (b << 3) | d);
                i += 3;
            }
        }
        if (!path[j] || path[j++] != c)
            return false;
    }
    return path[j] == '\0';
}

static bool ksu_mvf_in_umount_list(const char *mountpoint, size_t len)
{
    struct mount_entry *entry;
    bool found = false;

    /* namespace_sem(R) is held here; umount takes mount_list_lock(R) then namespace_sem(W). */
    if (!down_read_trylock(&mount_list_lock))
        return false;
    list_for_each_entry (entry, &mount_list, list) {
        if (entry->umountable && ksu_mvf_path_equal(mountpoint, len, entry->umountable)) {
            found = true;
            break;
        }
    }
    up_read(&mount_list_lock);
    return found;
}

static bool ksu_mvf_record_hidden(struct seq_file *m, size_t start, enum ksu_mvf_format format, struct vfsmount *mnt)
{
    const char *text = m->buf + start;
    const char *mountpoint;
    size_t len = m->count - start;
    size_t mountpoint_len;

    if (ksu_mvf_has_marker(text, len))
        return true;
    mountpoint = ksu_mvf_mountpoint(text, len, format, &mountpoint_len);
    if (mountpoint && ksu_mvf_in_umount_list(mountpoint, mountpoint_len))
        return true;
    return ksu_mvf_has_root_marker(mnt);
}

static bool ksu_mvf_should_filter(void)
{
    uid_t uid = current_uid().val;
    bool isolated = is_isolated_process(uid);

    if (ksu_is_manager_uid(uid))
        return false;
    return (is_appuid(uid) || isolated) && (isolated || ksu_uid_should_umount(uid));
}

static int ksu_mvf_show(struct seq_file *m, struct vfsmount *mnt, enum ksu_mvf_format format, unsigned int family)
{
    size_t start = m->count;
    int ret = ksu_mvf_hooks[format].original_show[family](m, mnt);

    /* Existing proc fds must respect disable and must not hide records from a root/manager reader. */
    if (ret || seq_has_overflowed(m) || !smp_load_acquire(&ksu_mvf_enabled) || !ksu_mvf_should_filter())
        return ret;
    if (m->count > start && ksu_mvf_record_hidden(m, start, format, mnt))
        m->count = start;
    return 0;
}

static int ksu_mvf_show_mounts(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_mvf_show(m, mnt, KSU_MVF_MOUNTS, 0);
}

static int ksu_mvf_show_mountinfo(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_mvf_show(m, mnt, KSU_MVF_MOUNTINFO, 0);
}

static int ksu_mvf_show_mountstats(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_mvf_show(m, mnt, KSU_MVF_MOUNTSTATS, 0);
}

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static int ksu_mvf_show_susfs_mounts(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_mvf_show(m, mnt, KSU_MVF_MOUNTS, 1);
}

static int ksu_mvf_show_susfs_mountinfo(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_mvf_show(m, mnt, KSU_MVF_MOUNTINFO, 1);
}

static int ksu_mvf_show_susfs_mountstats(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_mvf_show(m, mnt, KSU_MVF_MOUNTSTATS, 1);
}
#endif

static const ksu_mvf_show_fn ksu_mvf_show_wrappers[][2] = {
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    { ksu_mvf_show_mounts, ksu_mvf_show_susfs_mounts },
    { ksu_mvf_show_mountinfo, ksu_mvf_show_susfs_mountinfo },
    { ksu_mvf_show_mountstats, ksu_mvf_show_susfs_mountstats },
#else
    { ksu_mvf_show_mounts, NULL },
    { ksu_mvf_show_mountinfo, NULL },
    { ksu_mvf_show_mountstats, NULL },
#endif
};

static int ksu_mvf_open(struct inode *inode, struct file *file, unsigned int index)
{
    struct ksu_mvf_hook *hook = &ksu_mvf_hooks[index];
    struct proc_mounts *mounts;
    struct seq_file *m;
    ksu_mvf_show_fn show;
    unsigned int family;
    int ret = hook->original_open(inode, file);

    if (ret || !smp_load_acquire(&ksu_mvf_enabled) || !ksu_mvf_should_filter())
        return ret;
    if (!file->private_data)
        goto broken;
    m = file->private_data;
    mounts = m->private;
    if (!mounts)
        goto broken;
    show = READ_ONCE(mounts->show);
    for (family = 0; family < ARRAY_SIZE(hook->original_show); family++) {
        if (hook->original_show[family] && show == hook->original_show[family]) {
            WRITE_ONCE(mounts->show, ksu_mvf_show_wrappers[index][family]);
            return 0;
        }
    }
broken:
    mutex_lock(&ksu_mvf_mutex);
    WRITE_ONCE(ksu_mvf_backend_broken, true);
    smp_store_release(&ksu_mvf_enabled, false);
    mutex_unlock(&ksu_mvf_mutex);
    pr_err_once("finasu_mount_view_filter: unsupported proc renderer/layout\n");
    return 0;
}

static int ksu_mvf_open_mounts(struct inode *inode, struct file *file)
{
    return ksu_mvf_open(inode, file, KSU_MVF_MOUNTS);
}

static int ksu_mvf_open_mountinfo(struct inode *inode, struct file *file)
{
    return ksu_mvf_open(inode, file, KSU_MVF_MOUNTINFO);
}

static int ksu_mvf_open_mountstats(struct inode *inode, struct file *file)
{
    return ksu_mvf_open(inode, file, KSU_MVF_MOUNTSTATS);
}

static const ksu_mvf_open_fn ksu_mvf_open_wrappers[] = {
    ksu_mvf_open_mounts,
    ksu_mvf_open_mountinfo,
    ksu_mvf_open_mountstats,
};

static int ksu_mvf_patch_open(struct ksu_mvf_hook *hook, ksu_mvf_open_fn replacement)
{
    int ret;

    /* The native fixmap patcher writes one page; never let a function pointer straddle its boundary. */
    if (!IS_ALIGNED((unsigned long)hook->open_slot, sizeof(replacement)) ||
        offset_in_page(hook->open_slot) + sizeof(replacement) > PAGE_SIZE)
        return -EINVAL;
    ret = ksu_patch_text((void *)hook->open_slot, &replacement, sizeof(replacement), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (!ret && READ_ONCE(*hook->open_slot) != replacement)
        ret = -EIO;
    return ret;
}

static bool ksu_mvf_hooks_owned(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ksu_mvf_hooks); i++) {
        if (!ksu_mvf_hooks[i].patched || READ_ONCE(*ksu_mvf_hooks[i].open_slot) != ksu_mvf_open_wrappers[i])
            return false;
    }
    return true;
}

static int ksu_mvf_restore_hooks(void)
{
    int error = 0;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ksu_mvf_hooks); i++) {
        struct ksu_mvf_hook *hook = &ksu_mvf_hooks[i];
        int ret;

        if (!hook->patched)
            continue;
        if (READ_ONCE(*hook->open_slot) != ksu_mvf_open_wrappers[i]) {
            hook->patched = false;
            WRITE_ONCE(ksu_mvf_backend_broken, true);
            error = error ?: -EBUSY;
            continue;
        }
        ret = ksu_mvf_patch_open(hook, hook->original_open);
        if (READ_ONCE(*hook->open_slot) == hook->original_open)
            hook->patched = false;
        if (ret)
            error = error ?: ret;
    }
    return error;
}

static int ksu_mvf_install_hooks(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ksu_mvf_hooks); i++) {
        struct ksu_mvf_hook *hook = &ksu_mvf_hooks[i];
        ksu_mvf_open_fn expected = hook->patched ? ksu_mvf_open_wrappers[i] : hook->original_open;
        int ret;

        if (READ_ONCE(*hook->open_slot) != expected) {
            WRITE_ONCE(ksu_mvf_backend_broken, true);
            return -EBUSY;
        }
        if (hook->patched)
            continue;
        ret = ksu_mvf_patch_open(hook, ksu_mvf_open_wrappers[i]);
        if (READ_ONCE(*hook->open_slot) == ksu_mvf_open_wrappers[i])
            hook->patched = true;
        if (ret)
            return ret;
    }
    return 0;
}

static int ksu_mvf_resolve_symbols(void)
{
    static const char *const names[] = {
        "proc_mounts_operations",
        "proc_mountinfo_operations",
        "proc_mountstats_operations",
    };
    unsigned long addrs[ARRAY_SIZE(names)] = { 0 };
    unsigned int i, family;
    int ret = ksu_lookup_kernel_symbols(names, addrs, ARRAY_SIZE(names));

    if (ret != (int)ARRAY_SIZE(names))
        return ret < 0 ? ret : -ENODEV;
    for (i = 0; i < ARRAY_SIZE(ksu_mvf_hooks); i++) {
        struct ksu_mvf_hook *hook = &ksu_mvf_hooks[i];

        if (!addrs[i])
            return -ENODEV;
        hook->ops = (const struct file_operations *)addrs[i];
        hook->open_slot = &hook->ops->open;
        hook->original_open = READ_ONCE(*hook->open_slot);
        if (!hook->original_open)
            return -ENODEV;
        for (family = 0; family < ARRAY_SIZE(hook->original_show); family++) {
#ifndef CONFIG_KSU_SUSFS_SUS_MOUNT
            if (family)
                break;
#endif
            /* Both the resolved functions and our wrappers have the exact native CFI prototypes. */
            hook->original_show[family] =
                (ksu_mvf_show_fn)ksu_resolve_symbol_for_functable_hook(hook->show_names[family]);
            if (!hook->original_show[family]) {
                pr_err("finasu_mount_view_filter: missing renderer %s\n", hook->show_names[family]);
                return -ENODEV;
            }
        }
    }
    return 0;
}

int ksu_finasu_mount_view_filter_feature_get(u64 *value)
{
    int ret = 0;

    if (!value)
        return -EINVAL;
    mutex_lock(&ksu_mvf_mutex);
    if (!ksu_mvf_initialized || ksu_mvf_stopping || READ_ONCE(ksu_mvf_backend_broken)) {
        ret = -ENODEV;
    } else if (smp_load_acquire(&ksu_mvf_enabled) && !ksu_mvf_hooks_owned()) {
        WRITE_ONCE(ksu_mvf_backend_broken, true);
        smp_store_release(&ksu_mvf_enabled, false);
        ret = -ENODEV;
    } else {
        *value = smp_load_acquire(&ksu_mvf_enabled) ? 1 : 0;
    }
    mutex_unlock(&ksu_mvf_mutex);
    return ret;
}

int ksu_finasu_mount_view_filter_feature_set(u64 value)
{
    bool enable = value != 0;
    int ret = 0;

    mutex_lock(&ksu_mvf_mutex);
    if (!ksu_mvf_initialized || ksu_mvf_stopping) {
        ret = -ENODEV;
        goto out;
    }
    if (!enable) {
        smp_store_release(&ksu_mvf_enabled, false);
        ret = ksu_mvf_restore_hooks();
        if (!ret && READ_ONCE(ksu_mvf_backend_broken))
            ret = -ENODEV;
    } else if (READ_ONCE(ksu_mvf_backend_broken)) {
        ret = -ENODEV;
    } else {
        ret = ksu_mvf_install_hooks();
        if (!ret && !READ_ONCE(ksu_mvf_backend_broken) && ksu_mvf_hooks_owned()) {
            smp_store_release(&ksu_mvf_enabled, true);
        } else {
            int restore_ret;

            ret = ret ?: -ENODEV;
            smp_store_release(&ksu_mvf_enabled, false);
            restore_ret = ksu_mvf_restore_hooks();
            if (restore_ret)
                WRITE_ONCE(ksu_mvf_backend_broken, true);
        }
    }
out:
    mutex_unlock(&ksu_mvf_mutex);
    return ret;
}

static struct ksu_feature_handler ksu_mvf_handler = {
    .name = "mount_view_filter",
    .get_handler = ksu_finasu_mount_view_filter_feature_get,
    .set_handler = ksu_finasu_mount_view_filter_feature_set,
};

int __init ksu_finasu_mount_view_filter_init(u32 feature_id)
{
    /* Old proc fds retain show wrappers after disable; their addresses must have builtin lifetime. */
#if defined(MODULE) || !defined(CONFIG_PROC_FS)
    return -EOPNOTSUPP;
#else
    int ret;

    mutex_lock(&ksu_mvf_mutex);
    if (ksu_mvf_initialized || ksu_mvf_stopping) {
        mutex_unlock(&ksu_mvf_mutex);
        return -EBUSY;
    }
    ret = ksu_mvf_resolve_symbols();
    if (ret) {
        mutex_unlock(&ksu_mvf_mutex);
        return ret;
    }
    ksu_mvf_initialized = true;
    ksu_mvf_handler.feature_id = feature_id;
    mutex_unlock(&ksu_mvf_mutex);
    ret = ksu_register_feature_handler(&ksu_mvf_handler);
    if (ret) {
        mutex_lock(&ksu_mvf_mutex);
        ksu_mvf_initialized = false;
        mutex_unlock(&ksu_mvf_mutex);
    }
    return ret;
#endif
}

void ksu_finasu_mount_view_filter_exit(void)
{
    bool registered;
    int ret;

    mutex_lock(&ksu_mvf_mutex);
    registered = ksu_mvf_initialized;
    ksu_mvf_stopping = true;
    smp_store_release(&ksu_mvf_enabled, false);
    ret = ksu_mvf_restore_hooks();
    ksu_mvf_initialized = false;
    mutex_unlock(&ksu_mvf_mutex);
    if (ret)
        pr_err("finasu_mount_view_filter: restoring proc hooks failed: %d\n", ret);
    if (registered)
        ksu_unregister_feature_handler(ksu_mvf_handler.feature_id);
}
