// SPDX-License-Identifier: GPL-2.0-only
/*
 * Isolated FinaSU dynamic-manager backend, adapted 2026-11-18 from
 * LyraVoid/FinaSU ff0e34f1d9d5694ab7b4f1e318a77c781d65cb41:
 * kernel/manager/dynamic_manager.c, manager/apk_sign.c and supercall/dispatch.c.
 * Native Baka's single-certificate configuration and fixed managers are not
 * modified. Immutable RCU snapshots replace upstream's in-place UID array.
 */
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "compat/kernel_compat.h"
#include "finasu_dynamic_manager.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "manager/manager_identity.h"
#include "manager/manager_sign.h"
#include "manager/throne_tracker.h"
#include "policy/feature.h"

#define FINASU_MANAGER_DIR "/data/adb/ksu"
#define FINASU_MANAGER_NAME "dynamic_manager"
#define FINASU_MANAGER_TEMP_NAME FINASU_MANAGER_NAME ".tmp"
#define FINASU_MANAGER_FILE FINASU_MANAGER_DIR "/" FINASU_MANAGER_NAME
#define FINASU_MANAGER_FILE_MAGIC 0x4d554b53U
#define FINASU_MANAGER_FILE_VERSION 2U
#define FINASU_MANAGER_FILE_STRICT (1U << 0)
#define FINASU_PER_USER_RANGE 100000U

struct finasu_disk_header {
	u32 magic;
	u32 version;
	u32 flags;
	u32 grant_count;
};

#define FINASU_MANAGER_FILE_MAX \
	(sizeof(struct finasu_disk_header) + \
	 KSU_FINASU_DYNAMIC_MANAGER_MAX_APPS * sizeof(u32) + \
	 KSU_FINASU_DYNAMIC_MANAGER_MAX_SIGNS * sizeof(struct ksu_finasu_dynamic_manager_sign))

struct finasu_scanned_app {
	struct hlist_node node;
	struct rcu_head rcu;
	u32 appid;
	u32 size;
	char hash[65];
	bool preset;
};

struct finasu_manager_snapshot {
	struct rcu_head rcu;
	bool ready;
	bool grants_strict;
	u32 sign_count;
	u32 grant_count;
	struct ksu_finasu_dynamic_manager_sign signs[KSU_FINASU_DYNAMIC_MANAGER_MAX_SIGNS];
	u32 grants[KSU_FINASU_DYNAMIC_MANAGER_MAX_APPS];
};

static DEFINE_MUTEX(finasu_manager_lock);
static struct finasu_manager_snapshot __rcu *finasu_managers;
/* The upstream 64-app limit is a query/grant capacity, not a census limit. */
static DEFINE_HASHTABLE(finasu_scanned_apps, 6);
static bool signs_pending;
static bool grants_pending;

/* Active public certificates only; retired forks are not offered as presets. */
#ifndef KSU_PRESET_MANAGER_MASK
#define KSU_PRESET_MANAGER_MASK 0xff
#endif
static const struct {
	u32 size;
	const char *hash;
} finasu_preset_signs[] = {
#if (KSU_PRESET_MANAGER_MASK & 0x01)
	{ 0x033b, "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6" },
#endif
#if (KSU_PRESET_MANAGER_MASK & 0x02)
	{ EXPECTED_SIZE_MILKSU, EXPECTED_HASH_MILKSU },
#endif
#if (KSU_PRESET_MANAGER_MASK & 0x04)
	{ 0x3e6, "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7" },
#endif
#if (KSU_PRESET_MANAGER_MASK & 0x08)
	{ 0x377, "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64" },
#endif
#if (KSU_PRESET_MANAGER_MASK & 0x10)
	{ 0x35c, "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef" },
#endif
#if (KSU_PRESET_MANAGER_MASK & 0x20)
	{ EXPECTED_SIZE_WILDKSU, EXPECTED_HASH_WILDKSU },
#endif
#if (KSU_PRESET_MANAGER_MASK & 0x40)
	{ EXPECTED_SIZE_KSUNEXT_ALT, EXPECTED_HASH_KSUNEXT_ALT },
#endif
};

_Static_assert(sizeof(struct ksu_finasu_dynamic_manager_sign) == 76, "Fina sign ABI");
_Static_assert(sizeof(struct ksu_finasu_dynamic_manager_cmd) == 16, "Fina SET ABI");
_Static_assert(offsetof(struct ksu_finasu_dynamic_manager_cmd, signs) == 8, "Fina signs offset");
_Static_assert(sizeof(struct ksu_finasu_dynamic_manager_app) == 8, "Fina app ABI");
_Static_assert(sizeof(struct ksu_finasu_get_dynamic_managers_cmd) == 16, "Fina GET ABI");
_Static_assert(sizeof(struct ksu_finasu_dynamic_manager_grants_cmd) == 16, "Fina grants ABI");
_Static_assert(KSU_FINASU_IOCTL_SET_DYNAMIC_MANAGERS == 0x40004b16U, "Fina SET ioctl");
_Static_assert(KSU_FINASU_IOCTL_GET_DYNAMIC_MANAGERS == 0xc0104b17U, "Fina GET ioctl");
_Static_assert(KSU_FINASU_IOCTL_SET_DYNAMIC_MANAGER_GRANTS == 0x40004b18U, "Fina grants ioctl");

static bool normalize_hash(char dst[65], const char *src)
{
	static const char hex[] = "0123456789abcdef";
	unsigned int i;

	if (!src || strnlen(src, 65) != 64)
		return false;
	for (i = 0; i < 64; i++) {
		int value = hex_to_bin(src[i]);

		if (value < 0)
			return false;
		dst[i] = hex[value];
	}
	dst[64] = '\0';
	return true;
}

static const struct ksu_finasu_dynamic_manager_sign *
find_sign(const struct finasu_manager_snapshot *state, u32 size, const char *hash)
{
	u32 i = state->sign_count;

	/* Upstream's last inserted duplicate takes precedence, including versionCode. */
	while (i--) {
		if (state->signs[i].size == size && !strcmp(state->signs[i].hash, hash))
			return &state->signs[i];
	}
	return NULL;
}

static bool has_grant(const struct finasu_manager_snapshot *state, u32 appid)
{
	u32 i;

	for (i = 0; i < state->grant_count; i++) {
		if (state->grants[i] == appid)
			return true;
	}
	return false;
}

/* Callers hold either RCU or the writer mutex; observed nodes are immutable. */
static struct finasu_scanned_app *find_scanned_app(u32 appid)
{
	struct finasu_scanned_app *app;

	hash_for_each_possible_rcu(finasu_scanned_apps, app, node, appid,
				   lockdep_is_held(&finasu_manager_lock)) {
		if (app->appid == appid)
			return app;
	}
	return NULL;
}

static void clear_scanned_apps(void)
{
	struct finasu_scanned_app *app;
	struct hlist_node *tmp;
	int bucket;

	lockdep_assert_held(&finasu_manager_lock);
	hash_for_each_safe(finasu_scanned_apps, bucket, tmp, app, node) {
		hash_del_rcu(&app->node);
		kfree_rcu(app, rcu);
	}
}

static u32 app_flags(const struct finasu_manager_snapshot *state,
		     const struct finasu_scanned_app *app)
{
	u32 flags = app->preset ? KSU_FINASU_DYNAMIC_MANAGER_FLAG_PRESET : 0;

	if (find_sign(state, app->size, app->hash)) {
		flags |= KSU_FINASU_DYNAMIC_MANAGER_FLAG_TRUSTED;
		/* Unknown/untrusted granted appids must never claim an active identity. */
		if (has_grant(state, app->appid))
			flags |= KSU_FINASU_DYNAMIC_MANAGER_FLAG_GRANTED;
	}
	return flags;
}

static struct finasu_manager_snapshot *clone_snapshot(struct finasu_manager_snapshot *old)
{
	struct finasu_manager_snapshot *next = kmemdup(old, sizeof(*old), GFP_KERNEL);

	if (next)
		memset(&next->rcu, 0, sizeof(next->rcu));
	return next;
}

static void publish_snapshot(struct finasu_manager_snapshot *next)
{
	struct finasu_manager_snapshot *old;

	lockdep_assert_held(&finasu_manager_lock);
	old = rcu_dereference_protected(finasu_managers, lockdep_is_held(&finasu_manager_lock));
	rcu_assign_pointer(finasu_managers, next);
	if (old)
		kfree_rcu(old, rcu);
}

static int validate_signs(struct ksu_finasu_dynamic_manager_sign *signs, u32 count)
{
	u32 i;

	for (i = 0; i < count; i++) {
		if (!signs[i].size || signs[i].size > KSU_FINASU_DYNAMIC_MANAGER_CERT_MAX ||
		    !normalize_hash(signs[i].hash, signs[i].hash))
			return -EINVAL;
	}
	return 0;
}

/* Only reclaim our reserved private temp name, never a substituted inode. */
static int cleanup_snapshot_temp(const struct path *parent, const struct inode *expected)
{
	struct user_namespace *userns = mnt_user_ns(parent->mnt);
	struct inode *dir = d_inode(parent->dentry), *inode, *held = NULL;
	struct dentry *temp;
	int ret;

	ret = mnt_want_write(parent->mnt);
	if (ret)
		return ret;
	inode_lock_nested(dir, I_MUTEX_PARENT);
	temp = lookup_one(userns, FINASU_MANAGER_TEMP_NAME, parent->dentry,
			  sizeof(FINASU_MANAGER_TEMP_NAME) - 1);
	if (IS_ERR(temp)) {
		ret = PTR_ERR(temp);
		goto unlock;
	}
	ret = 0;
	if (d_is_negative(temp))
		goto put;
	inode = d_inode(temp);
	if (expected && inode != expected) {
		ret = -ESTALE;
		goto put;
	}
	ret = -EPERM;
	if (!S_ISREG(inode->i_mode) ||
	    !uid_eq(i_uid_into_mnt(userns, inode), current_fsuid()))
		goto put;
	/* A crash before chmod can leave permissions reduced by the caller's umask. */
	if (!expected && (inode->i_nlink != 1 || ((inode->i_mode & 07777) & ~0600)))
		goto put;
	/* Keep final inode truncation outside the parent lock, as do_unlinkat does. */
	ihold(inode);
	held = inode;
	ret = security_path_unlink(parent, temp);
	if (!ret)
		ret = vfs_unlink(userns, dir, temp, NULL);
put:
	dput(temp);
unlock:
	inode_unlock(dir);
	if (held)
		iput(held);
	mnt_drop_write(parent->mnt);
	return ret;
}

/* Do not alter current->fs or rely on its umask to preserve exactly 0600. */
static int set_snapshot_temp_mode(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct iattr attr = { .ia_valid = ATTR_MODE | ATTR_CTIME };
	int ret;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;
	inode_lock(inode);
	attr.ia_mode = (inode->i_mode & S_IFMT) | 0600;
	ret = security_path_chmod(&file->f_path, 0600);
	if (!ret)
		ret = notify_change(file_mnt_user_ns(file), file->f_path.dentry, &attr, NULL);
	inode_unlock(inode);
	mnt_drop_write_file(file);
	return ret;
}

static int replace_snapshot_file(const struct path *parent, const struct path *staged)
{
	struct user_namespace *userns = mnt_user_ns(parent->mnt);
	struct renamedata rd = {
		.old_mnt_userns = userns,
		.old_dir = d_inode(parent->dentry),
		.new_mnt_userns = userns,
		.new_dir = d_inode(parent->dentry),
		/* Local /data; delegation errors fail before committing, without a ref. */
		.delegated_inode = NULL,
		.flags = 0,
	};
	struct dentry *old, *new;
	struct inode *inode;
	int ret;

	if (staged->mnt != parent->mnt)
		return -EXDEV;
	ret = mnt_want_write(parent->mnt);
	if (ret)
		return ret;
	lock_rename(parent->dentry, parent->dentry);
	old = lookup_one(userns, FINASU_MANAGER_TEMP_NAME, parent->dentry,
			 sizeof(FINASU_MANAGER_TEMP_NAME) - 1);
	if (IS_ERR(old)) {
		ret = PTR_ERR(old);
		goto unlock;
	}
	ret = -ESTALE;
	if (d_is_negative(old) || old != staged->dentry)
		goto put_old;
	inode = d_inode(old);
	ret = -EPERM;
	if (!S_ISREG(inode->i_mode) || inode->i_nlink != 1 ||
	    (inode->i_mode & 07777) != 0600 ||
	    !uid_eq(i_uid_into_mnt(userns, inode), current_fsuid()))
		goto put_old;
	new = lookup_one(userns, FINASU_MANAGER_NAME, parent->dentry,
			 sizeof(FINASU_MANAGER_NAME) - 1);
	if (IS_ERR(new)) {
		ret = PTR_ERR(new);
		goto put_old;
	}
	ret = -EINVAL;
	if (d_is_positive(new) && (!S_ISREG(d_inode(new)->i_mode) || d_inode(new) == inode))
		goto put_new;
	ret = security_path_rename(parent, old, parent, new, 0);
	if (!ret) {
		rd.old_dentry = old;
		rd.new_dentry = new;
		ret = vfs_rename(&rd);
	}
put_new:
	dput(new);
put_old:
	dput(old);
unlock:
	unlock_rename(parent->dentry, parent->dentry);
	mnt_drop_write(parent->mnt);
	return ret;
}

/* Negative means no final-file replacement; zero means the rename committed. */
static int persist_snapshot(const struct finasu_manager_snapshot *state)
{
	struct finasu_disk_header header = {
		.magic = FINASU_MANAGER_FILE_MAGIC,
		.version = FINASU_MANAGER_FILE_VERSION,
		.flags = state->grants_strict ? FINASU_MANAGER_FILE_STRICT : 0,
		.grant_count = state->grant_count,
	};
	const struct cred *saved;
	struct file *dir, *file;
	struct path staged;
	size_t size;
	u8 *buffer;
	loff_t offset = 0;
	ssize_t written;
	bool committed = false;
	int ret, close_ret, sync_ret, cleanup_ret;

	lockdep_assert_held(&finasu_manager_lock);
	if (!ksu_cred)
		return -EAGAIN;
	if (state->grant_count > KSU_FINASU_DYNAMIC_MANAGER_MAX_APPS ||
	    state->sign_count > KSU_FINASU_DYNAMIC_MANAGER_MAX_SIGNS)
		return -EINVAL;
	size = sizeof(header) + state->grant_count * sizeof(u32) +
		state->sign_count * sizeof(struct ksu_finasu_dynamic_manager_sign);
	buffer = kzalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	memcpy(buffer, &header, sizeof(header));
	memcpy(buffer + sizeof(header), state->grants, state->grant_count * sizeof(u32));
	memcpy(buffer + sizeof(header) + state->grant_count * sizeof(u32), state->signs,
	       state->sign_count * sizeof(struct ksu_finasu_dynamic_manager_sign));

	saved = override_creds(ksu_cred);
	dir = filp_open(FINASU_MANAGER_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
	if (IS_ERR(dir)) {
		ret = PTR_ERR(dir);
		goto revert;
	}
	ret = cleanup_snapshot_temp(&dir->f_path, NULL);
	if (ret)
		goto close_dir;
	/* Exclusive creation cannot truncate a stale temp hard-linked to the final file. */
	file = file_open_root(&dir->f_path, FINASU_MANAGER_TEMP_NAME,
			      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK, 0600);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto close_dir;
	}
	staged = file->f_path;
	path_get(&staged);
	if (staged.mnt != dir->f_path.mnt) {
		ret = -EXDEV;
		goto close_temp;
	}
	if (!S_ISREG(file_inode(file)->i_mode) || file_inode(file)->i_nlink != 1 ||
	    !uid_eq(i_uid_into_mnt(file_mnt_user_ns(file), file_inode(file)), current_fsuid())) {
		ret = -EINVAL;
		goto close_temp;
	}
	ret = set_snapshot_temp_mode(file);
	if (ret)
		goto close_temp;
	written = kernel_write(file, buffer, size, &offset);
	ret = written < 0 ? written : (written == (ssize_t)size ? 0 : -EIO);
	if (!ret)
		ret = vfs_fsync(file, 0);
close_temp:
	close_ret = filp_close(file, NULL);
	if (!ret)
		ret = close_ret;
	if (ret)
		goto cleanup;
	/* Reject unsupported/failed directory sync before changing the final name. */
	ret = vfs_fsync(dir, 0);
	if (ret)
		goto cleanup;
	ret = replace_snapshot_file(&dir->f_path, &staged);
	if (ret)
		goto cleanup;
	committed = true;
	sync_ret = vfs_fsync(dir, 0);
	if (sync_ret)
		pr_warn("finasu_dynamic_manager: committed, directory fsync failed (%d); "
			"crash durability uncertain\n", sync_ret);
	/* Do not return a post-rename error: callers must publish the committed RAM. */
	goto put_staged;
cleanup:
	cleanup_ret = cleanup_snapshot_temp(&dir->f_path, d_inode(staged.dentry));
	if (cleanup_ret)
		pr_warn("finasu_dynamic_manager: temp cleanup failed (%d), original error %d\n",
			cleanup_ret, ret);
put_staged:
	path_put(&staged);
close_dir:
	close_ret = filp_close(dir, NULL);
	if (close_ret) {
		pr_warn("finasu_dynamic_manager: %s directory close failed (%d)\n",
			committed ? "committed" : "aborted", close_ret);
		if (!committed && !ret)
			ret = close_ret;
	}
revert:
	revert_creds(saved);
	kfree(buffer);
	return ret;
}

static int commit_snapshot(struct finasu_manager_snapshot *next, bool signs, bool grants)
{
	int ret;

	lockdep_assert_held(&finasu_manager_lock);
	/* Only a pre-rename error aborts RAM; a committed rename always publishes. */
	if (next->ready) {
		ret = persist_snapshot(next);
		if (ret)
			return ret;
	} else {
		signs_pending |= signs;
		grants_pending |= grants;
	}
	publish_snapshot(next);
	return 0;
}

/* No count on disk: after grants, complete 76-byte sign records run to EOF. */
static int read_snapshot(struct finasu_manager_snapshot *state)
{
	struct finasu_disk_header header = { 0 };
	const struct cred *saved;
	struct file *file;
	struct path parent;
	u8 *buffer = NULL;
	u8 extra;
	loff_t offset = 0, file_size;
	size_t start, remaining;
	ssize_t count;
	u32 i;
	int ret;

	lockdep_assert_held(&finasu_manager_lock);
	if (!ksu_cred)
		return -EAGAIN;
	saved = override_creds(ksu_cred);
	file = filp_open(FINASU_MANAGER_FILE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		if (ret == -ENOENT) {
			/* /data exists before it is mounted; only an accessible parent is ready. */
			ret = kern_path(FINASU_MANAGER_DIR, LOOKUP_DIRECTORY, &parent);
			if (!ret)
				path_put(&parent);
		}
		goto revert;
	}
	file_size = i_size_read(file_inode(file));
	ret = -EINVAL;
	if (!S_ISREG(file_inode(file)->i_mode) || file_size < 8 ||
	    file_size > FINASU_MANAGER_FILE_MAX)
		goto close;
	buffer = kmalloc(file_size, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto close;
	}
	count = kernel_read(file, buffer, file_size, &offset);
	if (count != file_size) {
		ret = count < 0 ? count : -EIO;
		goto close;
	}
	count = kernel_read(file, &extra, sizeof(extra), &offset);
	if (count) {
		ret = count < 0 ? count : -EINVAL;
		goto close;
	}
	memcpy(&header, buffer, 8);
	if (header.magic != FINASU_MANAGER_FILE_MAGIC ||
	    (header.version != 1 && header.version != FINASU_MANAGER_FILE_VERSION))
		goto close;
	start = 8;
	if (header.version == FINASU_MANAGER_FILE_VERSION) {
		if (file_size < sizeof(header))
			goto close;
		memcpy(&header, buffer, sizeof(header));
		if ((header.flags & ~FINASU_MANAGER_FILE_STRICT) ||
		    header.grant_count > KSU_FINASU_DYNAMIC_MANAGER_MAX_APPS)
			goto close;
		start = sizeof(header) + header.grant_count * sizeof(u32);
		if (start > file_size)
			goto close;
		state->grants_strict = !!(header.flags & FINASU_MANAGER_FILE_STRICT);
		for (i = 0; i < header.grant_count; i++) {
			u32 appid;

			memcpy(&appid, buffer + sizeof(header) + i * sizeof(appid), sizeof(appid));
			if (appid >= FINASU_PER_USER_RANGE)
				goto close;
			if (!has_grant(state, appid))
				state->grants[state->grant_count++] = appid;
		}
	}
	remaining = file_size - start;
	if (remaining % sizeof(struct ksu_finasu_dynamic_manager_sign))
		goto close;
	state->sign_count = remaining / sizeof(struct ksu_finasu_dynamic_manager_sign);
	if (state->sign_count > KSU_FINASU_DYNAMIC_MANAGER_MAX_SIGNS)
		goto close;
	memcpy(state->signs, buffer + start, remaining);
	ret = validate_signs(state->signs, state->sign_count);
close:
	filp_close(file, NULL);
revert:
	revert_creds(saved);
	kfree(buffer);
	return ret;
}

int ksu_finasu_dynamic_manager_load(void)
{
	struct finasu_manager_snapshot *old, *next = NULL;
	int ret = 0;

	mutex_lock(&finasu_manager_lock);
	old = rcu_dereference_protected(finasu_managers, lockdep_is_held(&finasu_manager_lock));
	if (!old) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (old->ready)
		goto out;
	next = kzalloc(sizeof(*next), GFP_KERNEL);
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	ret = read_snapshot(next);
	if (ret)
		goto out;
	if (signs_pending) {
		next->sign_count = old->sign_count;
		memcpy(next->signs, old->signs, sizeof(next->signs));
	}
	if (grants_pending) {
		next->grants_strict = old->grants_strict;
		next->grant_count = old->grant_count;
		memcpy(next->grants, old->grants, sizeof(next->grants));
	}
	next->ready = true;
	if (signs_pending || grants_pending) {
		ret = persist_snapshot(next);
		if (ret)
			goto out;
	}
	signs_pending = false;
	grants_pending = false;
	publish_snapshot(next);
	next = NULL;
out:
	mutex_unlock(&finasu_manager_lock);
	kfree(next);
	return ret;
}

bool ksu_finasu_dynamic_manager_signature_matches(unsigned int size, const char *hash)
{
	struct finasu_manager_snapshot *state;
	char normalized[65];
	bool matched = false;

	if (!size || size > KSU_FINASU_DYNAMIC_MANAGER_CERT_MAX || !normalize_hash(normalized, hash))
		return false;
	rcu_read_lock();
	state = rcu_dereference(finasu_managers);
	if (state)
		matched = find_sign(state, size, normalized) != NULL;
	rcu_read_unlock();
	return matched;
}

bool ksu_finasu_dynamic_manager_signature_is_preset(unsigned int size, const char *hash)
{
	char normalized[65];
	u32 i;

	if (!size || !normalize_hash(normalized, hash))
		return false;
	for (i = 0; i < ARRAY_SIZE(finasu_preset_signs); i++) {
		if (finasu_preset_signs[i].size == size && !strcmp(finasu_preset_signs[i].hash, normalized))
			return true;
	}
	return false;
}

bool ksu_finasu_dynamic_manager_uid_allowed(u32 uid, u8 signature_index)
{
	struct finasu_manager_snapshot *state;
	struct finasu_scanned_app *app;
	u32 appid = uid % FINASU_PER_USER_RANGE;
	bool allowed = false;

	/* Fina release3 is fixed/trusted upstream; no native static/Baka revocation. */
	if (signature_index != KSU_SIGNATURE_INDEX_FINASU_DYNAMIC_MANAGER)
		return true;
	rcu_read_lock();
	state = rcu_dereference(finasu_managers);
	if (!state || !state->ready || (state->grants_strict && !has_grant(state, appid)))
		goto out;
	app = find_scanned_app(appid);
	allowed = app && find_sign(state, app->size, app->hash);
out:
	rcu_read_unlock();
	return allowed;
}

bool ksu_finasu_dynamic_manager_version_code(u32 uid, u32 *out)
{
	struct finasu_manager_snapshot *state;
	struct finasu_scanned_app *app;
	const struct ksu_finasu_dynamic_manager_sign *sign;
	u32 appid = uid % FINASU_PER_USER_RANGE;
	bool found = false;

	if (!out)
		return false;
	rcu_read_lock();
	state = rcu_dereference(finasu_managers);
	if (!state)
		goto unlock;
	app = find_scanned_app(appid);
	if (!app)
		goto unlock;
	sign = find_sign(state, app->size, app->hash);
	if (sign && sign->version_code) {
		*out = sign->version_code;
		found = true;
	}
unlock:
	rcu_read_unlock();
	return found;
}

int ksu_finasu_dynamic_manager_reset_scanned(void)
{
	int ret = 0;

	mutex_lock(&finasu_manager_lock);
	if (!rcu_access_pointer(finasu_managers))
		ret = -EOPNOTSUPP;
	else
		clear_scanned_apps();
	mutex_unlock(&finasu_manager_lock);
	return ret;
}

int ksu_finasu_dynamic_manager_note_scanned(u32 appid, u8 signature_index,
					 unsigned int size, const char *hash)
{
	struct finasu_manager_snapshot *state;
	struct finasu_scanned_app *app, *next;
	char normalized[65];
	bool preset, candidate;
	int ret = 0;

	if (appid >= FINASU_PER_USER_RANGE || !size || size > KSU_FINASU_DYNAMIC_MANAGER_CERT_MAX ||
	    !normalize_hash(normalized, hash))
		return -EINVAL;
	preset = ksu_finasu_dynamic_manager_signature_is_preset(size, normalized);
	mutex_lock(&finasu_manager_lock);
	state = rcu_dereference_protected(finasu_managers, lockdep_is_held(&finasu_manager_lock));
	if (!state) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	candidate = signature_index != KSU_SIG_FINASU &&
		(preset || find_sign(state, size, normalized));
	app = find_scanned_app(appid);
	if (!candidate) {
		if (app) {
			hash_del_rcu(&app->node);
			kfree_rcu(app, rcu);
		}
		goto out;
	}
	next = kzalloc(sizeof(*next), GFP_KERNEL);
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	next->appid = appid;
	next->size = size;
	memcpy(next->hash, normalized, sizeof(next->hash));
	next->preset = preset;
	if (app) {
		hlist_replace_rcu(&app->node, &next->node);
		kfree_rcu(app, rcu);
	} else {
		hash_add_rcu(finasu_scanned_apps, &next->node, appid);
	}
out:
	mutex_unlock(&finasu_manager_lock);
	return ret;
}

int ksu_finasu_dynamic_manager_set_managers(void __user *arg)
{
	struct ksu_finasu_dynamic_manager_cmd cmd;
	struct ksu_finasu_dynamic_manager_sign *signs = NULL;
	struct finasu_manager_snapshot *old, *next = NULL;
	u32 i;
	int ret;

	if (ksu_get_uid_t(current_uid()) != 0)
		return -EPERM;
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.count > KSU_FINASU_DYNAMIC_MANAGER_MAX_SIGNS)
		return -EINVAL;
	if (cmd.count) {
		if (!cmd.signs)
			return -EFAULT;
		signs = memdup_user(u64_to_user_ptr(cmd.signs), cmd.count * sizeof(*signs));
		if (IS_ERR(signs))
			return PTR_ERR(signs);
		ret = validate_signs(signs, cmd.count);
		if (ret)
			goto free;
	}
	mutex_lock(&finasu_manager_lock);
	old = rcu_dereference_protected(finasu_managers, lockdep_is_held(&finasu_manager_lock));
	ret = -EOPNOTSUPP;
	if (!old)
		goto unlock;
	next = clone_snapshot(old);
	ret = -ENOMEM;
	if (!next)
		goto unlock;
	memset(next->signs, 0, sizeof(next->signs));
	next->sign_count = cmd.count;
	for (i = 0; i < cmd.count; i++) {
		next->signs[i].size = signs[i].size;
		next->signs[i].version_code = signs[i].version_code;
		memcpy(next->signs[i].hash, signs[i].hash, sizeof(next->signs[i].hash));
	}
	ret = commit_snapshot(next, true, false);
	if (!ret)
		next = NULL;
unlock:
	mutex_unlock(&finasu_manager_lock);
free:
	kfree(next);
	kfree(signs);
	/* Never scan while holding the snapshot/IO mutex or the native manager RCU. */
	if (!ret)
		track_throne(TRACK_THRONE_FORCE_SYNCHRONOUS);
	return ret;
}

int ksu_finasu_dynamic_manager_set_grants(void __user *arg)
{
	struct ksu_finasu_dynamic_manager_grants_cmd cmd;
	struct finasu_manager_snapshot *old, *next = NULL;
	u32 *appids = NULL;
	u32 i;
	int ret;

	if (ksu_get_uid_t(current_uid()) != 0)
		return -EPERM;
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.reserved || cmd.count > KSU_FINASU_DYNAMIC_MANAGER_MAX_APPS)
		return -EINVAL;
	if (cmd.count) {
		if (!cmd.appids)
			return -EFAULT;
		appids = memdup_user(u64_to_user_ptr(cmd.appids), cmd.count * sizeof(*appids));
		if (IS_ERR(appids))
			return PTR_ERR(appids);
		for (i = 0; i < cmd.count; i++) {
			if (appids[i] >= FINASU_PER_USER_RANGE) {
				ret = -EINVAL;
				goto free;
			}
		}
	}
	mutex_lock(&finasu_manager_lock);
	old = rcu_dereference_protected(finasu_managers, lockdep_is_held(&finasu_manager_lock));
	ret = -EOPNOTSUPP;
	if (!old)
		goto unlock;
	next = clone_snapshot(old);
	ret = -ENOMEM;
	if (!next)
		goto unlock;
	next->grant_count = 0;
	memset(next->grants, 0, sizeof(next->grants));
	for (i = 0; i < cmd.count; i++) {
		if (!has_grant(next, appids[i]))
			next->grants[next->grant_count++] = appids[i];
	}
	/* Even the first empty list is an explicit, persistent deny-all decision. */
	next->grants_strict = true;
	ret = commit_snapshot(next, false, true);
	if (!ret)
		next = NULL;
unlock:
	mutex_unlock(&finasu_manager_lock);
free:
	kfree(next);
	kfree(appids);
	if (!ret)
		track_throne(TRACK_THRONE_FORCE_SYNCHRONOUS);
	return ret;
}

int ksu_finasu_dynamic_manager_get_managers(void __user *arg)
{
	struct ksu_finasu_get_dynamic_managers_cmd cmd;
	struct ksu_finasu_dynamic_manager_app *apps = NULL;
	struct finasu_manager_snapshot *state;
	struct finasu_scanned_app *app;
	u32 capacity;
	int bucket;
	int ret = 0;

	if (ksu_get_uid_t(current_uid()) != 0 && !is_manager())
		return -EPERM;
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;
	capacity = min_t(u32, cmd.count, KSU_FINASU_DYNAMIC_MANAGER_MAX_APPS);
	if (capacity) {
		apps = kcalloc(capacity, sizeof(*apps), GFP_KERNEL);
		if (!apps)
			return -ENOMEM;
	}
	cmd.count = 0;
	cmd.total_count = 0;
	mutex_lock(&finasu_manager_lock);
	state = rcu_dereference_protected(finasu_managers, lockdep_is_held(&finasu_manager_lock));
	if (!state) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}
	hash_for_each(finasu_scanned_apps, bucket, app, node) {
		u32 flags = app_flags(state, app);

		if (!flags)
			continue;
		if (cmd.count < capacity) {
			apps[cmd.count].appid = app->appid;
			apps[cmd.count++].flags = flags;
		}
		cmd.total_count++;
	}
unlock:
	mutex_unlock(&finasu_manager_lock);
	if (ret)
		goto out;
	if (cmd.count && (!cmd.apps ||
		copy_to_user(u64_to_user_ptr(cmd.apps), apps, cmd.count * sizeof(*apps)))) {
		ret = -EFAULT;
		goto out;
	}
	if (copy_to_user(arg, &cmd, sizeof(cmd)))
		ret = -EFAULT;
out:
	kfree(apps);
	return ret;
}

int ksu_finasu_dynamic_manager_feature_get(u64 *value)
{
	bool supported;

	if (!value)
		return -EINVAL;
	rcu_read_lock();
	supported = rcu_dereference(finasu_managers) != NULL;
	rcu_read_unlock();
	if (!supported)
		return -EOPNOTSUPP;
	*value = 1;
	return 0;
}

int ksu_finasu_dynamic_manager_grants_feature_get(u64 *value)
{
	return ksu_finasu_dynamic_manager_feature_get(value);
}

static struct ksu_feature_handler finasu_sign_feature = {
	.name = "finasu_dynamic_manager",
	.get_handler = ksu_finasu_dynamic_manager_feature_get,
	.set_handler = NULL,
};

static struct ksu_feature_handler finasu_grant_feature = {
	.name = "finasu_dynamic_manager_grants",
	.get_handler = ksu_finasu_dynamic_manager_grants_feature_get,
	.set_handler = NULL,
};

int __init ksu_finasu_dynamic_manager_init(u32 sign_feature_id, u32 grant_feature_id)
{
	struct finasu_manager_snapshot *state;
	int ret;

	if (IS_ENABLED(CONFIG_KSU_DISABLE_MANAGER))
		return -EOPNOTSUPP;
	if (sign_feature_id == grant_feature_id)
		return -EINVAL;
	if (rcu_access_pointer(finasu_managers))
		return -EALREADY;
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	finasu_sign_feature.feature_id = sign_feature_id;
	finasu_grant_feature.feature_id = grant_feature_id;
	ret = ksu_register_feature_handler(&finasu_sign_feature);
	if (ret)
		goto free;
	ret = ksu_register_feature_handler(&finasu_grant_feature);
	if (ret) {
		ksu_unregister_feature_handler(sign_feature_id);
		goto free;
	}
	mutex_lock(&finasu_manager_lock);
	hash_init(finasu_scanned_apps);
	signs_pending = false;
	grants_pending = false;
	publish_snapshot(state);
	mutex_unlock(&finasu_manager_lock);
	return 0;
free:
	kfree(state);
	return ret;
}

void ksu_finasu_dynamic_manager_exit(void)
{
	struct finasu_manager_snapshot *state;

	mutex_lock(&finasu_manager_lock);
	state = rcu_dereference_protected(finasu_managers, lockdep_is_held(&finasu_manager_lock));
	RCU_INIT_POINTER(finasu_managers, NULL);
	clear_scanned_apps();
	signs_pending = false;
	grants_pending = false;
	mutex_unlock(&finasu_manager_lock);
	if (!state)
		return;
	ksu_unregister_feature_handler(finasu_grant_feature.feature_id);
	ksu_unregister_feature_handler(finasu_sign_feature.feature_id);
	synchronize_rcu();
	kfree(state);
	/* No task_work or file-IO callbacks can survive backend teardown. */
	rcu_barrier();
}
