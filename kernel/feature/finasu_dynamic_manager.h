/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Namespaced FinaSU v1.6.4 dynamic-manager ABI, adapted 2026-11-18 from
 * LyraVoid/FinaSU ff0e34f1d9d5694ab7b4f1e318a77c781d65cb41:
 * kernel/manager/dynamic_manager.h and uapi/supercall.h.
 */
#ifndef __KSU_FINASU_DYNAMIC_MANAGER_H
#define __KSU_FINASU_DYNAMIC_MANAGER_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KSU_FINASU_DYNAMIC_MANAGER_MAX_SIGNS 64
#define KSU_FINASU_DYNAMIC_MANAGER_MAX_APPS 64
#define KSU_FINASU_DYNAMIC_MANAGER_CERT_MAX 1024

struct ksu_finasu_dynamic_manager_sign {
	__u32 size;
	__u32 version_code; /* Configured APK versionCode; 0 means unknown. */
	char hash[65];
};

struct ksu_finasu_dynamic_manager_cmd {
	__u32 count;
	__aligned_u64 signs;
};

#define KSU_FINASU_DYNAMIC_MANAGER_FLAG_PRESET (1U << 0)
#define KSU_FINASU_DYNAMIC_MANAGER_FLAG_TRUSTED (1U << 1)
#define KSU_FINASU_DYNAMIC_MANAGER_FLAG_GRANTED (1U << 2)

struct ksu_finasu_dynamic_manager_app {
	__u32 appid;
	__u32 flags;
};

struct ksu_finasu_get_dynamic_managers_cmd {
	__u32 count; /* Input capacity; output entries written. */
	__u32 total_count;
	__aligned_u64 apps;
};

struct ksu_finasu_dynamic_manager_grants_cmd {
	__u32 count;
	__u32 reserved; /* Must be 0. */
	__aligned_u64 appids;
};

/* nr22 also has the unrelated WRITE/24-byte LOOKUP_SYMBOLS command. */
#define KSU_FINASU_IOCTL_SET_DYNAMIC_MANAGERS _IOC(_IOC_WRITE, 'K', 22, 0)
#define KSU_FINASU_IOCTL_GET_DYNAMIC_MANAGERS \
	_IOWR('K', 23, struct ksu_finasu_get_dynamic_managers_cmd)
#define KSU_FINASU_IOCTL_SET_DYNAMIC_MANAGER_GRANTS _IOC(_IOC_WRITE, 'K', 24, 0)

#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/uaccess.h>

int __init ksu_finasu_dynamic_manager_init(u32 sign_feature_id, u32 grant_feature_id);
void ksu_finasu_dynamic_manager_exit(void);

/*
 * Call after /data/adb/ksu exists, before the post-fs-data/late-load census.
 * Retry errors; a failed restore does not reopen dynamic authorization.
 * Pre-ready SETs are cached, then merged with the untouched persisted fields.
 */
int ksu_finasu_dynamic_manager_load(void);

int ksu_finasu_dynamic_manager_feature_get(u64 *value);
int ksu_finasu_dynamic_manager_grants_feature_get(u64 *value);

/*
 * Main dispatch must additionally restrict these exact commands to Fina/root.
 * Ready SETs fail before atomic rename, retaining the previous file and RAM.
 * After rename they return 0 and publish RAM even if directory fsync/close fails;
 * such failures are logged because crash durability can no longer be promised.
 * Pre-ready SETs remain cached as described above, without a disk commit yet.
 */
int ksu_finasu_dynamic_manager_set_managers(void __user *arg);
int ksu_finasu_dynamic_manager_get_managers(void __user *arg);
int ksu_finasu_dynamic_manager_set_grants(void __user *arg);

/* Read-only, non-sleeping helpers, including inside the native manager RCU read. */
bool ksu_finasu_dynamic_manager_signature_matches(unsigned int size, const char *hash);
bool ksu_finasu_dynamic_manager_signature_is_preset(unsigned int size, const char *hash);
bool ksu_finasu_dynamic_manager_uid_allowed(u32 uid, u8 signature_index);
bool ksu_finasu_dynamic_manager_version_code(u32 uid, u32 *out);

/*
 * Sleepable census hooks: pass the actual certificate size/hash, not a guessed
 * family key. appid is a full u32 Android appid (<100000), not a truncated u16.
 * Reset only after validating that a full census can run; grants are retained.
 * Note every candidate after package->appid resolution, before registration.
 * The fixed production Fina signature is deliberately not a dynamic candidate.
 * Query flags/versionCode are derived from this metadata and the current list.
 */
int ksu_finasu_dynamic_manager_reset_scanned(void);
int ksu_finasu_dynamic_manager_note_scanned(u32 appid, u8 signature_index,
					 unsigned int size, const char *hash);
#endif

#endif /* __KSU_FINASU_DYNAMIC_MANAGER_H */
