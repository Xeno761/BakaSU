/* SPDX-License-Identifier: GPL-2.0-only */
/* FinaSU ff0e34f1d9d5694ab7b4f1e318a77c781d65cb41, uapi/uts_view.h ABI. */
#ifndef __KSU_FINASU_UTS_VIEW_H
#define __KSU_FINASU_UTS_VIEW_H

#include <linux/ioctl.h>
#include <linux/types.h>

#ifndef __KSU_UAPI_UTS_VIEW_H
#define __KSU_UAPI_UTS_VIEW_H

#define KSU_UTS_FIELD_SYSNAME (1U << 0)
#define KSU_UTS_FIELD_NODENAME (1U << 1)
#define KSU_UTS_FIELD_RELEASE (1U << 2)
#define KSU_UTS_FIELD_VERSION (1U << 3)
#define KSU_UTS_FIELD_MACHINE (1U << 4)
#define KSU_UTS_FIELD_DOMAINNAME (1U << 5)
#define KSU_UTS_FIELD_VALID_MASK ((1U << 6) - 1)
#define KSU_UTS_NAME_LEN 65

#define KSU_UTS_STATE_SUPPORTED (1U << 0)
#define KSU_UTS_STATE_ACTIVE (1U << 1)
#define KSU_UTS_STATE_OBSERVED (1U << 2)

#define KSU_UTS_MODE_GLOBAL (1U << 0)
#define KSU_UTS_MODE_SELECTED (1U << 1)
#define KSU_UTS_MODE_VALID_MASK (KSU_UTS_MODE_GLOBAL | KSU_UTS_MODE_SELECTED)
#define KSU_UTS_MAX_TARGETS 128

struct ksu_uts_view_config {
    __u32 field_mask;
    __u32 state;
    __u32 generation;
    __u32 mode;
    __u32 matched;
    __u32 discarded;
    __u32 last_pid;
    __u32 last_uid;
    __u32 skip_not_app;
    __u32 skip_isolated;
    __u32 skip_not_target;
    __u32 skip_not_zygote;
    __u32 skip_private_ns;
    __u32 reserved0;
    __u32 unshare_failed;
    __u32 merge_missing_ns;
    char sysname[KSU_UTS_NAME_LEN];
    char nodename[KSU_UTS_NAME_LEN];
    char release[KSU_UTS_NAME_LEN];
    char version[KSU_UTS_NAME_LEN];
    char machine[KSU_UTS_NAME_LEN];
    char domainname[KSU_UTS_NAME_LEN];
    __u32 target_count;
    __u32 target_uids[KSU_UTS_MAX_TARGETS];
};

#endif /* __KSU_UAPI_UTS_VIEW_H */

#define KSU_FINASU_IOCTL_GET_UTS_VIEW_CONFIG _IOWR('K', 25, struct ksu_uts_view_config)
#define KSU_FINASU_IOCTL_SET_UTS_VIEW_CONFIG _IOW('K', 26, struct ksu_uts_view_config)

#ifdef __KERNEL__
#include <linux/compiler_types.h>
#include <linux/init.h>

int __init ksu_finasu_uts_view_init(u32 feature_id);
void ksu_finasu_uts_view_exit(void);
int ksu_finasu_uts_view_feature_get(u64 *value);
int ksu_finasu_uts_view_feature_set(u64 value);
int ksu_finasu_uts_view_get_config(struct ksu_uts_view_config *config);
int ksu_finasu_uts_view_set_config(const struct ksu_uts_view_config *config);
int ksu_finasu_uts_view_get_config_handler(void __user *arg);
int ksu_finasu_uts_view_set_config_handler(void __user *arg);

/* Must run on the zygote child before credential specialization, including root-allowed targets. */
void ksu_finasu_uts_view_apply_for_uid(u32 target_uid);

/* Caller holds uts_sem(R). Returns actual owned coverage, including live, previously selected namespaces. */
u32 ksu_finasu_uts_view_current_mask(void);
#endif

#endif /* __KSU_FINASU_UTS_VIEW_H */
