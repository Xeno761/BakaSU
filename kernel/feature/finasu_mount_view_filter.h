/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KSU_FINASU_MOUNT_VIEW_FILTER_H
#define __KSU_FINASU_MOUNT_VIEW_FILTER_H

#include <linux/init.h>
#include <linux/types.h>

/* FinaSU feature 10 is an independent toggle, with no feature-specific ioctl payload. */
int __init ksu_finasu_mount_view_filter_init(u32 feature_id);
void ksu_finasu_mount_view_filter_exit(void);
int ksu_finasu_mount_view_filter_feature_get(u64 *value);
int ksu_finasu_mount_view_filter_feature_set(u64 value);

#endif /* __KSU_FINASU_MOUNT_VIEW_FILTER_H */
