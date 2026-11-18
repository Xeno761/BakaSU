/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Namespaced FinaSU v1.6.4 ABI, unchanged from uapi/netisolate.h and
 * uapi/supercall.h at ff0e34f1d9d5694ab7b4f1e318a77c781d65cb41.
 */
#ifndef __KSU_FINASU_NET_ISOLATE_H
#define __KSU_FINASU_NET_ISOLATE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KSU_FINASU_NETISOLATE_MAX_UIDS 256
#define KSU_FINASU_NETISOLATE_MAX_POLICIES 256
#define KSU_FINASU_NETISOLATE_EVENT_MAX 64
#define KSU_FINASU_NETISOLATE_FLAG_MASK 0xffffu
#define KSU_FINASU_NETISOLATE_SUPPORTED_SHIFT 16u

#define KSU_FINASU_NETISOLATE_FLAG_STRICT_SOCKET (1u << 0)
#define KSU_FINASU_NETISOLATE_FLAG_ALLOW_LOOPBACK (1u << 1)
#define KSU_FINASU_NETISOLATE_FLAG_ALLOW_PRIVATE_NETWORK (1u << 2)
#define KSU_FINASU_NETISOLATE_FLAG_ALLOW_LOCAL_DISCOVERY (1u << 3)
#define KSU_FINASU_NETISOLATE_SUPPORTED_FLAGS \
	(KSU_FINASU_NETISOLATE_FLAG_STRICT_SOCKET | \
	 KSU_FINASU_NETISOLATE_FLAG_ALLOW_LOOPBACK | \
	 KSU_FINASU_NETISOLATE_FLAG_ALLOW_PRIVATE_NETWORK | \
	 KSU_FINASU_NETISOLATE_FLAG_ALLOW_LOCAL_DISCOVERY)

struct ksu_finasu_netisolate_config {
	__u32 enabled;
	__u32 count;
	__u32 compat_supported; /* Output; ignored on SET. */
	__u32 reserved; /* SET: flags; GET: active | supported << 16. */
	__u32 uids[KSU_FINASU_NETISOLATE_MAX_UIDS];
};

struct ksu_finasu_netisolate_policy {
	__u32 uid;
	__u32 flags;
};

struct ksu_finasu_netisolate_policies {
	__u32 enabled;
	__u32 count;
	__u32 supported_flags; /* Output; must be 0 on SET. */
	__u32 reserved; /* Must be 0. */
	struct ksu_finasu_netisolate_policy policies[KSU_FINASU_NETISOLATE_MAX_POLICIES];
};

struct ksu_finasu_netisolate_event {
	__u64 timestamp_ns;
	__u32 uid;
	__u16 port; /* Host byte order; 0 if not parsed. */
	__u8 family;
	__u8 operation;
	__u8 address[16];
	__u32 reserved;
};

struct ksu_finasu_netisolate_events {
	__u32 count;
	__u32 capacity;
	__u64 dropped;
	struct ksu_finasu_netisolate_event events[KSU_FINASU_NETISOLATE_EVENT_MAX];
};

enum ksu_finasu_netisolate_operation {
	KSU_FINASU_NETISOLATE_CONNECT = 0,
	KSU_FINASU_NETISOLATE_SENDTO = 1,
	KSU_FINASU_NETISOLATE_SENDMSG = 2,
	KSU_FINASU_NETISOLATE_SENDMMSG = 3,
	KSU_FINASU_NETISOLATE_SOCKET = 4,
};

/* Match the entire command: nr29 also has an unrelated READ/64 version ABI. */
#define KSU_FINASU_IOCTL_GET_NETISOLATE_CONFIG \
	_IOWR('K', 27, struct ksu_finasu_netisolate_config)
#define KSU_FINASU_IOCTL_SET_NETISOLATE_CONFIG \
	_IOW('K', 28, struct ksu_finasu_netisolate_config)
#define KSU_FINASU_IOCTL_GET_NETISOLATE_POLICIES \
	_IOWR('K', 29, struct ksu_finasu_netisolate_policies)
#define KSU_FINASU_IOCTL_SET_NETISOLATE_POLICIES \
	_IOW('K', 30, struct ksu_finasu_netisolate_policies)
#define KSU_FINASU_IOCTL_GET_NETISOLATE_EVENTS \
	_IOWR('K', 31, struct ksu_finasu_netisolate_events)
#define KSU_FINASU_IOCTL_CLEAR_NETISOLATE_EVENTS \
	_IOW('K', 32, struct ksu_finasu_netisolate_events)

#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/uaccess.h>

enum ksu_finasu_netisolate_backend {
	KSU_FINASU_NETISOLATE_BACKEND_UNAVAILABLE = 0,
	KSU_FINASU_NETISOLATE_BACKEND_BUILTIN_LSM = 1,
};

int __init ksu_finasu_netisolate_init(void);
void ksu_finasu_netisolate_exit(void);
bool ksu_finasu_netisolate_supported(void);
bool ksu_finasu_netisolate_compat_supported(void);
bool ksu_finasu_netisolate_enabled(void);
enum ksu_finasu_netisolate_backend ksu_finasu_netisolate_backend(void);

/* Main dispatch must authenticate root/Fina callers before invoking these. */
int ksu_finasu_netisolate_get_config(void __user *arg);
int ksu_finasu_netisolate_set_config(void __user *arg);
int ksu_finasu_netisolate_get_policies(void __user *arg);
int ksu_finasu_netisolate_set_policies(void __user *arg);
int ksu_finasu_netisolate_get_events(void __user *arg);
int ksu_finasu_netisolate_clear_events(void __user *arg);
#endif

#endif /* __KSU_FINASU_NET_ISOLATE_H */
