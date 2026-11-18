// SPDX-License-Identifier: GPL-2.0-only
/*
 * FinaSU v1.6.4, ff0e34f1d9d5694ab7b4f1e318a77c781d65cb41,
 * kernel/feature/netisolate.c (kernel/LICENSE: GPL v2).
 * Modified 2026-11-18: built-in LSM enforcement, namespaced ABI, and connected
 * peer checks instead of syscall-table patching. No socket-owner UID cache.
 */
#include <linux/build_bug.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>

#include "finasu_net_isolate.h"

#if !defined(MODULE) && defined(CONFIG_SECURITY) && \
	defined(CONFIG_SECURITY_NETWORK) && defined(CONFIG_INET)
#define NI_BUILTIN_LSM 1
#include <linux/lsm_hooks.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/udp.h>
#include "manager/manager_identity.h"
#ifdef CONFIG_ARM64
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#endif
#else
#define NI_BUILTIN_LSM 0
#endif

static_assert(sizeof(struct ksu_finasu_netisolate_config) == 1040);
static_assert(sizeof(struct ksu_finasu_netisolate_policy) == 8);
static_assert(sizeof(struct ksu_finasu_netisolate_policies) == 2064);
static_assert(sizeof(struct ksu_finasu_netisolate_event) == 40);
static_assert(sizeof(struct ksu_finasu_netisolate_events) == 2576);
static_assert(offsetof(struct ksu_finasu_netisolate_event, address) == 16);
static_assert(offsetof(struct ksu_finasu_netisolate_event, reserved) == 32);
static_assert(offsetof(struct ksu_finasu_netisolate_events, events) == 16);

#define NI_ALLOW_FLAGS \
	(KSU_FINASU_NETISOLATE_FLAG_ALLOW_LOOPBACK | \
	 KSU_FINASU_NETISOLATE_FLAG_ALLOW_PRIVATE_NETWORK | \
	 KSU_FINASU_NETISOLATE_FLAG_ALLOW_LOCAL_DISCOVERY)

struct ni_state {
	u32 enabled;
	u32 count;
	struct ksu_finasu_netisolate_policy policies[KSU_FINASU_NETISOLATE_MAX_POLICIES];
};

struct ni_event_ring {
	u32 head;
	u32 count;
	u64 dropped;
	struct ksu_finasu_netisolate_event events[KSU_FINASU_NETISOLATE_EVENT_MAX];
};

static DEFINE_MUTEX(ni_lifecycle_lock);
static DEFINE_SPINLOCK(ni_state_lock);
static DEFINE_SPINLOCK(ni_event_lock);
static DEFINE_STATIC_KEY_FALSE(ni_enabled_key);
static struct ni_state ni_state;
static struct ni_event_ring ni_events;
static bool ni_registered;
static bool ni_stopping;

bool ksu_finasu_netisolate_supported(void)
{
	return NI_BUILTIN_LSM && READ_ONCE(ni_registered) &&
		!READ_ONCE(ni_stopping);
}

bool ksu_finasu_netisolate_compat_supported(void)
{
	/* Compat messages pass through the same LSM after kernel copying. */
	return ksu_finasu_netisolate_supported() && IS_ENABLED(CONFIG_COMPAT);
}

bool ksu_finasu_netisolate_enabled(void)
{
	return ksu_finasu_netisolate_supported() && READ_ONCE(ni_state.enabled);
}

enum ksu_finasu_netisolate_backend ksu_finasu_netisolate_backend(void)
{
	return ksu_finasu_netisolate_supported() ?
		KSU_FINASU_NETISOLATE_BACKEND_BUILTIN_LSM :
		KSU_FINASU_NETISOLATE_BACKEND_UNAVAILABLE;
}

#if NI_BUILTIN_LSM
struct ni_endpoint {
	u8 family;
	u8 address[16];
	u16 port;
};

enum ni_target_class {
	NI_TARGET_LOOPBACK,
	NI_TARGET_PRIVATE_NETWORK,
	NI_TARGET_LOCAL_DISCOVERY,
	NI_TARGET_OTHER_IP,
};

static bool ni_policy_match(u32 uid, u32 *policy_flags)
{
	unsigned long flags;
	u32 i;
	bool matched = false;

	if (!READ_ONCE(ni_state.enabled) || READ_ONCE(ni_stopping))
		return false;
	/* These are the only upstream exemptions, not root-granted app UIDs. */
	if (!uid || ksu_is_manager_uid(uid))
		return false;

	spin_lock_irqsave(&ni_state_lock, flags);
	if (ni_state.enabled) {
		for (i = 0; i < ni_state.count; i++) {
			if (ni_state.policies[i].uid == uid) {
				*policy_flags = ni_state.policies[i].flags;
				matched = true;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&ni_state_lock, flags);
	return matched;
}

static enum ni_target_class ni_ipv4_target(const struct in_addr *address)
{
	const u8 *bytes = (const u8 *)&address->s_addr;

	if (bytes[0] == 127)
		return NI_TARGET_LOOPBACK;
	if (bytes[0] == 224 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 251)
		return NI_TARGET_LOCAL_DISCOVERY;
	if (bytes[0] == 239 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 250)
		return NI_TARGET_LOCAL_DISCOVERY;
	if (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
	    (bytes[0] == 192 && bytes[1] == 168) || (bytes[0] == 169 && bytes[1] == 254))
		return NI_TARGET_PRIVATE_NETWORK;
	return NI_TARGET_OTHER_IP;
}

static enum ni_target_class ni_ipv6_target(const struct in6_addr *address)
{
	const u8 *bytes = address->s6_addr;
	struct in_addr mapped;
	bool zero_prefix = true;
	u32 i;

	for (i = 0; i < 10; i++) {
		if (bytes[i]) {
			zero_prefix = false;
			break;
		}
	}
	if (zero_prefix && !bytes[10] && !bytes[11]) {
		for (i = 12; i < 15; i++) {
			if (bytes[i])
				break;
		}
		if (i == 15 && bytes[15] == 1)
			return NI_TARGET_LOOPBACK;
	}
	if (zero_prefix && bytes[10] == 0xff && bytes[11] == 0xff) {
		memcpy(&mapped, &bytes[12], sizeof(mapped));
		return ni_ipv4_target(&mapped);
	}
	if (bytes[0] == 0xff && bytes[1] == 0x02) {
		for (i = 2; i < 15; i++) {
			if (bytes[i])
				return NI_TARGET_OTHER_IP;
		}
		/* The pinned implementation permits ff02::fb, not ff02::c. */
		return bytes[15] == 0xfb ? NI_TARGET_LOCAL_DISCOVERY : NI_TARGET_OTHER_IP;
	}
	if ((bytes[0] & 0xfe) == 0xfc || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80))
		return NI_TARGET_PRIVATE_NETWORK;
	return NI_TARGET_OTHER_IP;
}

static bool ni_target_allowed(enum ni_target_class target_class, u32 policy_flags)
{
	switch (target_class) {
	case NI_TARGET_LOOPBACK:
		return policy_flags & KSU_FINASU_NETISOLATE_FLAG_ALLOW_LOOPBACK;
	case NI_TARGET_PRIVATE_NETWORK:
		return policy_flags & KSU_FINASU_NETISOLATE_FLAG_ALLOW_PRIVATE_NETWORK;
	case NI_TARGET_LOCAL_DISCOVERY:
		return policy_flags & KSU_FINASU_NETISOLATE_FLAG_ALLOW_LOCAL_DISCOVERY;
	default:
		return false;
	}
}

static enum ni_target_class ni_sockaddr_target(const struct sockaddr *address,
					      int address_length, int socket_family,
					      bool send, struct ni_endpoint *endpoint)
{
	u16 family;

	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->family = socket_family;
	if (!address || address_length < (int)sizeof(address->sa_family))
		return NI_TARGET_OTHER_IP;
	memcpy(&family, address, sizeof(family));
	/* IPv4 UDP accepts AF_UNSPEC with a real sockaddr_in destination. */
	if (send && family == AF_UNSPEC && socket_family == AF_INET)
		family = AF_INET;
	if (family == AF_INET) {
		struct sockaddr_in addr;

		if (address_length < (int)sizeof(addr))
			return NI_TARGET_OTHER_IP;
		memcpy(&addr, address, sizeof(addr));
		endpoint->family = AF_INET;
		memcpy(endpoint->address, &addr.sin_addr, sizeof(addr.sin_addr));
		endpoint->port = ntohs(addr.sin_port);
		return ni_ipv4_target(&addr.sin_addr);
	}
	if (family == AF_INET6) {
		struct sockaddr_in6 addr;
		/* IPv6 also accepts the RFC2133 sockaddr without scope_id. */
		int minimum = offsetof(struct sockaddr_in6, sin6_scope_id);

		if (address_length < minimum)
			return NI_TARGET_OTHER_IP;
		memset(&addr, 0, sizeof(addr));
		memcpy(&addr, address, min_t(size_t, address_length, sizeof(addr)));
		endpoint->family = AF_INET6;
		memcpy(endpoint->address, &addr.sin6_addr, sizeof(addr.sin6_addr));
		endpoint->port = ntohs(addr.sin6_port);
		return ni_ipv6_target(&addr.sin6_addr);
	}
	return NI_TARGET_OTHER_IP;
}

static enum ni_target_class ni_peer_target(const struct sock *sk,
					 struct ni_endpoint *endpoint)
{
	struct in_addr addr;

	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->family = READ_ONCE(sk->sk_family);
	endpoint->port = ntohs(READ_ONCE(sk->sk_dport));
	if (endpoint->family == AF_INET) {
		addr.s_addr = READ_ONCE(sk->sk_daddr);
		memcpy(endpoint->address, &addr, sizeof(addr));
		return ni_ipv4_target(&addr);
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (endpoint->family == AF_INET6) {
		struct in6_addr addr6;
		u32 i;

		for (i = 0; i < ARRAY_SIZE(addr6.s6_addr32); i++)
			addr6.s6_addr32[i] = READ_ONCE(sk->sk_v6_daddr.s6_addr32[i]);
		memcpy(endpoint->address, &addr6, sizeof(addr6));
		return ni_ipv6_target(&addr6);
	}
#endif
	return NI_TARGET_OTHER_IP;
}

static enum ni_target_class ni_send_target(struct socket *sock, struct msghdr *msg,
					 struct ni_endpoint *endpoint)
{
	struct sock *sk = sock->sk;
	int family = READ_ONCE(sk->sk_family);
	u16 protocol = READ_ONCE(sk->sk_protocol);

	/* A transferred, corked UDP socket ignores the next message's name. */
	if (sock->type == SOCK_DGRAM &&
	    (protocol == IPPROTO_UDP || protocol == IPPROTO_UDPLITE)) {
		int pending = READ_ONCE(udp_sk(sk)->pending);

		if (pending) {
			const struct flowi *flow = &inet_sk(sk)->cork.fl;
			struct in_addr addr;

			memset(endpoint, 0, sizeof(*endpoint));
			endpoint->family = pending;
			if (pending == AF_INET) {
				addr.s_addr = READ_ONCE(flow->u.ip4.daddr);
				endpoint->port = ntohs(READ_ONCE(flow->u.ip4.fl4_dport));
				memcpy(endpoint->address, &addr, sizeof(addr));
				return ni_ipv4_target(&addr);
			}
#if IS_ENABLED(CONFIG_IPV6)
			if (pending == AF_INET6) {
				struct in6_addr addr6;
				u32 i;

				for (i = 0; i < ARRAY_SIZE(addr6.s6_addr32); i++)
					addr6.s6_addr32[i] = READ_ONCE(flow->u.ip6.daddr.s6_addr32[i]);
				endpoint->port = ntohs(READ_ONCE(flow->u.ip6.fl6_dport));
				memcpy(endpoint->address, &addr6, sizeof(addr6));
				return ni_ipv6_target(&addr6);
			}
#endif
			return NI_TARGET_OTHER_IP;
		}
	}

	/* Connected streams ignore msg_name; only a new Fast Open uses it. */
	if (sock->type == SOCK_STREAM &&
	    (!(msg->msg_flags & MSG_FASTOPEN) || READ_ONCE(sk->sk_dport)))
		return ni_peer_target(sk, endpoint);
	if (msg->msg_name) {
		const struct sockaddr *address = msg->msg_name;

		/* IPv6 UDP treats AF_UNSPEC as a send to the connected peer. */
		if (family == AF_INET6 && msg->msg_namelen >= (int)sizeof(address->sa_family) &&
		    address->sa_family == AF_UNSPEC)
			return ni_peer_target(sk, endpoint);
		return ni_sockaddr_target(address, msg->msg_namelen, family, true, endpoint);
	}
	return ni_peer_target(sk, endpoint);
}

static enum ksu_finasu_netisolate_operation ni_send_operation(void)
{
#ifdef CONFIG_ARM64
	struct pt_regs *regs;
	int nr;

	if (!current->mm)
		return KSU_FINASU_NETISOLATE_SENDMSG;
	regs = task_pt_regs(current);
	nr = syscall_get_nr(current, regs);
	if (nr < 0 || !user_mode(regs))
		return KSU_FINASU_NETISOLATE_SENDMSG;
#ifdef CONFIG_COMPAT
	if (in_compat_syscall()) {
		/* asm/unistd32.h numbers for event labels only, never table offsets. */
		if (nr == 290)
			return KSU_FINASU_NETISOLATE_SENDTO;
		if (nr == 374)
			return KSU_FINASU_NETISOLATE_SENDMMSG;
		return KSU_FINASU_NETISOLATE_SENDMSG;
	}
#endif
	if (nr == __NR_sendto)
		return KSU_FINASU_NETISOLATE_SENDTO;
	if (nr == __NR_sendmmsg)
		return KSU_FINASU_NETISOLATE_SENDMMSG;
#endif
	return KSU_FINASU_NETISOLATE_SENDMSG;
}

static void ni_record_event(u32 uid, enum ksu_finasu_netisolate_operation op,
			    const struct ni_endpoint *endpoint)
{
	struct ksu_finasu_netisolate_event event;
	unsigned long flags;
	u32 slot;

	/* Explicitly zero the ABI tail padding as well as reserved fields. */
	memset(&event, 0, sizeof(event));
	event.timestamp_ns = ktime_get_ns();
	event.uid = uid;
	event.port = endpoint->port;
	event.family = endpoint->family;
	event.operation = op;
	memcpy(event.address, endpoint->address, sizeof(event.address));

	spin_lock_irqsave(&ni_event_lock, flags);
	if (!READ_ONCE(ni_stopping)) {
		slot = ni_events.head;
		ni_events.events[slot] = event;
		ni_events.head = (slot + 1) % KSU_FINASU_NETISOLATE_EVENT_MAX;
		if (ni_events.count < KSU_FINASU_NETISOLATE_EVENT_MAX)
			ni_events.count++;
		else
			ni_events.dropped++;
	}
	spin_unlock_irqrestore(&ni_event_lock, flags);
}

static int ni_socket_create(int family, int type, int protocol, int kern)
{
	struct ni_endpoint endpoint = { 0 };
	u32 uid, policy_flags;

	if (!static_branch_unlikely(&ni_enabled_key) || kern ||
	    (family != AF_INET && family != AF_INET6))
		return 0;
	uid = __kuid_val(current_uid());
	if (!ni_policy_match(uid, &policy_flags) ||
	    !(policy_flags & KSU_FINASU_NETISOLATE_FLAG_STRICT_SOCKET))
		return 0;
	endpoint.family = family;
	ni_record_event(uid, KSU_FINASU_NETISOLATE_SOCKET, &endpoint);
	return -EACCES;
}

static int ni_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct ni_endpoint endpoint;
	enum ni_target_class target;
	u32 uid, policy_flags;
	int family;

	if (!static_branch_unlikely(&ni_enabled_key) || !sock->sk)
		return 0;
	family = READ_ONCE(sock->sk->sk_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	uid = __kuid_val(current_uid());
	if (!ni_policy_match(uid, &policy_flags))
		return 0;
	/* AF_UNSPEC disconnects an IP socket; it does not establish a path. */
	if (address && addrlen >= (int)sizeof(address->sa_family) &&
	    address->sa_family == AF_UNSPEC)
		return 0;
	target = ni_sockaddr_target(address, addrlen, family, false, &endpoint);
	if (ni_target_allowed(target, policy_flags))
		return 0;
	ni_record_event(uid, KSU_FINASU_NETISOLATE_CONNECT, &endpoint);
	return -ECONNREFUSED;
}

static int ni_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	struct ni_endpoint endpoint;
	enum ni_target_class target;
	u32 uid, policy_flags;
	int family;

	if (!static_branch_unlikely(&ni_enabled_key) || !sock->sk)
		return 0;
	family = READ_ONCE(sock->sk->sk_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	uid = __kuid_val(current_uid());
	if (!ni_policy_match(uid, &policy_flags))
		return 0;
	target = ni_send_target(sock, msg, &endpoint);
	if (ni_target_allowed(target, policy_flags))
		return 0;
	ni_record_event(uid, ni_send_operation(), &endpoint);
	return -ECONNREFUSED;
}

static struct security_hook_list ni_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(socket_create, ni_socket_create),
	LSM_HOOK_INIT(socket_connect, ni_socket_connect),
	LSM_HOOK_INIT(socket_sendmsg, ni_socket_sendmsg),
};
#endif /* NI_BUILTIN_LSM */

static void ni_clear_events_locked(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ni_event_lock, flags);
	memset(&ni_events, 0, sizeof(ni_events));
	spin_unlock_irqrestore(&ni_event_lock, flags);
}

int __init ksu_finasu_netisolate_init(void)
{
#if NI_BUILTIN_LSM
	if (ni_registered)
		return -EBUSY;
	/* security_add_hooks is init-only, before hook heads become read-only. */
	security_add_hooks(ni_hooks, ARRAY_SIZE(ni_hooks), "ksu_finasu_netisolate");
	WRITE_ONCE(ni_registered, true);
	pr_info("ksu_finasu_netisolate: built-in LSM ready, compat=%u, disabled\n",
		IS_ENABLED(CONFIG_COMPAT));
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

void ksu_finasu_netisolate_exit(void)
{
	unsigned long flags;

	mutex_lock(&ni_lifecycle_lock);
	WRITE_ONCE(ni_stopping, true);
	spin_lock_irqsave(&ni_state_lock, flags);
	WRITE_ONCE(ni_state.enabled, 0);
	ni_state.count = 0;
	memset(ni_state.policies, 0, sizeof(ni_state.policies));
	spin_unlock_irqrestore(&ni_state_lock, flags);
	static_branch_disable(&ni_enabled_key);
	ni_clear_events_locked();
	/* Built-in LSM hooks remain resident; MODULE never registers these hooks. */
	mutex_unlock(&ni_lifecycle_lock);
}

static bool ni_flags_valid(u32 flags)
{
	return !(flags & ~KSU_FINASU_NETISOLATE_SUPPORTED_FLAGS) &&
		!((flags & KSU_FINASU_NETISOLATE_FLAG_STRICT_SOCKET) &&
		  (flags & NI_ALLOW_FLAGS));
}

static int ni_validate_config(const struct ksu_finasu_netisolate_config *config)
{
	u32 i, j;

	if (!ni_flags_valid(config->reserved) ||
	    config->count > KSU_FINASU_NETISOLATE_MAX_UIDS ||
	    (config->enabled && !config->count))
		return -EINVAL;
	for (i = 0; i < config->count; i++) {
		if (!config->uids[i])
			return -EINVAL;
		for (j = 0; j < i; j++) {
			if (config->uids[j] == config->uids[i])
				return -EINVAL;
		}
	}
	return 0;
}

static int ni_validate_policies(const struct ksu_finasu_netisolate_policies *config)
{
	u32 i, j;

	if (config->supported_flags || config->reserved ||
	    config->count > KSU_FINASU_NETISOLATE_MAX_POLICIES ||
	    (config->enabled && !config->count))
		return -EINVAL;
	for (i = 0; i < config->count; i++) {
		if (!config->policies[i].uid || !ni_flags_valid(config->policies[i].flags))
			return -EINVAL;
		for (j = 0; j < i; j++) {
			if (config->policies[j].uid == config->policies[i].uid)
				return -EINVAL;
		}
	}
	return 0;
}

static int ni_set_policies(const struct ksu_finasu_netisolate_policies *config)
{
	unsigned long flags;
	int ret = 0;

	mutex_lock(&ni_lifecycle_lock);
	if (!ksu_finasu_netisolate_supported()) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	spin_lock_irqsave(&ni_state_lock, flags);
	ni_state.count = config->count;
	memset(ni_state.policies, 0, sizeof(ni_state.policies));
	memcpy(ni_state.policies, config->policies,
	       config->count * sizeof(config->policies[0]));
	WRITE_ONCE(ni_state.enabled, !!config->enabled);
	spin_unlock_irqrestore(&ni_state_lock, flags);
	/* Jump-label patching can sleep, never perform it under an LSM/spin lock. */
	if (config->enabled)
		static_branch_enable(&ni_enabled_key);
	else
		static_branch_disable(&ni_enabled_key);
out:
	mutex_unlock(&ni_lifecycle_lock);
	return ret;
}

int ksu_finasu_netisolate_get_config(void __user *arg)
{
	struct ksu_finasu_netisolate_config *config;
	unsigned long flags;
	u32 common_flags = 0, i;
	int ret = 0;

	config = kzalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;
	mutex_lock(&ni_lifecycle_lock);
	if (!ksu_finasu_netisolate_supported()) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	spin_lock_irqsave(&ni_state_lock, flags);
	config->enabled = ni_state.enabled;
	config->count = ni_state.count;
	if (ni_state.count)
		common_flags = ni_state.policies[0].flags;
	for (i = 0; i < ni_state.count; i++) {
		config->uids[i] = ni_state.policies[i].uid;
		common_flags &= ni_state.policies[i].flags;
	}
	spin_unlock_irqrestore(&ni_state_lock, flags);
	config->compat_supported = ksu_finasu_netisolate_compat_supported();
	config->reserved = (common_flags & KSU_FINASU_NETISOLATE_FLAG_MASK) |
		(KSU_FINASU_NETISOLATE_SUPPORTED_FLAGS << KSU_FINASU_NETISOLATE_SUPPORTED_SHIFT);
out_unlock:
	mutex_unlock(&ni_lifecycle_lock);
	if (!ret && copy_to_user(arg, config, sizeof(*config)))
		ret = -EFAULT;
	kfree(config);
	return ret;
}

int ksu_finasu_netisolate_set_config(void __user *arg)
{
	struct ksu_finasu_netisolate_config *config;
	struct ksu_finasu_netisolate_policies *policies;
	u32 i;
	int ret;

	config = memdup_user(arg, sizeof(*config));
	if (IS_ERR(config))
		return PTR_ERR(config);
	ret = ni_validate_config(config);
	if (ret)
		goto out;
	policies = kzalloc(sizeof(*policies), GFP_KERNEL);
	if (!policies) {
		ret = -ENOMEM;
		goto out;
	}
	policies->enabled = config->enabled;
	policies->count = config->count;
	for (i = 0; i < config->count; i++) {
		policies->policies[i].uid = config->uids[i];
		policies->policies[i].flags = config->reserved;
	}
	ret = ni_set_policies(policies);
	kfree(policies);
out:
	kfree(config);
	return ret;
}

int ksu_finasu_netisolate_get_policies(void __user *arg)
{
	struct ksu_finasu_netisolate_policies *config;
	unsigned long flags;
	int ret = 0;

	config = kzalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;
	mutex_lock(&ni_lifecycle_lock);
	if (!ksu_finasu_netisolate_supported()) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	spin_lock_irqsave(&ni_state_lock, flags);
	config->enabled = ni_state.enabled;
	config->count = ni_state.count;
	memcpy(config->policies, ni_state.policies,
	       ni_state.count * sizeof(config->policies[0]));
	spin_unlock_irqrestore(&ni_state_lock, flags);
	config->supported_flags = KSU_FINASU_NETISOLATE_SUPPORTED_FLAGS;
out_unlock:
	mutex_unlock(&ni_lifecycle_lock);
	if (!ret && copy_to_user(arg, config, sizeof(*config)))
		ret = -EFAULT;
	kfree(config);
	return ret;
}

int ksu_finasu_netisolate_set_policies(void __user *arg)
{
	struct ksu_finasu_netisolate_policies *config;
	int ret;

	config = memdup_user(arg, sizeof(*config));
	if (IS_ERR(config))
		return PTR_ERR(config);
	ret = ni_validate_policies(config);
	if (!ret)
		ret = ni_set_policies(config);
	kfree(config);
	return ret;
}

int ksu_finasu_netisolate_get_events(void __user *arg)
{
	struct ksu_finasu_netisolate_events *events;
	unsigned long flags;
	u32 first, i;
	int ret = 0;

	events = kzalloc(sizeof(*events), GFP_KERNEL);
	if (!events)
		return -ENOMEM;
	mutex_lock(&ni_lifecycle_lock);
	if (!ksu_finasu_netisolate_supported()) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	spin_lock_irqsave(&ni_event_lock, flags);
	events->count = ni_events.count;
	events->capacity = KSU_FINASU_NETISOLATE_EVENT_MAX;
	events->dropped = ni_events.dropped;
	first = (ni_events.head + KSU_FINASU_NETISOLATE_EVENT_MAX - ni_events.count) %
		KSU_FINASU_NETISOLATE_EVENT_MAX;
	for (i = 0; i < ni_events.count; i++)
		events->events[i] = ni_events.events[(first + i) % KSU_FINASU_NETISOLATE_EVENT_MAX];
	spin_unlock_irqrestore(&ni_event_lock, flags);
out_unlock:
	mutex_unlock(&ni_lifecycle_lock);
	if (!ret && copy_to_user(arg, events, sizeof(*events)))
		ret = -EFAULT;
	kfree(events);
	return ret;
}

int ksu_finasu_netisolate_clear_events(void __user *arg)
{
	int ret = 0;

	/* Upstream ignores this argument despite the encoded 2576-byte size. */
	(void)arg;
	mutex_lock(&ni_lifecycle_lock);
	if (!ksu_finasu_netisolate_supported())
		ret = -EOPNOTSUPP;
	else
		ni_clear_events_locked();
	mutex_unlock(&ni_lifecycle_lock);
	return ret;
}
