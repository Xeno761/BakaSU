#ifndef __KSU_H_THRONE_TRACKER
#define __KSU_H_THRONE_TRACKER

#include <linux/errno.h>
#include <linux/types.h>

struct file;

#define TRACK_THRONE_PRUNE_ONLY (1 << 0)
#define TRACK_THRONE_FROM_RENAMEAT (1 << 1)
#define TRACK_THRONE_FORCE_SYNCHRONOUS (1 << 2)

#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline void ksu_throne_tracker_init(void)
{
}

static inline void ksu_throne_tracker_exit(void)
{
}

static inline void track_throne(unsigned int flags)
{
}

static inline int ksu_get_daemon_signature_index(struct file *executable)
{
    return -EOPNOTSUPP;
}

static inline int ksu_get_daemon_info(struct file *executable, u32 *uapi_version)
{
    return -EOPNOTSUPP;
}
#else
void ksu_throne_tracker_init(void);
void ksu_throne_tracker_exit(void);
void track_throne(unsigned int flags);
int ksu_get_daemon_signature_index(struct file *executable);
int ksu_get_daemon_info(struct file *executable, u32 *uapi_version);
#endif

#endif
