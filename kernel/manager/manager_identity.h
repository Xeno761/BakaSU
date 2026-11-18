#ifndef __KSU_H_MANAGER_IDENTITY
#define __KSU_H_MANAGER_IDENTITY

#include <linux/cred.h>
#include <linux/types.h>

#include "compat/kernel_compat.h"

#define KSU_SIGNATURE_INDEX_DYNAMIC_MANAGER 255
#define KSU_SIGNATURE_INDEX_KSU_DEBUG 254
#define KSU_SIGNATURE_INDEX_KSU_TOOLKIT 253
#define KSU_SIGNATURE_INDEX_FINASU_DYNAMIC_MANAGER 252

#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline void ksu_mark_manager(u32 uid)
{
}

static inline u32 ksu_get_manager_appid(void)
{
    return 0;
}

static inline u32 ksu_get_manager_uapi_by_appid(u32 appid)
{
    return 0;
}

static inline u32 ksu_get_manager_appid_by_signature(u8 signature_index)
{
    return 0;
}

static inline void ksu_register_manager_with_uapi(u32 uid, u8 signature_index, u32 uapi)
{
}

static inline bool is_manager(void)
{
    return ksu_get_uid_t(current_uid()) == 0;
}

static inline bool ksu_is_manager_appid(u32 appid)
{
    return appid == 0;
}

static inline bool ksu_is_manager_uid(u32 uid)
{
    return uid == 0;
}

static inline bool ksu_register_manager(u32 uid, u8 signature_index)
{
    return true;
}

static inline bool ksu_unregister_manager(u32 uid)
{
    return true;
}

static inline void ksu_unregister_manager_by_signature_index(u8 signature_index)
{
}

static inline int ksu_get_manager_signature_index_by_appid(u32 appid)
{
    return -EOPNOTSUPP;
}

static inline bool ksu_has_manager(void)
{
    return true;
}
#else
#define PER_USER_RANGE 100000
#define KSU_INVALID_APPID ((u32)-1)
extern u32 ksu_last_manager_appid;

void ksu_mark_manager(u32 uid);
u32 ksu_get_manager_appid(void);
u32 ksu_get_manager_uapi_by_appid(u32 appid);
u32 ksu_get_manager_appid_by_signature(u8 signature_index);

extern bool is_manager(void);
bool ksu_is_manager_appid(u32 appid);
extern bool ksu_is_manager_uid(u32 uid);
extern void ksu_register_manager(u32 uid, u8 signature_index);
void ksu_register_manager_with_uapi(u32 uid, u8 signature_index, u32 uapi);
extern void ksu_unregister_manager(u32 uid);
extern void ksu_unregister_manager_by_signature_index(u8 signature_index);
extern void ksu_unregister_all_manager(void);
extern int ksu_get_manager_signature_index_by_appid(u32 appid);
extern bool ksu_has_manager(void);
#endif

#endif
