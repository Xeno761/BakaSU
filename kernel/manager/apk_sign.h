#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>
#include "ksu.h"

struct file;

struct ksu_manager_apk_info {
    u8 signature_index;
    unsigned int certificate_size;
    char certificate_hash[65];
    u32 uapi_version;
};

bool is_manager_apk(char *path, u8 *signature_index);
bool ksu_get_manager_apk_info(char *path, struct ksu_manager_apk_info *info);
bool ksu_manager_apk_matches_executable(const char *path, struct file *executable);
int get_pkg_from_apk_path(char *pkg, const char *path);

bool is_dynamic_manager_apk(char *path, int *signature_index);

#endif
