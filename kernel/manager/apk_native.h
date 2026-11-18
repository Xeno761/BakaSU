/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSU_APK_NATIVE_H
#define KSU_APK_NATIVE_H

#include <linux/types.h>

/*
 * Parse an immutable, certificate-recognized APK JNI blob; no execution or I/O.
 * Returns 3..6, -ENOENT for no named getter, -EOPNOTSUPP for unsupported ELF/code,
 * -EBADMSG for malformed metadata, -EPROTO for conflicting/out-of-range constants,
 * or -E2BIG for excessive table work. The caller owns the size cap and fallback.
 */
int ksu_apk_native_uapi_version(const void *data, size_t size);

#endif
