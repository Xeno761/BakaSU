#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/zlib.h>
#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#include <linux/hex.h>
#endif

#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "policy/app_profile.h"
#include "feature/dynamic_manager.h"
#include "feature/finasu_dynamic_manager.h"
#include "klog.h" // IWYU pragma: keep
#include "manager_sign.h"
#include "apk_native.h"
#include "compat/kernel_compat.h"

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static apk_sign_key_t apk_sign_keys[] = {
    [KSU_SIG_BAKASU] = { EXPECTED_SIZE_BAKASU, EXPECTED_HASH_BAKASU },
#ifdef CONFIG_KSU_MULTI_MANAGER_SUPPORT
    [KSU_SIG_OFFICIAL] = { EXPECTED_SIZE_OFFICIAL, EXPECTED_HASH_OFFICIAL },
    [KSU_SIG_KSUNEXT] = { EXPECTED_SIZE_KSUNEXT, EXPECTED_HASH_KSUNEXT },
    [KSU_SIG_FINASU] = { EXPECTED_SIZE_FINASU, EXPECTED_HASH_FINASU },
    [KSU_SIG_SUKISU] = { EXPECTED_SIZE_SUKISU, EXPECTED_HASH_SUKISU },
    [KSU_SIG_MILKSU] = { EXPECTED_SIZE_MILKSU, EXPECTED_HASH_MILKSU },
    [KSU_SIG_WILDKSU] = { EXPECTED_SIZE_WILDKSU, EXPECTED_HASH_WILDKSU },
    [KSU_SIG_KSUNEXT_ALT] = { EXPECTED_SIZE_KSUNEXT_ALT, EXPECTED_HASH_KSUNEXT_ALT },
#ifdef EXPECTED_SIZE
    { EXPECTED_SIZE, EXPECTED_HASH }, // Custom
#endif
#ifdef EXPECTED_PR_BUILD_SIZE
    { EXPECTED_PR_BUILD_SIZE, EXPECTED_PR_BUILD_HASH }, // Custom 2 (For PR build)
#endif
#endif
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kzalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data, unsigned int datalen, unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int ksu_sha256(const unsigned char *data, unsigned int datalen, unsigned char *digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg);
    return ret;
}

static bool read_exact(struct file *fp, void *buffer, size_t size, loff_t *pos, loff_t end)
{
    if (*pos < 0 || *pos > end || size > (size_t)(end - *pos))
        return false;

    return ksu_kernel_read_compat(fp, buffer, size, pos) == (ssize_t)size;
}

static bool read_length_prefixed_end(struct file *fp, loff_t *pos, loff_t container_end, loff_t *value_end)
{
    u32 length;

    if (!read_exact(fp, &length, sizeof(length), pos, container_end))
        return false;
    if (length > INT_MAX || length > (u64)(container_end - *pos))
        return false;

    *value_end = *pos + length;
    return true;
}

static bool check_block(struct file *fp, loff_t *pos, loff_t block_end, u8 *matched_index,
                        struct ksu_manager_apk_info *info)
{
    u8 i;
    apk_sign_key_t sign_key;
    loff_t signers_end, signer_end, signed_data_end, digests_end, certificates_end;
    bool signature_valid = false;
    u32 certificate_size;

    // v2 block: signers sequence -> first signer -> signed data -> digests
    if (!read_length_prefixed_end(fp, pos, block_end, &signers_end) ||
        !read_length_prefixed_end(fp, pos, signers_end, &signer_end) ||
        !read_length_prefixed_end(fp, pos, signer_end, &signed_data_end) ||
        !read_length_prefixed_end(fp, pos, signed_data_end, &digests_end))
        return false;

    *pos = digests_end;
    if (!read_length_prefixed_end(fp, pos, signed_data_end, &certificates_end) ||
        !read_exact(fp, &certificate_size, sizeof(certificate_size), pos, certificates_end))
        return false;

    if (certificate_size > INT_MAX || certificate_size > (u64)(certificates_end - *pos))
        return false;

#define CERT_MAX_LENGTH 1024
    if (certificate_size > CERT_MAX_LENGTH) {
        pr_info("cert length overlimit\n");
        return false;
    }

    char cert[CERT_MAX_LENGTH];
    if (!read_exact(fp, cert, certificate_size, pos, certificates_end))
        return false;

    unsigned char digest[SHA256_DIGEST_SIZE];
    if (ksu_sha256(cert, certificate_size, digest)) {
        pr_info("sha256 error\n");
        return false;
    }

    char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
    hash_str[SHA256_DIGEST_SIZE * 2] = '\0';

    bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
    info->certificate_size = certificate_size;
    memcpy(info->certificate_hash, hash_str, sizeof(info->certificate_hash));
    pr_info("sha256: %s\n", hash_str);

    // keep 255, 254, 253 here
    // 255 reserved for dynamic manager
    // 254 reserved for ksu debug
    // 253 reserved for ksu toolkit
    BUILD_BUG_ON(ARRAY_SIZE(apk_sign_keys) > KSU_SIGNATURE_INDEX_FINASU_DYNAMIC_MANAGER);
    for (i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {
        sign_key = apk_sign_keys[i];
        if (certificate_size == sign_key.size && strcmp(sign_key.sha256, hash_str) == 0) {
            if (matched_index)
                *matched_index = i;
            signature_valid = true;
            break;
        }
    }

    if (!signature_valid && ksu_is_dynamic_manager_enabled()) {
        sign_key = ksu_get_dynamic_manager_sign();
        if (certificate_size == sign_key.size && strcmp(sign_key.sha256, hash_str) == 0) {
            if (matched_index)
                *matched_index = KSU_SIGNATURE_INDEX_DYNAMIC_MANAGER;
            signature_valid = true;
        }
    }
    if (!signature_valid && (ksu_finasu_dynamic_manager_signature_matches(certificate_size, hash_str) ||
                             ksu_finasu_dynamic_manager_signature_is_preset(certificate_size, hash_str))) {
        *matched_index = KSU_SIGNATURE_INDEX_FINASU_DYNAMIC_MANAGER;
        signature_valid = true;
    }
    return signature_valid;
}

struct zip_entry_header {
    uint32_t signature;
    uint16_t version;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
} __attribute__((packed));

struct zip_central_header {
    __le32 signature;
    __le16 version_made, version_needed, flags, compression, mod_time, mod_date;
    __le32 crc32, compressed_size, uncompressed_size;
    __le16 file_name_length, extra_field_length, comment_length, disk, internal_attr;
    __le32 external_attr, local_offset;
} __attribute__((packed));

struct zip_eocd {
    __le32 signature;
    __le16 disk, central_disk, disk_entries, entries;
    __le32 central_size, central_offset;
    __le16 comment_length;
} __attribute__((packed));

static bool get_zip_central_directory(struct file *fp, loff_t file_size, loff_t *offset, loff_t *end)
{
    struct zip_eocd eocd;
    unsigned int comment;

    for (comment = 0; comment <= 0xffff; comment++) {
        loff_t start = file_size - sizeof(eocd) - comment;
        loff_t pos = start;
        loff_t size;

        if (!read_exact(fp, &eocd, sizeof(eocd), &pos, file_size))
            return false;
        if (le32_to_cpu(eocd.signature) != 0x06054b50 || le16_to_cpu(eocd.comment_length) != comment)
            continue;
        if (eocd.disk || eocd.central_disk || eocd.disk_entries != eocd.entries)
            return false;

        *offset = le32_to_cpu(eocd.central_offset);
        size = le32_to_cpu(eocd.central_size);
        if (*offset > start || size > start - *offset)
            return false;
        *end = *offset + size;
        return true;
    }
    return false;
}

static bool executable_matches_range(struct file *fp, loff_t start, loff_t size, struct file *executable)
{
    char *buf;
    loff_t pos = start, exe_pos = 0, end;
    loff_t file_size = i_size_read(file_inode(fp));
    bool matched = false;

    if (start < 0 || size <= 0 || start > file_size || size > file_size - start ||
        size != i_size_read(file_inode(executable)))
        return false;
    end = start + size;

    buf = kmalloc(8192, GFP_KERNEL);
    if (!buf)
        return false;

    while (exe_pos < size) {
        size_t count = min_t(loff_t, 4096, size - exe_pos);

        if (!read_exact(fp, buf, count, &pos, end) ||
            !read_exact(executable, buf + 4096, count, &exe_pos, size) || memcmp(buf, buf + 4096, count))
            goto out;
    }
    matched = true;
out:
    kfree(buf);
    return matched;
}

static bool executable_matches_deflated_range(struct file *fp, loff_t start, u32 compressed_size, u32 size,
                                             struct file *executable)
{
    z_stream stream = { 0 };
    loff_t file_size = i_size_read(file_inode(fp));
    loff_t pos = start, exe_pos = 0, end;
    unsigned char *buf;
    bool matched = false;
    int ret;

    if (start < 0 || !compressed_size || !size || start > file_size || compressed_size > file_size - start ||
        size != i_size_read(file_inode(executable)))
        return false;
    end = start + compressed_size;

    buf = kmalloc(12288, GFP_KERNEL);
    if (!buf)
        return false;
    stream.workspace = vzalloc(zlib_inflate_workspacesize());
    if (!stream.workspace)
        goto out;
    if (zlib_inflateInit2(&stream, -MAX_WBITS) != Z_OK)
        goto free_workspace;

    for (;;) {
        unsigned long old_in = stream.total_in;
        size_t count;

        if (!stream.avail_in && pos < end) {
            count = min_t(loff_t, 4096, end - pos);
            if (!read_exact(fp, buf, count, &pos, end))
                break;
            stream.next_in = buf;
            stream.avail_in = count;
        }

        stream.next_out = buf + 4096;
        stream.avail_out = 4096;
        ret = zlib_inflate(&stream, Z_NO_FLUSH);
        count = 4096 - stream.avail_out;
        if (count && (!read_exact(executable, buf + 8192, count, &exe_pos, size) ||
                      memcmp(buf + 4096, buf + 8192, count)))
            break;
        if (ret == Z_STREAM_END) {
            matched = exe_pos == size && stream.total_in == compressed_size;
            break;
        }
        if (ret != Z_OK || (!count && stream.total_in == old_in))
            break;
    }

    zlib_inflateEnd(&stream);
free_workspace:
    vfree(stream.workspace);
out:
    kfree(buf);
    return matched;
}

static int native_payload_uapi(struct file *fp, loff_t start, u32 compressed_size, u32 size, u16 compression)
{
    void *data, *compressed = NULL;
    loff_t pos = start, file_size = i_size_read(file_inode(fp));
    int ret = -ENODATA;

    /* JNI metadata is small; never allocate for an entire daemon or a ZIP bomb. */
    if (!size || size > 2 * 1024 * 1024 || compressed_size > 2 * 1024 * 1024 + 65536 ||
        start < 0 || start > file_size || compressed_size > file_size - start)
        return ret;
    data = kvmalloc(size, GFP_KERNEL);
    if (!data)
        return -ENOMEM;
    if (!compression) {
        if (!read_exact(fp, data, size, &pos, file_size))
            goto out;
    } else {
        compressed = kvmalloc(compressed_size, GFP_KERNEL);
        if (!compressed || !read_exact(fp, compressed, compressed_size, &pos, file_size) ||
            zlib_inflate_blob(data, size, compressed, compressed_size) != size)
            goto out;
    }
    ret = ksu_apk_native_uapi_version(data, size);
out:
    kvfree(compressed);
    kvfree(data);
    return ret;
}

/* Match signed payloads or read only their named native ABI getter. */
static bool scan_apk_native_payloads(const char *path, struct file *executable, u32 *uapi_version)
{
    static const char jni_prefix[] = "lib/arm64-v8a/";
    struct zip_central_header central;
    struct zip_entry_header local;
    struct file *fp;
    loff_t pos, end, file_size;
    bool matched = false;
    char name[128], local_name[128];

    fp = ksu_filp_open_nonotify(path, O_RDONLY | O_NOFOLLOW);
    if (IS_ERR(fp))
        return false;

    file_size = i_size_read(file_inode(fp));
    if (!get_zip_central_directory(fp, file_size, &pos, &end))
        goto close_apk;

    while (pos < end) {
        loff_t next, local_pos;
        u16 name_len, compression;
        u32 size, compressed_size;

        if (!read_exact(fp, &central, sizeof(central), &pos, end) ||
            le32_to_cpu(central.signature) != 0x02014b50)
            break;
        name_len = le16_to_cpu(central.file_name_length);
        next = pos + name_len + le16_to_cpu(central.extra_field_length) + le16_to_cpu(central.comment_length);
        if (next > end)
            break;
        size = le32_to_cpu(central.uncompressed_size);
        if (name_len <= sizeof(jni_prefix) - 1 + 3 || name_len >= sizeof(name) ||
            (executable && size != i_size_read(file_inode(executable))) ||
            !read_exact(fp, name, name_len, &pos, end) ||
            memcmp(name, jni_prefix, sizeof(jni_prefix) - 1) || memcmp(name + name_len - 3, ".so", 3)) {
            pos = next;
            continue;
        }

        compression = le16_to_cpu(central.compression);
        compressed_size = le32_to_cpu(central.compressed_size);
        if ((compression != 0 && compression != 8) || (le16_to_cpu(central.flags) & 1) ||
            (compression == 0 && compressed_size != size))
            break;
        local_pos = le32_to_cpu(central.local_offset);
        if (!read_exact(fp, &local, sizeof(local), &local_pos, file_size) || local.signature != 0x04034b50 ||
            local.compression != compression || local.file_name_length != name_len || (local.flags & 1) ||
            !read_exact(fp, local_name, name_len, &local_pos, file_size) || memcmp(name, local_name, name_len))
            break;
        local_pos += local.extra_field_length;
        if (!executable) {
            int uapi = native_payload_uapi(fp, local_pos, compressed_size, size, compression);

            if (uapi >= 3 && uapi <= 6) {
                if (*uapi_version && *uapi_version != uapi) {
                    *uapi_version = 0;
                    break;
                }
                *uapi_version = uapi;
            } else if (uapi == -EPROTO) {
                *uapi_version = 0;
                break;
            }
            pos = next;
            continue;
        }
        if (compression == 8)
            matched = executable_matches_deflated_range(fp, local_pos, compressed_size, size, executable);
        else
            matched = executable_matches_range(fp, local_pos, size, executable);
        if (matched)
            break;
        pos = next;
    }
close_apk:
    filp_close(fp, NULL);
    return matched;
}

bool ksu_manager_apk_matches_executable(const char *path, struct file *executable)
{
    return executable && scan_apk_native_payloads(path, executable, NULL);
}

// This is a necessary but not sufficient condition, but it is enough for us
static bool has_v1_signature_file(struct file *fp)
{
    struct zip_entry_header header;
    const char MANIFEST[] = "META-INF/MANIFEST.MF";

    loff_t pos = 0;

    while (ksu_kernel_read_compat(fp, &header, sizeof(struct zip_entry_header), &pos) ==
           sizeof(struct zip_entry_header)) {
        if (header.signature != 0x04034b50) {
            // ZIP magic: 'PK'
            return false;
        }
        // Read the entry file name
        if (header.file_name_length == sizeof(MANIFEST) - 1) {
            char fileName[sizeof(MANIFEST)];
            ksu_kernel_read_compat(fp, fileName, header.file_name_length, &pos);
            fileName[header.file_name_length] = '\0';

            // Check if the entry matches META-INF/MANIFEST.MF
            if (strncmp(MANIFEST, fileName, sizeof(MANIFEST) - 1) == 0) {
                return true;
            }
        } else {
            // Skip the entry file name
            pos += header.file_name_length;
        }

        // Skip to the next entry
        pos += header.extra_field_length + header.compressed_size;
    }

    return false;
}

static __always_inline bool check_v2_signature(char *path, struct ksu_manager_apk_info *info)
{
    unsigned char buffer[0x10] = { 0 };
    u64 size_of_block, size_of_block_at_head;

    loff_t pos, pairs_end, file_size, cd_offset, cd_end;

    bool v2_signing_valid = false;
    int v2_signing_blocks = 0;
    u8 matched_index = -1;
    struct file *fp = ksu_filp_open_nonotify(path, O_RDONLY | O_NOATIME);
    if (IS_ERR(fp)) {
        pr_err("open %s error.\n", path);
        return false;
    }

    file_size = generic_file_llseek(fp, 0, SEEK_END);
    if (file_size < 0)
        goto clean;

    if (!get_zip_central_directory(fp, file_size, &cd_offset, &cd_end))
        goto clean;
    if (cd_offset < 0x20)
        goto clean;

    pairs_end = (loff_t)cd_offset - 0x18;
    pos = pairs_end;

    if (!read_exact(fp, &size_of_block, sizeof(size_of_block), &pos, cd_offset))
        goto clean;
    if (!read_exact(fp, buffer, sizeof(buffer), &pos, cd_offset))
        goto clean;
    if (memcmp((char *)buffer, "APK Sig Block 42", sizeof(buffer)))
        goto clean;

    if (size_of_block < 0x18 || size_of_block > INT_MAX - 0x8 || size_of_block > (u64)cd_offset - 0x8)
        goto clean;

    pos = (loff_t)cd_offset - (loff_t)size_of_block - 0x8;
    if (!read_exact(fp, &size_of_block_at_head, sizeof(size_of_block_at_head), &pos, pairs_end))
        goto clean;
    if (size_of_block_at_head != size_of_block)
        goto clean;

    // Scan every length-prefixed pair, matching AOSP's signing block parser
    // Each valid pair consumes an 8-byte length plus at least a 4-byte ID, so
    // malformed entries fail below instead of spinning in place.
    while (pos < pairs_end) {
        uint32_t id;
        u64 size_of_pair;
        loff_t pair_end;

        if (!read_exact(fp, &size_of_pair, sizeof(size_of_pair), &pos, pairs_end))
            goto invalid;
        if (size_of_pair < sizeof(id) || size_of_pair > INT_MAX || size_of_pair > (u64)(pairs_end - pos))
            goto invalid;

        pair_end = pos + (loff_t)size_of_pair;
        if (!read_exact(fp, &id, sizeof(id), &pos, pair_end))
            goto invalid;

        if (id == 0x7109871au) {
            v2_signing_blocks++;
            v2_signing_valid = check_block(fp, &pos, pair_end, &matched_index, info);
        } else if (id != 0x42726577u) { // APK verity padding
            // https://cs.android.com/android/platform/superproject/+/android-latest-release:tools/apksig/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java;l=102;drc=ebe4dfd4fd6550c949a6c7c2427484bf5e96500b
#ifdef CONFIG_KSU_DEBUG
            pr_info("Unexpected signature block id: 0x%08x\n", id);
#endif
            goto invalid;
        }
        pos = pair_end;
    }

    if (v2_signing_blocks != 1) {
#ifdef CONFIG_KSU_DEBUG
        pr_err("Unexpected v2 signature count: %d\n", v2_signing_blocks);
#endif
        v2_signing_valid = false;
    }

    if (v2_signing_valid) {
        int has_v1_signing = has_v1_signature_file(fp);
        if (has_v1_signing) {
            pr_err("Unexpected v1 signature scheme found!\n");
            goto invalid;
        }
    }
    goto clean;

invalid:
    v2_signing_valid = false;
clean:
    filp_close(fp, 0);

    if (v2_signing_valid) {
        info->signature_index = matched_index;

        return true;
    }
    return false;
}

#ifdef CONFIG_KSU_DEBUG
int ksu_debug_manager_appid = -1;

static int set_expected_size(const char *val, const struct kernel_param *kp)
{
    int rv = param_set_uint(val, kp);
    ksu_unregister_manager_by_signature_index(KSU_SIGNATURE_INDEX_KSU_DEBUG);
    ksu_register_manager(ksu_debug_manager_appid, KSU_SIGNATURE_INDEX_KSU_DEBUG);
    pr_info("ksu_manager_appid set to %d\n", ksu_debug_manager_appid);
    return rv;
}

static struct kernel_param_ops expected_size_ops = {
    .set = set_expected_size,
    .get = param_get_uint,
};

module_param_cb(ksu_debug_manager_appid, &expected_size_ops, &ksu_debug_manager_appid, S_IRUSR | S_IWUSR);

#endif

int get_pkg_from_apk_path(char *pkg, const char *path)
{
    int len = strlen(path);
    if (len >= KSU_MAX_PACKAGE_NAME || len < 1)
        return -1;

    const char *last_slash = NULL;
    const char *second_last_slash = NULL;

    int i;
    for (i = len - 1; i >= 0; i--) {
        if (path[i] == '/') {
            if (!last_slash) {
                last_slash = &path[i];
            } else {
                second_last_slash = &path[i];
                break;
            }
        }
    }

    if (!last_slash || !second_last_slash)
        return -1;

    const char *last_hyphen = strchr(second_last_slash, '-');
    if (!last_hyphen || last_hyphen > last_slash)
        return -1;

    int pkg_len = last_hyphen - second_last_slash - 1;
    if (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)
        return -1;

    // Copying the package name
    strncpy(pkg, second_last_slash + 1, pkg_len);
    pkg[pkg_len] = '\0';

    return 0;
}

bool ksu_get_manager_apk_info(char *path, struct ksu_manager_apk_info *info)
{
    memset(info, 0, sizeof(*info));
#ifdef KSU_MANAGER_PACKAGE
    char pkg[KSU_MAX_PACKAGE_NAME];
    if (get_pkg_from_apk_path(pkg, path) < 0) {
        pr_err("Failed to get package name from apk path: %s\n", path);
        return false;
    }

    // pkg is `<real package>`
    if (strncmp(pkg, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE))) {
        return false;
    }
#endif
    if (!check_v2_signature(path, info))
        return false;
    scan_apk_native_payloads(path, NULL, &info->uapi_version);
    return true;
}

bool is_manager_apk(char *path, u8 *signature_index)
{
    struct ksu_manager_apk_info info;
    bool matched = ksu_get_manager_apk_info(path, &info);

    if (matched && signature_index)
        *signature_index = info.signature_index;
    return matched;
}
