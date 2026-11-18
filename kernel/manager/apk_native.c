// SPDX-License-Identifier: GPL-2.0-only
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/overflow.h>
#include <linux/string.h>
#include <asm/byteorder.h>

#include "apk_native.h"

#define KSU_NATIVE_MAX_LOADS 16
#define KSU_NATIVE_FUNC_BYTES 64
#define KSU_NATIVE_NAME_BYTES 512
#define KSU_NATIVE_BRANCHES 2

struct ksu_native_load {
    u64 address;
    u64 offset;
    u64 filesz;
    u64 memsz;
    u32 flags;
};

struct ksu_native_elf {
    const u8 *data;
    size_t size;
    u64 shoff;
    u16 shnum;
    unsigned int load_count;
    struct ksu_native_load loads[KSU_NATIVE_MAX_LOADS];
};

static bool ksu_native_range(const struct ksu_native_elf *elf, u64 offset, u64 length)
{
    u64 end;

    return !check_add_overflow(offset, length, &end) && end <= elf->size;
}

static bool ksu_native_table(const struct ksu_native_elf *elf, u64 offset, u64 count, u64 stride)
{
    u64 length;

    return !check_mul_overflow(count, stride, &length) && ksu_native_range(elf, offset, length);
}

static void ksu_native_section(const struct ksu_native_elf *elf, unsigned int index, Elf64_Shdr *section)
{
    /* The complete table extent is checked before any indexed read. */
    memcpy(section, elf->data + elf->shoff + (u64)index * sizeof(*section), sizeof(*section));
    section->sh_name = le32_to_cpu(section->sh_name);
    section->sh_type = le32_to_cpu(section->sh_type);
    section->sh_flags = le64_to_cpu(section->sh_flags);
    section->sh_addr = le64_to_cpu(section->sh_addr);
    section->sh_offset = le64_to_cpu(section->sh_offset);
    section->sh_size = le64_to_cpu(section->sh_size);
    section->sh_link = le32_to_cpu(section->sh_link);
    section->sh_info = le32_to_cpu(section->sh_info);
    section->sh_addralign = le64_to_cpu(section->sh_addralign);
    section->sh_entsize = le64_to_cpu(section->sh_entsize);
}

static int ksu_native_validate(struct ksu_native_elf *elf)
{
    Elf64_Ehdr header;
    Elf64_Shdr section, names;
    unsigned int i, j;
    u64 end;

    if (!elf->data)
        return -EINVAL;
    if (elf->size < sizeof(header))
        return -EBADMSG;
    memcpy(&header, elf->data, sizeof(header));
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB)
        return -EOPNOTSUPP;
    if (header.e_ident[EI_VERSION] != EV_CURRENT || le32_to_cpu(header.e_version) != EV_CURRENT)
        return -EBADMSG;
    if (le16_to_cpu(header.e_machine) != EM_AARCH64 ||
        (le16_to_cpu(header.e_type) != ET_DYN && le16_to_cpu(header.e_type) != ET_EXEC))
        return -EOPNOTSUPP;

    header.e_ehsize = le16_to_cpu(header.e_ehsize);
    header.e_phoff = le64_to_cpu(header.e_phoff);
    header.e_phentsize = le16_to_cpu(header.e_phentsize);
    header.e_phnum = le16_to_cpu(header.e_phnum);
    header.e_shoff = le64_to_cpu(header.e_shoff);
    header.e_shentsize = le16_to_cpu(header.e_shentsize);
    header.e_shnum = le16_to_cpu(header.e_shnum);
    header.e_shstrndx = le16_to_cpu(header.e_shstrndx);
    if (header.e_ehsize != sizeof(header))
        return -EBADMSG;
    /* SHN_HIRESERVE is SHN_XINDEX; this kernel's ELF header does not name it. */
    if (header.e_phnum == PN_XNUM || header.e_shnum >= SHN_LORESERVE || header.e_shstrndx == SHN_HIRESERVE ||
        (!header.e_shnum && header.e_shoff))
        return -EOPNOTSUPP;
    if (header.e_phnum) {
        if (header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phoff < sizeof(header) ||
            !ksu_native_table(elf, header.e_phoff, header.e_phnum, header.e_phentsize))
            return -EBADMSG;
    } else if (header.e_phoff || (header.e_phentsize && header.e_phentsize != sizeof(Elf64_Phdr))) {
        return -EBADMSG;
    }
    if (header.e_shnum) {
        if (header.e_shentsize != sizeof(Elf64_Shdr) || header.e_shoff < sizeof(header) ||
            header.e_shstrndx >= header.e_shnum ||
            !ksu_native_table(elf, header.e_shoff, header.e_shnum, header.e_shentsize))
            return -EBADMSG;
    } else if (header.e_shstrndx || (header.e_shentsize && header.e_shentsize != sizeof(Elf64_Shdr))) {
        return -EBADMSG;
    }
    elf->shoff = header.e_shoff;
    elf->shnum = header.e_shnum;

    for (i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr program;
        struct ksu_native_load *load;

        memcpy(&program, elf->data + header.e_phoff + (u64)i * sizeof(program), sizeof(program));
        program.p_type = le32_to_cpu(program.p_type);
        program.p_flags = le32_to_cpu(program.p_flags);
        program.p_offset = le64_to_cpu(program.p_offset);
        program.p_vaddr = le64_to_cpu(program.p_vaddr);
        program.p_filesz = le64_to_cpu(program.p_filesz);
        program.p_memsz = le64_to_cpu(program.p_memsz);
        program.p_align = le64_to_cpu(program.p_align);
        if (!ksu_native_range(elf, program.p_offset, program.p_filesz) ||
            check_add_overflow(program.p_vaddr, program.p_memsz, &end))
            return -EBADMSG;
        if (program.p_type != PT_LOAD)
            continue;
        if (program.p_filesz > program.p_memsz ||
            (program.p_align > 1 && ((program.p_align & (program.p_align - 1)) ||
                                     ((program.p_vaddr ^ program.p_offset) & (program.p_align - 1)))))
            return -EBADMSG;
        if (elf->load_count == KSU_NATIVE_MAX_LOADS)
            return -E2BIG;
        for (j = 0; j < elf->load_count; j++) {
            load = &elf->loads[j];
            if (program.p_memsz && load->memsz && program.p_vaddr < load->address + load->memsz && load->address < end)
                return -EBADMSG;
        }
        load = &elf->loads[elf->load_count++];
        load->address = program.p_vaddr;
        load->offset = program.p_offset;
        load->filesz = program.p_filesz;
        load->memsz = program.p_memsz;
        load->flags = program.p_flags;
    }

    for (i = 0; i < elf->shnum; i++) {
        ksu_native_section(elf, i, &section);
        if (!i && (section.sh_type != SHT_NULL || section.sh_size || section.sh_link || section.sh_info))
            return -EBADMSG;
        if ((section.sh_type != SHT_NOBITS && !ksu_native_range(elf, section.sh_offset, section.sh_size)) ||
            check_add_overflow(section.sh_addr, section.sh_size, &end) ||
            (section.sh_addralign > 1 && (section.sh_addralign & (section.sh_addralign - 1))) ||
            (section.sh_entsize && section.sh_size % section.sh_entsize))
            return -EBADMSG;
        if (section.sh_type == SHT_STRTAB &&
            (!section.sh_size || elf->data[section.sh_offset] || elf->data[section.sh_offset + section.sh_size - 1]))
            return -EBADMSG;
        if ((section.sh_type == SHT_DYNSYM || section.sh_type == SHT_SYMTAB) &&
            (section.sh_entsize != sizeof(Elf64_Sym) || section.sh_link >= elf->shnum ||
             section.sh_info > section.sh_size / sizeof(Elf64_Sym)))
            return -EBADMSG;
    }
    if (header.e_shstrndx) {
        ksu_native_section(elf, header.e_shstrndx, &names);
        if (names.sh_type != SHT_STRTAB)
            return -EBADMSG;
        for (i = 0; i < elf->shnum; i++) {
            ksu_native_section(elf, i, &section);
            if (section.sh_name >= names.sh_size)
                return -EBADMSG;
        }
    }
    return 0;
}

static int ksu_native_map(const struct ksu_native_elf *elf, u64 address, u64 length, u64 *offset, u64 *remaining)
{
    unsigned int i;

    for (i = 0; i < elf->load_count; i++) {
        const struct ksu_native_load *load = &elf->loads[i];
        u64 delta;

        if (address < load->address)
            continue;
        delta = address - load->address;
        if (delta >= load->filesz || length > load->filesz - delta)
            continue;
        if (!(load->flags & PF_X))
            return -EOPNOTSUPP;
        if (check_add_overflow(load->offset, delta, offset) || !ksu_native_range(elf, *offset, length))
            return -EBADMSG;
        *remaining = load->filesz - delta;
        return 0;
    }
    return -EBADMSG;
}

static unsigned int ksu_native_getter(const char *name, size_t length)
{
    static const char suffix[] = "_Natives_getManagerUAPIVersion";
    size_t i, prefix_length;

    /* C helper and the verified no-argument C++ encoding used by Official/Next. */
    if (!strcmp(name, "get_manager_uapi_version") || !strcmp(name, "_Z24get_manager_uapi_versionv"))
        return 1;
    if (length <= 5 + sizeof(suffix) - 1 || memcmp(name, "Java_", 5) ||
        memcmp(name + length - (sizeof(suffix) - 1), suffix, sizeof(suffix) - 1))
        return 0;
    prefix_length = length - (sizeof(suffix) - 1);
    /* Package hiding may change only this JNI-encoded prefix, never the method. */
    for (i = 5; i < prefix_length; i++) {
        unsigned char c = name[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
            return 0;
    }
    return 2;
}

static int ksu_native_constant(const struct ksu_native_elf *elf, const Elf64_Sym *symbol)
{
    Elf64_Shdr section;
    u64 address = symbol->st_value, offset, remaining, section_offset;
    unsigned int limit, position = 0, hops = 0, value = 0, pac = 0;
    int ret;

    if (symbol->st_shndx >= SHN_LORESERVE || !symbol->st_size || symbol->st_size > KSU_NATIVE_FUNC_BYTES)
        return -EOPNOTSUPP;
    if ((address & 3) || (symbol->st_size & 3))
        return -EBADMSG;
    ksu_native_section(elf, symbol->st_shndx, &section);
    if (section.sh_type != SHT_PROGBITS || !(section.sh_flags & SHF_ALLOC) || !(section.sh_flags & SHF_EXECINSTR))
        return -EOPNOTSUPP;
    if (address < section.sh_addr || address - section.sh_addr > section.sh_size ||
        symbol->st_size > section.sh_size - (address - section.sh_addr) ||
        check_add_overflow(section.sh_offset, address - section.sh_addr, &section_offset))
        return -EBADMSG;
    ret = ksu_native_map(elf, address, symbol->st_size, &offset, &remaining);
    if (ret)
        return ret;
    if ((offset & 3) || offset != section_offset)
        return -EBADMSG;
    limit = symbol->st_size;

    /* Start only at the semantic symbol (or its direct B target), never scan for a MOV/RET pair. */
    while (position < limit) {
        u32 instruction;

        memcpy(&instruction, elf->data + offset + position, sizeof(instruction));
        instruction = le32_to_cpu(instruction);
        switch (instruction) {
        case 0xd503201f: /* NOP */
        case 0xd503241f: /* BTI */
        case 0xd503245f: /* BTI c */
        case 0xd503249f: /* BTI j */
        case 0xd50324df: /* BTI jc */
            break;
        case 0xd503233f: /* PACIASP */
        case 0xd503237f: /* PACIBSP */
            if (pac || value)
                return -EOPNOTSUPP;
            pac = instruction == 0xd503233f ? 1 : 2;
            break;
        case 0xd50323bf: /* AUTIASP */
        case 0xd50323ff: /* AUTIBSP */
            if (pac != (instruction == 0xd50323bf ? 1 : 2))
                return -EOPNOTSUPP;
            pac = 0;
            break;
        default:
            /* MOVZ w0/x0, imm16, LSL #0; no other register writes or constant synthesis. */
            if ((instruction & 0x7fe0001f) == 0x52800000) {
                if (value)
                    return -EOPNOTSUPP;
                value = (instruction >> 5) & 0xffff;
                if (value < 3 || value > 6)
                    return -EPROTO;
            } else if (instruction == 0xd65f03c0) { /* RET x30 */
                return value && !pac ? (int)value : -EOPNOTSUPP;
            } else if ((instruction & 0xfc000000) == 0x14000000) { /* B, not BL/BR/PLT */
                s64 delta = (s64)(instruction & 0x03ffffff);
                u64 pc, target;

                if (value || pac || hops == KSU_NATIVE_BRANCHES)
                    return -EOPNOTSUPP;
                if (instruction & 0x02000000)
                    delta -= 0x04000000;
                delta *= 4;
                if (check_add_overflow(address, (u64)position, &pc))
                    return -EBADMSG;
                if (delta < 0) {
                    if (pc < (u64)-delta)
                        return -EBADMSG;
                    target = pc - (u64)-delta;
                } else if (check_add_overflow(pc, (u64)delta, &target)) {
                    return -EBADMSG;
                }
                ret = ksu_native_map(elf, target, sizeof(instruction), &offset, &remaining);
                if (ret)
                    return ret;
                if ((target & 3) || (offset & 3))
                    return -EBADMSG;
                address = target;
                limit = remaining < KSU_NATIVE_FUNC_BYTES ? remaining : KSU_NATIVE_FUNC_BYTES;
                limit &= ~3U;
                position = 0;
                hops++;
                continue;
            } else {
                return -EOPNOTSUPP;
            }
        }
        position += sizeof(instruction);
    }
    return -EOPNOTSUPP;
}

int ksu_apk_native_uapi_version(const void *data, size_t size)
{
    struct ksu_native_elf elf = { .data = data, .size = size };
    bool helper_seen = false, helper_unsupported = false, jni_unsupported = false;
    u64 symbol_budget = size / sizeof(Elf64_Sym);
    unsigned int i;
    int version = 0, ret;

    ret = ksu_native_validate(&elf);
    if (ret)
        return ret;
    for (i = 0; i < elf.shnum; i++) {
        Elf64_Shdr symbols, strings;
        u64 index, count;

        ksu_native_section(&elf, i, &symbols);
        if (symbols.sh_type != SHT_DYNSYM && symbols.sh_type != SHT_SYMTAB)
            continue;
        ksu_native_section(&elf, symbols.sh_link, &strings);
        if (strings.sh_type != SHT_STRTAB)
            return -EBADMSG;
        count = symbols.sh_size / sizeof(Elf64_Sym);
        /* Aliased/repeated symbol tables cannot multiply work beyond the blob's byte budget. */
        if (count > symbol_budget)
            return -E2BIG;
        symbol_budget -= count;
        for (index = 0; index < count; index++) {
            Elf64_Sym symbol;
            const char *name, *nul;
            size_t name_limit;
            unsigned int getter;

            memcpy(&symbol, elf.data + symbols.sh_offset + index * sizeof(symbol), sizeof(symbol));
            symbol.st_name = le32_to_cpu(symbol.st_name);
            symbol.st_shndx = le16_to_cpu(symbol.st_shndx);
            symbol.st_value = le64_to_cpu(symbol.st_value);
            symbol.st_size = le64_to_cpu(symbol.st_size);
            if (symbol.st_shndx == SHN_HIRESERVE)
                return -EOPNOTSUPP;
            if (symbol.st_name >= strings.sh_size || (symbol.st_shndx < SHN_LORESERVE && symbol.st_shndx >= elf.shnum))
                return -EBADMSG;
            if (ELF64_ST_TYPE(symbol.st_info) != STT_FUNC || symbol.st_shndx == SHN_UNDEF)
                continue;
            name = (const char *)elf.data + strings.sh_offset + symbol.st_name;
            name_limit = strings.sh_size - symbol.st_name;
            if (name_limit > KSU_NATIVE_NAME_BYTES)
                name_limit = KSU_NATIVE_NAME_BYTES;
            /* STRTAB's final NUL guarantees termination; overlong unrelated names need no scan. */
            nul = memchr(name, '\0', name_limit);
            if (!nul)
                continue;
            getter = ksu_native_getter(name, nul - name);
            if (!getter)
                continue;
            if (getter == 1)
                helper_seen = true;
            ret = ksu_native_constant(&elf, &symbol);
            if (ret == -EOPNOTSUPP) {
                if (getter == 1)
                    helper_unsupported = true;
                else
                    jni_unsupported = true;
                continue;
            }
            if (ret < 0)
                return ret;
            if (version && version != ret)
                return -EPROTO;
            version = ret;
        }
    }
    /* A visible helper is authoritative; opaque JNI alone is never treated as constant metadata. */
    if (helper_seen)
        return helper_unsupported ? -EOPNOTSUPP : version;
    if (jni_unsupported)
        return -EOPNOTSUPP;
    return version ? version : -ENOENT;
}
