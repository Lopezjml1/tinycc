//! ELF (Executable and Linkable Format) binary format definitions.
//!
//! This module provides Rust struct definitions and constants translated from
//! the original `TinyCC` `elf.h` header (3,324 lines). All structs use `#[repr(C)]`
//! for binary compatibility with the ELF specification.
//!
//! C equivalent: `elf.h`

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]

// ELF format definitions — struct field prefixes (e_*, sh_*, st_*, p_*, etc.)
// preserve the ELF specification naming convention from elf.h for traceability.
#![allow(clippy::struct_field_names)]

// ---------------------------------------------------------------------------
// ELF Type Aliases (elf.h lines 27-70)
// ---------------------------------------------------------------------------

/// 32-bit ELF unsigned half-word
pub type Elf32Half = u16;
/// 32-bit ELF unsigned word
pub type Elf32Word = u32;
/// 32-bit ELF signed word
pub type Elf32Sword = i32;
/// 32-bit ELF unsigned extended word
pub type Elf32Xword = u64;
/// 32-bit ELF signed extended word
pub type Elf32Sxword = i64;
/// 32-bit ELF address
pub type Elf32Addr = u32;
/// 32-bit ELF file offset
pub type Elf32Off = u32;
/// 32-bit ELF section index
pub type Elf32Section = u16;
/// 32-bit ELF version symbol
pub type Elf32Versym = Elf32Half;

/// 64-bit ELF unsigned half-word
pub type Elf64Half = u16;
/// 64-bit ELF unsigned word
pub type Elf64Word = u32;
/// 64-bit ELF signed word
pub type Elf64Sword = i32;
/// 64-bit ELF unsigned extended word
pub type Elf64Xword = u64;
/// 64-bit ELF signed extended word
pub type Elf64Sxword = i64;
/// 64-bit ELF address
pub type Elf64Addr = u64;
/// 64-bit ELF file offset
pub type Elf64Off = u64;
/// 64-bit ELF section index
pub type Elf64Section = u16;
/// 64-bit ELF version symbol
pub type Elf64Versym = Elf64Half;

// ---------------------------------------------------------------------------
// ELF Identification Constants (elf.h lines 117-173)
// ---------------------------------------------------------------------------

/// Number of bytes in `e_ident`[]
pub const EI_NIDENT: usize = 16;
/// File identification byte 0 index
pub const EI_MAG0: usize = 0;
/// File identification byte 1 index
pub const EI_MAG1: usize = 1;
/// File identification byte 2 index
pub const EI_MAG2: usize = 2;
/// File identification byte 3 index
pub const EI_MAG3: usize = 3;
/// Magic number byte 0
pub const ELFMAG0: u8 = 0x7f;
/// Magic number byte 1
pub const ELFMAG1: u8 = b'E';
/// Magic number byte 2
pub const ELFMAG2: u8 = b'L';
/// Magic number byte 3
pub const ELFMAG3: u8 = b'F';
/// File class byte index
pub const EI_CLASS: usize = 4;
/// Invalid class
pub const ELFCLASSNONE: u8 = 0;
/// 32-bit objects
pub const ELFCLASS32: u8 = 1;
/// 64-bit objects
pub const ELFCLASS64: u8 = 2;
/// ELF class number
pub const ELFCLASSNUM: u8 = 3;
/// Data encoding byte index
pub const EI_DATA: usize = 5;
/// Invalid data encoding
pub const ELFDATANONE: u8 = 0;
/// 2's complement, little endian
pub const ELFDATA2LSB: u8 = 1;
/// 2's complement, big endian
pub const ELFDATA2MSB: u8 = 2;
/// ELF data encoding number
pub const ELFDATANUM: u8 = 3;
/// File version byte index
pub const EI_VERSION: usize = 6;
/// OS/ABI identification byte index
pub const EI_OSABI: usize = 7;
/// UNIX System V ABI
pub const ELFOSABI_NONE: u8 = 0;
/// Alias for `ELFOSABI_NONE`
pub const ELFOSABI_SYSV: u8 = 0;
/// HP-UX
pub const ELFOSABI_HPUX: u8 = 1;
/// NetBSD
pub const ELFOSABI_NETBSD: u8 = 2;
/// GNU ELF extensions
pub const ELFOSABI_GNU: u8 = 3;
/// Alias: Linux
pub const ELFOSABI_LINUX: u8 = 3;
/// Sun Solaris
pub const ELFOSABI_SOLARIS: u8 = 6;
/// IBM AIX
pub const ELFOSABI_AIX: u8 = 7;
/// SGI Irix
pub const ELFOSABI_IRIX: u8 = 8;
/// FreeBSD
pub const ELFOSABI_FREEBSD: u8 = 9;
/// Compaq TRU64 UNIX
pub const ELFOSABI_TRU64: u8 = 10;
/// Novell Modesto
pub const ELFOSABI_MODESTO: u8 = 11;
/// OpenBSD
pub const ELFOSABI_OPENBSD: u8 = 12;
/// ARM EABI
pub const ELFOSABI_ARM_AEABI: u8 = 64;
/// ARM
pub const ELFOSABI_ARM: u8 = 97;
/// Standalone (embedded) application
pub const ELFOSABI_STANDALONE: u8 = 255;
/// ABI version byte index
pub const EI_ABIVERSION: usize = 8;
/// Byte index of padding bytes
pub const EI_PAD: usize = 9;

// ---------------------------------------------------------------------------
// Object File Types — e_type (elf.h lines 177-186)
// ---------------------------------------------------------------------------

/// No file type
pub const ET_NONE: u16 = 0;
/// Relocatable file
pub const ET_REL: u16 = 1;
/// Executable file
pub const ET_EXEC: u16 = 2;
/// Shared object file
pub const ET_DYN: u16 = 3;
/// Core file
pub const ET_CORE: u16 = 4;
/// Number of defined types
pub const ET_NUM: u16 = 5;
/// OS-specific range start
pub const ET_LOOS: u16 = 0xfe00;
/// OS-specific range end
pub const ET_HIOS: u16 = 0xfeff;
/// Processor-specific range start
pub const ET_LOPROC: u16 = 0xff00;
/// Processor-specific range end
pub const ET_HIPROC: u16 = 0xffff;

// ---------------------------------------------------------------------------
// ELF Version (elf.h lines 276-278)
// ---------------------------------------------------------------------------

/// Invalid ELF version
pub const EV_NONE: u32 = 0;
/// Current version
pub const EV_CURRENT: u32 = 1;
/// ELF version number
pub const EV_NUM: u32 = 2;

// ---------------------------------------------------------------------------
// Machine Types — e_machine (elf.h lines 190-275)
// ---------------------------------------------------------------------------

pub const EM_NONE: u16 = 0;
pub const EM_M32: u16 = 1;
pub const EM_SPARC: u16 = 2;
pub const EM_386: u16 = 3;
pub const EM_68K: u16 = 4;
pub const EM_88K: u16 = 5;
pub const EM_IAMCU: u16 = 6;
pub const EM_860: u16 = 7;
pub const EM_MIPS: u16 = 8;
pub const EM_S370: u16 = 9;
pub const EM_MIPS_RS3_LE: u16 = 10;
pub const EM_PARISC: u16 = 15;
pub const EM_VPP500: u16 = 17;
pub const EM_SPARC32PLUS: u16 = 18;
pub const EM_960: u16 = 19;
pub const EM_PPC: u16 = 20;
pub const EM_PPC64: u16 = 21;
pub const EM_S390: u16 = 22;
pub const EM_SPU: u16 = 23;
pub const EM_V800: u16 = 36;
pub const EM_FR20: u16 = 37;
pub const EM_RH32: u16 = 38;
pub const EM_RCE: u16 = 39;
pub const EM_ARM: u16 = 40;
pub const EM_FAKE_ALPHA: u16 = 41;
pub const EM_SH: u16 = 42;
pub const EM_SPARCV9: u16 = 43;
pub const EM_TRICORE: u16 = 44;
pub const EM_ARC: u16 = 45;
pub const EM_H8_300: u16 = 46;
pub const EM_H8_300H: u16 = 47;
pub const EM_H8S: u16 = 48;
pub const EM_H8_500: u16 = 49;
pub const EM_IA_64: u16 = 50;
pub const EM_MIPS_X: u16 = 51;
pub const EM_COLDFIRE: u16 = 52;
pub const EM_68HC12: u16 = 53;
pub const EM_MMA: u16 = 54;
pub const EM_PCP: u16 = 55;
pub const EM_NCPU: u16 = 56;
pub const EM_NDR1: u16 = 57;
pub const EM_STARCORE: u16 = 58;
pub const EM_ME16: u16 = 59;
pub const EM_ST100: u16 = 60;
pub const EM_TINYJ: u16 = 61;
pub const EM_X86_64: u16 = 62;
pub const EM_PDSP: u16 = 63;
pub const EM_PDP10: u16 = 64;
pub const EM_PDP11: u16 = 65;
pub const EM_FX66: u16 = 66;
pub const EM_ST9PLUS: u16 = 67;
pub const EM_ST7: u16 = 68;
pub const EM_68HC16: u16 = 69;
pub const EM_68HC11: u16 = 70;
pub const EM_68HC08: u16 = 71;
pub const EM_68HC05: u16 = 72;
pub const EM_SVX: u16 = 73;
pub const EM_ST19: u16 = 74;
pub const EM_VAX: u16 = 75;
pub const EM_CRIS: u16 = 76;
pub const EM_JAVELIN: u16 = 77;
pub const EM_FIREPATH: u16 = 78;
pub const EM_ZSP: u16 = 79;
pub const EM_MMIX: u16 = 80;
pub const EM_HUANY: u16 = 81;
pub const EM_PRISM: u16 = 82;
pub const EM_AVR: u16 = 83;
pub const EM_FR30: u16 = 84;
pub const EM_D10V: u16 = 85;
pub const EM_D30V: u16 = 86;
pub const EM_V850: u16 = 87;
pub const EM_M32R: u16 = 88;
pub const EM_MN10300: u16 = 89;
pub const EM_MN10200: u16 = 90;
pub const EM_PJ: u16 = 91;
pub const EM_OPENRISC: u16 = 92;
pub const EM_ARC_COMPACT: u16 = 93;
pub const EM_XTENSA: u16 = 94;
pub const EM_VIDEOCORE: u16 = 95;
pub const EM_TMM_GPP: u16 = 96;
pub const EM_NS32K: u16 = 97;
pub const EM_TPC: u16 = 98;
pub const EM_SNP1K: u16 = 99;
pub const EM_ST200: u16 = 100;
pub const EM_IP2K: u16 = 101;
pub const EM_MAX: u16 = 102;
pub const EM_CR: u16 = 103;
pub const EM_F2MC16: u16 = 104;
pub const EM_MSP430: u16 = 105;
pub const EM_BLACKFIN: u16 = 106;
pub const EM_SE_C33: u16 = 107;
pub const EM_SEP: u16 = 108;
pub const EM_ARCA: u16 = 109;
pub const EM_UNICORE: u16 = 110;
pub const EM_EXCESS: u16 = 111;
pub const EM_DXP: u16 = 112;
pub const EM_ALTERA_NIOS2: u16 = 113;
pub const EM_CRX: u16 = 114;
pub const EM_XGATE: u16 = 115;
pub const EM_C166: u16 = 116;
pub const EM_M16C: u16 = 117;
pub const EM_DSPIC30F: u16 = 118;
pub const EM_CE: u16 = 119;
pub const EM_M32C: u16 = 120;
pub const EM_TSK3000: u16 = 131;
pub const EM_RS08: u16 = 132;
pub const EM_SHARC: u16 = 133;
pub const EM_ECOG2: u16 = 134;
pub const EM_SCORE7: u16 = 135;
pub const EM_DSP24: u16 = 136;
pub const EM_VIDEOCORE3: u16 = 137;
pub const EM_LATTICEMICO32: u16 = 138;
pub const EM_SE_C17: u16 = 139;
pub const EM_TI_C6000: u16 = 140;
pub const EM_TI_C2000: u16 = 141;
pub const EM_TI_C5500: u16 = 142;
pub const EM_MMDSP_PLUS: u16 = 160;
pub const EM_CYPRESS_M8C: u16 = 161;
pub const EM_R32C: u16 = 162;
pub const EM_TRIMEDIA: u16 = 163;
pub const EM_QDSP6: u16 = 164;
pub const EM_8051: u16 = 165;
pub const EM_STXP7X: u16 = 166;
pub const EM_NDS32: u16 = 167;
pub const EM_ECOG1X: u16 = 168;
pub const EM_MAXQ30: u16 = 169;
pub const EM_XIMO16: u16 = 170;
pub const EM_MANIK: u16 = 171;
pub const EM_CRAYNV2: u16 = 172;
pub const EM_RX: u16 = 173;
pub const EM_METAG: u16 = 174;
pub const EM_MCST_ELBRUS: u16 = 175;
pub const EM_ECOG16: u16 = 176;
pub const EM_CR16: u16 = 177;
pub const EM_ETPU: u16 = 178;
pub const EM_SLE9X: u16 = 179;
pub const EM_L10M: u16 = 180;
pub const EM_K10M: u16 = 181;
pub const EM_AARCH64: u16 = 183;
pub const EM_AVR32: u16 = 185;
pub const EM_STM8: u16 = 186;
pub const EM_TILE64: u16 = 187;
pub const EM_TILEPRO: u16 = 188;
pub const EM_MICROBLAZE: u16 = 189;
pub const EM_CUDA: u16 = 190;
pub const EM_TILEGX: u16 = 191;
pub const EM_CLOUDSHIELD: u16 = 192;
pub const EM_COREA_1ST: u16 = 193;
pub const EM_COREA_2ND: u16 = 194;
pub const EM_ARC_COMPACT2: u16 = 195;
pub const EM_OPEN8: u16 = 196;
pub const EM_RL78: u16 = 197;
pub const EM_VIDEOCORE5: u16 = 198;
pub const EM_78KOR: u16 = 199;
pub const EM_56800EX: u16 = 200;
pub const EM_RISCV: u16 = 243;
pub const EM_ALPHA: u16 = 0x9026;
pub const EM_C60: u16 = 0x9c60;
pub const EM_NUM: u16 = 192;

// ---------------------------------------------------------------------------
// ELF Header — implemented above in type aliases section
// ELF Section Header Structs (elf.h lines 288-314)
// ---------------------------------------------------------------------------

/// 32-bit ELF file header.
/// C equivalent: `Elf32_Ehdr` (elf.h:77-93)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Ehdr {
    /// Magic number and other info
    pub e_ident: [u8; EI_NIDENT],
    /// Object file type
    pub e_type: Elf32Half,
    /// Architecture
    pub e_machine: Elf32Half,
    /// Object file version
    pub e_version: Elf32Word,
    /// Entry point virtual address
    pub e_entry: Elf32Addr,
    /// Program header table file offset
    pub e_phoff: Elf32Off,
    /// Section header table file offset
    pub e_shoff: Elf32Off,
    /// Processor-specific flags
    pub e_flags: Elf32Word,
    /// ELF header size in bytes
    pub e_ehsize: Elf32Half,
    /// Program header table entry size
    pub e_phentsize: Elf32Half,
    /// Program header table entry count
    pub e_phnum: Elf32Half,
    /// Section header table entry size
    pub e_shentsize: Elf32Half,
    /// Section header table entry count
    pub e_shnum: Elf32Half,
    /// Section header string table index
    pub e_shstrndx: Elf32Half,
}

/// 64-bit ELF file header.
/// C equivalent: `Elf64_Ehdr` (elf.h:95-111)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Ehdr {
    /// Magic number and other info
    pub e_ident: [u8; EI_NIDENT],
    /// Object file type
    pub e_type: Elf64Half,
    /// Architecture
    pub e_machine: Elf64Half,
    /// Object file version
    pub e_version: Elf64Word,
    /// Entry point virtual address
    pub e_entry: Elf64Addr,
    /// Program header table file offset
    pub e_phoff: Elf64Off,
    /// Section header table file offset
    pub e_shoff: Elf64Off,
    /// Processor-specific flags
    pub e_flags: Elf64Word,
    /// ELF header size in bytes
    pub e_ehsize: Elf64Half,
    /// Program header table entry size
    pub e_phentsize: Elf64Half,
    /// Program header table entry count
    pub e_phnum: Elf64Half,
    /// Section header table entry size
    pub e_shentsize: Elf64Half,
    /// Section header table entry count
    pub e_shnum: Elf64Half,
    /// Section header string table index
    pub e_shstrndx: Elf64Half,
}

/// 32-bit ELF section header.
/// C equivalent: `Elf32_Shdr` (elf.h:288-299)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Shdr {
    /// Section name (string tbl index)
    pub sh_name: Elf32Word,
    /// Section type
    pub sh_type: Elf32Word,
    /// Section flags
    pub sh_flags: Elf32Word,
    /// Section virtual addr at execution
    pub sh_addr: Elf32Addr,
    /// Section file offset
    pub sh_offset: Elf32Off,
    /// Section size in bytes
    pub sh_size: Elf32Word,
    /// Link to another section
    pub sh_link: Elf32Word,
    /// Additional section information
    pub sh_info: Elf32Word,
    /// Section alignment
    pub sh_addralign: Elf32Word,
    /// Entry size if section holds table
    pub sh_entsize: Elf32Word,
}

/// 64-bit ELF section header.
/// C equivalent: `Elf64_Shdr` (elf.h:301-314)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Shdr {
    /// Section name (string tbl index)
    pub sh_name: Elf64Word,
    /// Section type
    pub sh_type: Elf64Word,
    /// Section flags
    pub sh_flags: Elf64Xword,
    /// Section virtual addr at execution
    pub sh_addr: Elf64Addr,
    /// Section file offset
    pub sh_offset: Elf64Off,
    /// Section size in bytes
    pub sh_size: Elf64Xword,
    /// Link to another section
    pub sh_link: Elf64Word,
    /// Additional section information
    pub sh_info: Elf64Word,
    /// Section alignment
    pub sh_addralign: Elf64Xword,
    /// Entry size if section holds table
    pub sh_entsize: Elf64Xword,
}

/// 32-bit ELF symbol table entry.
/// C equivalent: `Elf32_Sym` (elf.h:398-405)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Sym {
    /// Symbol name (string tbl index)
    pub st_name: Elf32Word,
    /// Symbol value
    pub st_value: Elf32Addr,
    /// Symbol size
    pub st_size: Elf32Word,
    /// Symbol type and binding
    pub st_info: u8,
    /// Symbol visibility
    pub st_other: u8,
    /// Section index
    pub st_shndx: Elf32Section,
}

/// 64-bit ELF symbol table entry.
/// IMPORTANT: Field order differs from `Elf32_Sym` — `st_info/st_other/st_shndx`
/// come before `st_value/st_size` in the 64-bit variant.
/// C equivalent: `Elf64_Sym` (elf.h:407-416)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Sym {
    /// Symbol name (string tbl index)
    pub st_name: Elf64Word,
    /// Symbol type and binding
    pub st_info: u8,
    /// Symbol visibility
    pub st_other: u8,
    /// Section index
    pub st_shndx: Elf64Section,
    /// Symbol value
    pub st_value: Elf64Addr,
    /// Symbol size
    pub st_size: Elf64Xword,
}

/// 32-bit ELF symbol information entry.
/// C equivalent: `Elf32_Syminfo` (elf.h:421-425)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Syminfo {
    /// Direct bindings, symbol bound to
    pub si_boundto: Elf32Half,
    /// Per symbol flags
    pub si_flags: Elf32Half,
}

/// 64-bit ELF symbol information entry.
/// C equivalent: `Elf64_Syminfo` (elf.h:427-431)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Syminfo {
    /// Direct bindings, symbol bound to
    pub si_boundto: Elf64Half,
    /// Per symbol flags
    pub si_flags: Elf64Half,
}

// ---------------------------------------------------------------------------
// Relocation Structs (elf.h lines 513-554)
// ---------------------------------------------------------------------------

/// 32-bit ELF relocation entry (without addend).
/// C equivalent: `Elf32_Rel` (elf.h:513-517)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Rel {
    /// Address
    pub r_offset: Elf32Addr,
    /// Relocation type and symbol index
    pub r_info: Elf32Word,
}

/// 64-bit ELF relocation entry (without addend).
/// C equivalent: `Elf64_Rel` (elf.h:519-528)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rel {
    /// Address
    pub r_offset: Elf64Addr,
    /// Relocation type and symbol index
    pub r_info: Elf64Xword,
}

/// 32-bit ELF relocation entry (with addend).
/// C equivalent: `Elf32_Rela` (elf.h:532-537)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Rela {
    /// Address
    pub r_offset: Elf32Addr,
    /// Relocation type and symbol index
    pub r_info: Elf32Word,
    /// Addend
    pub r_addend: Elf32Sword,
}

/// 64-bit ELF relocation entry (with addend).
/// C equivalent: `Elf64_Rela` (elf.h:539-544)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rela {
    /// Address
    pub r_offset: Elf64Addr,
    /// Relocation type and symbol index
    pub r_info: Elf64Xword,
    /// Addend
    pub r_addend: Elf64Sxword,
}

// ---------------------------------------------------------------------------
// Program Header Structs (elf.h lines 558-580)
// ---------------------------------------------------------------------------

/// 32-bit ELF program header.
/// C equivalent: `Elf32_Phdr` (elf.h:558-568)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Phdr {
    /// Segment type
    pub p_type: Elf32Word,
    /// Segment file offset
    pub p_offset: Elf32Off,
    /// Segment virtual address
    pub p_vaddr: Elf32Addr,
    /// Segment physical address
    pub p_paddr: Elf32Addr,
    /// Segment size in file
    pub p_filesz: Elf32Word,
    /// Segment size in memory
    pub p_memsz: Elf32Word,
    /// Segment flags
    pub p_flags: Elf32Word,
    /// Segment alignment
    pub p_align: Elf32Word,
}

/// 64-bit ELF program header.
/// IMPORTANT: `p_flags` is in position 2 (after `p_type`), unlike `Elf32_Phdr`
/// where `p_flags` is in position 7.
/// C equivalent: `Elf64_Phdr` (elf.h:570-580)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    /// Segment type
    pub p_type: Elf64Word,
    /// Segment flags
    pub p_flags: Elf64Word,
    /// Segment file offset
    pub p_offset: Elf64Off,
    /// Segment virtual address
    pub p_vaddr: Elf64Addr,
    /// Segment physical address
    pub p_paddr: Elf64Addr,
    /// Segment size in file
    pub p_filesz: Elf64Xword,
    /// Segment size in memory
    pub p_memsz: Elf64Xword,
    /// Segment alignment
    pub p_align: Elf64Xword,
}

// ---------------------------------------------------------------------------
// Dynamic Section Structs (elf.h lines 664-682)
// ---------------------------------------------------------------------------

/// 32-bit ELF dynamic section entry.
/// The C union `d_un { d_val, d_ptr }` is modeled as a single `d_val` field
/// since both union members have the same size (`Elf32_Word`).
/// C equivalent: `Elf32_Dyn` (elf.h:664-673)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Dyn {
    /// Dynamic entry type tag
    pub d_tag: Elf32Sword,
    /// Integer or address value (union `d_val/d_ptr`)
    pub d_val: Elf32Word,
}

/// 64-bit ELF dynamic section entry.
/// The C union `d_un { d_val, d_ptr }` is modeled as a single `d_val` field
/// since both union members have the same size (`Elf64_Xword`).
/// C equivalent: `Elf64_Dyn` (elf.h:674-682)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Dyn {
    /// Dynamic entry type tag
    pub d_tag: Elf64Sxword,
    /// Integer or address value (union `d_val/d_ptr`)
    pub d_val: Elf64Xword,
}

// ---------------------------------------------------------------------------
// Note Header Structs (elf.h lines 1048-1060)
// ---------------------------------------------------------------------------

/// 32-bit ELF note header.
/// C equivalent: `Elf32_Nhdr` (elf.h:1048-1053)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Nhdr {
    /// Length of the note name
    pub n_namesz: Elf32Word,
    /// Length of the note descriptor
    pub n_descsz: Elf32Word,
    /// Note type
    pub n_type: Elf32Word,
}

/// 64-bit ELF note header.
/// C equivalent: `Elf64_Nhdr` (elf.h:1055-1060)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Nhdr {
    /// Length of the note name
    pub n_namesz: Elf64Word,
    /// Length of the note descriptor
    pub n_descsz: Elf64Word,
    /// Note type
    pub n_type: Elf64Word,
}

// ---------------------------------------------------------------------------
// Version Definition Structs (elf.h lines 841-948)
// ---------------------------------------------------------------------------

/// 32-bit ELF version definition.
/// C equivalent: `Elf32_Verdef` (elf.h:841-852)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Verdef {
    /// Version revision
    pub vd_version: Elf32Half,
    /// Version information flags
    pub vd_flags: Elf32Half,
    /// Version index (`VER_NDX`_*)
    pub vd_ndx: Elf32Half,
    /// Number of associated aux entries
    pub vd_cnt: Elf32Half,
    /// Version name hash value
    pub vd_hash: Elf32Word,
    /// Offset to Verdaux array (bytes)
    pub vd_aux: Elf32Word,
    /// Offset to next Verdef entry (bytes)
    pub vd_next: Elf32Word,
}

/// 64-bit ELF version definition (identical layout to 32-bit).
/// C equivalent: `Elf64_Verdef` (elf.h:854-863)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Verdef {
    /// Version revision
    pub vd_version: Elf64Half,
    /// Version information flags
    pub vd_flags: Elf64Half,
    /// Version index (`VER_NDX`_*)
    pub vd_ndx: Elf64Half,
    /// Number of associated aux entries
    pub vd_cnt: Elf64Half,
    /// Version name hash value
    pub vd_hash: Elf64Word,
    /// Offset to Verdaux array (bytes)
    pub vd_aux: Elf64Word,
    /// Offset to next Verdef entry (bytes)
    pub vd_next: Elf64Word,
}

/// 32-bit ELF version definition auxiliary entry.
/// C equivalent: `Elf32_Verdaux` (elf.h:883-887)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Verdaux {
    /// Version or dependency name string table offset
    pub vda_name: Elf32Word,
    /// Offset to next Verdaux entry (bytes)
    pub vda_next: Elf32Word,
}

/// 64-bit ELF version definition auxiliary entry.
/// C equivalent: `Elf64_Verdaux` (elf.h:889-895)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Verdaux {
    /// Version or dependency name string table offset
    pub vda_name: Elf64Word,
    /// Offset to next Verdaux entry (bytes)
    pub vda_next: Elf64Word,
}

/// 32-bit ELF version needed entry.
/// C equivalent: `Elf32_Verneed` (elf.h:900-910)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Verneed {
    /// Version of structure
    pub vn_version: Elf32Half,
    /// Number of associated aux entries
    pub vn_cnt: Elf32Half,
    /// Offset of filename for this dependency
    pub vn_file: Elf32Word,
    /// Offset of first Vernaux entry (bytes)
    pub vn_aux: Elf32Word,
    /// Offset to next Verneed entry (bytes)
    pub vn_next: Elf32Word,
}

/// 64-bit ELF version needed entry.
/// C equivalent: `Elf64_Verneed` (elf.h:912-920)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Verneed {
    /// Version of structure
    pub vn_version: Elf64Half,
    /// Number of associated aux entries
    pub vn_cnt: Elf64Half,
    /// Offset of filename for this dependency
    pub vn_file: Elf64Word,
    /// Offset of first Vernaux entry (bytes)
    pub vn_aux: Elf64Word,
    /// Offset to next Verneed entry (bytes)
    pub vn_next: Elf64Word,
}

/// 32-bit ELF version needed auxiliary entry.
/// C equivalent: `Elf32_Vernaux` (elf.h:930-939)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Vernaux {
    /// Hash value of dependency name
    pub vna_hash: Elf32Word,
    /// Dependency specific information flags
    pub vna_flags: Elf32Half,
    /// Unused
    pub vna_other: Elf32Half,
    /// Dependency name string offset
    pub vna_name: Elf32Word,
    /// Offset to next Vernaux entry (bytes)
    pub vna_next: Elf32Word,
}

/// 64-bit ELF version needed auxiliary entry.
/// C equivalent: `Elf64_Vernaux` (elf.h:941-948)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Vernaux {
    /// Hash value of dependency name
    pub vna_hash: Elf64Word,
    /// Dependency specific information flags
    pub vna_flags: Elf64Half,
    /// Unused
    pub vna_other: Elf64Half,
    /// Dependency name string offset
    pub vna_name: Elf64Word,
    /// Offset to next Vernaux entry (bytes)
    pub vna_next: Elf64Word,
}

/// 32-bit ELF auxiliary vector entry.
/// C equivalent: `Elf32_auxv_t` (elf.h:964-975)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32AuxvT {
    /// Entry type
    pub a_type: u32,
    /// Integer value (union `a_val`)
    pub a_val: u32,
}

/// 64-bit ELF auxiliary vector entry.
/// C equivalent: `Elf64_auxv_t` (elf.h:977-986)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64AuxvT {
    /// Entry type
    pub a_type: u64,
    /// Integer value (union `a_val`)
    pub a_val: u64,
}

/// 32-bit ELF move entry.
/// C equivalent: `Elf32_Move` (elf.h:1112-1119)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Move {
    /// Symbol value
    pub m_value: Elf32Xword,
    /// Size and index
    pub m_info: Elf32Word,
    /// Symbol offset
    pub m_poffset: Elf32Word,
    /// Repeat count
    pub m_repeat: Elf32Half,
    /// Stride info
    pub m_stride: Elf32Half,
}

/// 64-bit ELF move entry.
/// C equivalent: `Elf64_Move` (elf.h:1121-1128)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Move {
    /// Symbol value
    pub m_value: Elf64Xword,
    /// Size and index
    pub m_info: Elf64Xword,
    /// Symbol offset
    pub m_poffset: Elf64Xword,
    /// Repeat count
    pub m_repeat: Elf64Half,
    /// Stride info
    pub m_stride: Elf64Half,
}

/// 32-bit ELF library list entry.
/// C equivalent: `Elf32_Lib` (elf.h:1733-1740)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf32Lib {
    /// Library name (string table index)
    pub l_name: Elf32Word,
    /// Timestamp
    pub l_time_stamp: Elf32Word,
    /// Checksum
    pub l_checksum: Elf32Word,
    /// Interface version
    pub l_version: Elf32Word,
    /// Flags
    pub l_flags: Elf32Word,
}

/// 64-bit ELF library list entry.
/// C equivalent: `Elf64_Lib` (elf.h:1742-1749)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Lib {
    /// Library name (string table index)
    pub l_name: Elf64Word,
    /// Timestamp
    pub l_time_stamp: Elf64Word,
    /// Checksum
    pub l_checksum: Elf64Word,
    /// Interface version
    pub l_version: Elf64Word,
    /// Flags
    pub l_flags: Elf64Word,
}

// ---------------------------------------------------------------------------
// Helper Functions (ELF macros)
// ---------------------------------------------------------------------------

/// Extract symbol binding from `st_info`.
/// C equivalent: `ELF32_ST_BIND` / `ELF64_ST_BIND` macro
#[inline]
pub const fn elf_st_bind(val: u8) -> u8 { val >> 4 }

/// Extract symbol type from `st_info`.
/// C equivalent: `ELF32_ST_TYPE` / `ELF64_ST_TYPE` macro
#[inline]
pub const fn elf_st_type(val: u8) -> u8 { val & 0xf }

/// Construct `st_info` from binding and type.
/// C equivalent: `ELF32_ST_INFO` / `ELF64_ST_INFO` macro
#[inline]
pub const fn elf_st_info(bind: u8, sym_type: u8) -> u8 { (bind << 4) + (sym_type & 0xf) }

/// Extract symbol visibility from `st_other`.
/// C equivalent: `ELF32_ST_VISIBILITY` / `ELF64_ST_VISIBILITY` macro
#[inline]
pub const fn elf_st_visibility(other: u8) -> u8 { other & 0x03 }

/// Extract relocation symbol index (32-bit).
/// C equivalent: `ELF32_R_SYM` macro
#[inline]
pub const fn elf32_r_sym(val: u32) -> u32 { val >> 8 }

/// Extract relocation type (32-bit).
/// C equivalent: `ELF32_R_TYPE` macro
#[inline]
pub const fn elf32_r_type(val: u32) -> u32 { val & 0xff }

/// Construct `r_info` (32-bit).
/// C equivalent: `ELF32_R_INFO` macro
#[inline]
pub const fn elf32_r_info(sym: u32, r_type: u32) -> u32 { (sym << 8) + (r_type & 0xff) }

/// Extract relocation symbol index (64-bit).
/// C equivalent: `ELF64_R_SYM` macro
#[inline]
pub const fn elf64_r_sym(i: u64) -> u64 { i >> 32 }

/// Extract relocation type (64-bit).
/// C equivalent: `ELF64_R_TYPE` macro
#[inline]
pub const fn elf64_r_type(i: u64) -> u64 { i & 0xffffffff }

/// Construct `r_info` (64-bit).
/// C equivalent: `ELF64_R_INFO` macro
#[inline]
pub const fn elf64_r_info(sym: u64, r_type: u64) -> u64 { (sym << 32) + r_type }

// ---------------------------------------------------------------------------
// Special Section Indices (elf.h lines 318-331)
// ---------------------------------------------------------------------------
pub const SHN_UNDEF: u16 = 0x0;
pub const SHN_LORESERVE: u16 = 0xff00;
pub const SHN_LOPROC: u16 = 0xff00;
pub const SHN_BEFORE: u16 = 0xff00;
pub const SHN_AFTER: u16 = 0xff01;
pub const SHN_HIPROC: u16 = 0xff1f;
pub const SHN_LOOS: u16 = 0xff20;
pub const SHN_HIOS: u16 = 0xff3f;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;
pub const SHN_XINDEX: u16 = 0xffff;
pub const SHN_HIRESERVE: u16 = 0xffff;

// ---------------------------------------------------------------------------
// Section Types (elf.h lines 335-370)
// ---------------------------------------------------------------------------
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_SHLIB: u32 = 10;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const SHT_NUM: u32 = 19;
pub const SHT_LOOS: u32 = 0x60000000;
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6ffffff5;
pub const SHT_GNU_HASH: u32 = 0x6ffffff6;
pub const SHT_GNU_LIBLIST: u32 = 0x6ffffff7;
pub const SHT_CHECKSUM: u32 = 0x6ffffff8;
pub const SHT_LOSUNW: u32 = 0x6ffffffa;
pub const SHT_SUNW_move: u32 = 0x6ffffffa;
pub const SHT_SUNW_COMDAT: u32 = 0x6ffffffb;
pub const SHT_SUNW_syminfo: u32 = 0x6ffffffc;
pub const SHT_GNU_verdef: u32 = 0x6ffffffd;
pub const SHT_GNU_verneed: u32 = 0x6ffffffe;
pub const SHT_GNU_versym: u32 = 0x6fffffff;
pub const SHT_HISUNW: u32 = 0x6fffffff;
pub const SHT_HIOS: u32 = 0x6fffffff;
pub const SHT_LOPROC: u32 = 0x70000000;
pub const SHT_HIPROC: u32 = 0x7fffffff;
pub const SHT_LOUSER: u32 = 0x80000000;
pub const SHT_HIUSER: u32 = 0x8fffffff;

// ---------------------------------------------------------------------------
// Section Flags (elf.h lines 374-391)
// ---------------------------------------------------------------------------
pub const SHF_WRITE: u32 = 0x1;
pub const SHF_ALLOC: u32 = 0x2;
pub const SHF_EXECINSTR: u32 = 0x4;
pub const SHF_MERGE: u32 = 0x10;
pub const SHF_STRINGS: u32 = 0x20;
pub const SHF_INFO_LINK: u32 = 0x40;
pub const SHF_LINK_ORDER: u32 = 0x80;
pub const SHF_OS_NONCONFORMING: u32 = 0x100;
pub const SHF_GROUP: u32 = 0x200;
pub const SHF_TLS: u32 = 0x400;
pub const SHF_COMPRESSED: u32 = 0x800;
pub const SHF_MASKOS: u32 = 0x0ff00000;
pub const SHF_MASKPROC: u32 = 0xf0000000;
pub const SHF_ORDERED: u32 = 0x40000000;
pub const SHF_EXCLUDE: u32 = 0x80000000;
pub const GRP_COMDAT: u32 = 0x1;

// ---------------------------------------------------------------------------
// Syminfo Constants (elf.h)
// ---------------------------------------------------------------------------
pub const SYMINFO_BT_SELF: u16 = 0xffff;
pub const SYMINFO_BT_PARENT: u16 = 0xfffe;
pub const SYMINFO_BT_LOWRESERVE: u16 = 0xff00;
pub const SYMINFO_FLG_DIRECT: u16 = 0x0001;
pub const SYMINFO_FLG_PASSTHRU: u16 = 0x0002;
pub const SYMINFO_FLG_COPY: u16 = 0x0004;
pub const SYMINFO_FLG_LAZYLOAD: u16 = 0x0008;
pub const SYMINFO_NONE: u16 = 0;
pub const SYMINFO_CURRENT: u16 = 1;
pub const SYMINFO_NUM: u16 = 2;

// ---------------------------------------------------------------------------
// Symbol Binding (elf.h lines 463-471)
// ---------------------------------------------------------------------------
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STB_NUM: u8 = 3;
pub const STB_LOOS: u8 = 10;
pub const STB_GNU_UNIQUE: u8 = 10;
pub const STB_HIOS: u8 = 12;
pub const STB_LOPROC: u8 = 13;
pub const STB_HIPROC: u8 = 15;

// ---------------------------------------------------------------------------
// Symbol Types (elf.h lines 475-487)
// ---------------------------------------------------------------------------
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
pub const STT_NUM: u8 = 7;
pub const STT_LOOS: u8 = 10;
pub const STT_GNU_IFUNC: u8 = 10;
pub const STT_HIOS: u8 = 12;
pub const STT_LOPROC: u8 = 13;
pub const STT_HIPROC: u8 = 15;
pub const STN_UNDEF: u32 = 0;

// ---------------------------------------------------------------------------
// Symbol Visibility (elf.h lines 505-508)
// ---------------------------------------------------------------------------
pub const STV_DEFAULT: u8 = 0;
pub const STV_INTERNAL: u8 = 1;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;

pub const PN_XNUM: u16 = 0xffff;

// ---------------------------------------------------------------------------
// Program Header Types (elf.h lines 590-609)
// ---------------------------------------------------------------------------
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_NUM: u32 = 8;
pub const PT_LOOS: u32 = 0x60000000;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PT_GNU_STACK: u32 = 0x6474e551;
pub const PT_GNU_RELRO: u32 = 0x6474e552;
pub const PT_LOSUNW: u32 = 0x6ffffffa;
pub const PT_SUNWBSS: u32 = 0x6ffffffa;
pub const PT_SUNWSTACK: u32 = 0x6ffffffb;
pub const PT_HISUNW: u32 = 0x6fffffff;
pub const PT_HIOS: u32 = 0x6fffffff;
pub const PT_LOPROC: u32 = 0x70000000;
pub const PT_HIPROC: u32 = 0x7fffffff;

// ---------------------------------------------------------------------------
// Program Header Flags (elf.h lines 613-617)
// ---------------------------------------------------------------------------
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const PF_MASKOS: u32 = 0x0ff00000;
pub const PF_MASKPROC: u32 = 0xf0000000;

// ---------------------------------------------------------------------------
// Note Descriptor Types (elf.h lines 621-655)
// ---------------------------------------------------------------------------
pub const NT_PRSTATUS: u32 = 1;
pub const NT_FPREGSET: u32 = 2;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_PRXREG: u32 = 4;
pub const NT_TASKSTRUCT: u32 = 4;
pub const NT_PLATFORM: u32 = 5;
pub const NT_AUXV: u32 = 6;
pub const NT_GWINDOWS: u32 = 7;
pub const NT_ASRS: u32 = 8;
pub const NT_PSTATUS: u32 = 10;
pub const NT_PSINFO: u32 = 13;
pub const NT_PRCRED: u32 = 14;
pub const NT_UTSNAME: u32 = 15;
pub const NT_LWPSTATUS: u32 = 16;
pub const NT_LWPSINFO: u32 = 17;
pub const NT_PRFPXREG: u32 = 20;
pub const NT_SIGINFO: u32 = 0x53494749;
pub const NT_FILE: u32 = 0x46494c45;
pub const NT_PRXFPREG: u32 = 0x46e62b7f;
pub const NT_PPC_VMX: u32 = 0x100;
pub const NT_PPC_SPE: u32 = 0x101;
pub const NT_PPC_VSX: u32 = 0x102;
pub const NT_386_TLS: u32 = 0x200;
pub const NT_386_IOPERM: u32 = 0x201;
pub const NT_X86_XSTATE: u32 = 0x202;
pub const NT_S390_HIGH_GPRS: u32 = 0x300;
pub const NT_S390_TIMER: u32 = 0x301;
pub const NT_S390_TODCMP: u32 = 0x302;
pub const NT_S390_TODPREG: u32 = 0x303;
pub const NT_S390_CTRS: u32 = 0x304;
pub const NT_S390_PREFIX: u32 = 0x305;
pub const NT_S390_LAST_BREAK: u32 = 0x306;
pub const NT_S390_SYSTEM_CALL: u32 = 0x307;
pub const NT_S390_TDB: u32 = 0x308;
pub const NT_ARM_VFP: u32 = 0x400;
pub const NT_ARM_TLS: u32 = 0x401;
pub const NT_ARM_HW_BREAK: u32 = 0x402;
pub const NT_ARM_HW_WATCH: u32 = 0x403;
pub const NT_VERSION: u32 = 1;
pub const NT_GNU_ABI_TAG: u32 = 1;
pub const NT_GNU_HWCAP: u32 = 2;
pub const NT_GNU_BUILD_ID: u32 = 3;
pub const NT_GNU_GOLD_VERSION: u32 = 4;

// ---------------------------------------------------------------------------
// Dynamic Section Tags (elf.h lines 686+)
// ---------------------------------------------------------------------------
// DT_* tags defined as i32 to match Elf32_Sword / Elf64_Sxword usage.
// Large hex values use wrapping casts.
pub const DT_NULL: i32 = 0;
pub const DT_NEEDED: i32 = 1;
pub const DT_PLTRELSZ: i32 = 2;
pub const DT_PLTGOT: i32 = 3;
pub const DT_HASH: i32 = 4;
pub const DT_STRTAB: i32 = 5;
pub const DT_SYMTAB: i32 = 6;
pub const DT_RELA: i32 = 7;
pub const DT_RELASZ: i32 = 8;
pub const DT_RELAENT: i32 = 9;
pub const DT_STRSZ: i32 = 10;
pub const DT_SYMENT: i32 = 11;
pub const DT_INIT: i32 = 12;
pub const DT_FINI: i32 = 13;
pub const DT_SONAME: i32 = 14;
pub const DT_RPATH: i32 = 15;
pub const DT_SYMBOLIC: i32 = 16;
pub const DT_REL: i32 = 17;
pub const DT_RELSZ: i32 = 18;
pub const DT_RELENT: i32 = 19;
pub const DT_PLTREL: i32 = 20;
pub const DT_DEBUG: i32 = 21;
pub const DT_TEXTREL: i32 = 22;
pub const DT_JMPREL: i32 = 23;
pub const DT_BIND_NOW: i32 = 24;
pub const DT_INIT_ARRAY: i32 = 25;
pub const DT_FINI_ARRAY: i32 = 26;
pub const DT_INIT_ARRAYSZ: i32 = 27;
pub const DT_FINI_ARRAYSZ: i32 = 28;
pub const DT_RUNPATH: i32 = 29;
pub const DT_FLAGS: i32 = 30;
pub const DT_ENCODING: i32 = 32;
pub const DT_PREINIT_ARRAY: i32 = 32;
pub const DT_PREINIT_ARRAYSZ: i32 = 33;
pub const DT_NUM: i32 = 35;
pub const DT_PROCNUM: i32 = 54;
pub const DT_VALNUM: i32 = 12;
pub const DT_ADDRNUM: i32 = 11;
pub const DT_VERSIONTAGNUM: i32 = 16;
pub const DT_EXTRANUM: i32 = 3;

pub const DT_LOOS: u32 = 0x6000000d;
pub const DT_HIOS: u32 = 0x6ffff000;
pub const DT_LOPROC: u32 = 0x70000000;
pub const DT_HIPROC: u32 = 0x7fffffff;
pub const DT_VALRNGLO: u32 = 0x6ffffd00;
pub const DT_GNU_PRELINKED: u32 = 0x6ffffdf5;
pub const DT_GNU_CONFLICTSZ: u32 = 0x6ffffdf6;
pub const DT_GNU_LIBLISTSZ: u32 = 0x6ffffdf7;
pub const DT_CHECKSUM: u32 = 0x6ffffdf8;
pub const DT_PLTPADSZ: u32 = 0x6ffffdf9;
pub const DT_MOVEENT: u32 = 0x6ffffdfa;
pub const DT_MOVESZ: u32 = 0x6ffffdfb;
pub const DT_FEATURE_1: u32 = 0x6ffffdfc;
pub const DT_POSFLAG_1: u32 = 0x6ffffdfd;
pub const DT_SYMINSZ: u32 = 0x6ffffdfe;
pub const DT_SYMINENT: u32 = 0x6ffffdff;
pub const DT_VALRNGHI: u32 = 0x6ffffdff;
pub const DT_ADDRRNGLO: u32 = 0x6ffffe00;
pub const DT_GNU_HASH: u32 = 0x6ffffef5;
pub const DT_TLSDESC_PLT: u32 = 0x6ffffef6;
pub const DT_TLSDESC_GOT: u32 = 0x6ffffef7;
pub const DT_GNU_CONFLICT: u32 = 0x6ffffef8;
pub const DT_GNU_LIBLIST: u32 = 0x6ffffef9;
pub const DT_CONFIG: u32 = 0x6ffffefa;
pub const DT_DEPAUDIT: u32 = 0x6ffffefb;
pub const DT_AUDIT: u32 = 0x6ffffefc;
pub const DT_PLTPAD: u32 = 0x6ffffefd;
pub const DT_MOVETAB: u32 = 0x6ffffefe;
pub const DT_SYMINFO: u32 = 0x6ffffeff;
pub const DT_ADDRRNGHI: u32 = 0x6ffffeff;
pub const DT_VERSYM: u32 = 0x6ffffff0;
pub const DT_RELACOUNT: u32 = 0x6ffffff9;
pub const DT_RELCOUNT: u32 = 0x6ffffffa;
pub const DT_FLAGS_1: u32 = 0x6ffffffb;
pub const DT_VERDEF: u32 = 0x6ffffffc;
pub const DT_VERDEFNUM: u32 = 0x6ffffffd;
pub const DT_VERNEED: u32 = 0x6ffffffe;
pub const DT_VERNEEDNUM: u32 = 0x6fffffff;
pub const DT_AUXILIARY: u32 = 0x7ffffffd;
pub const DT_FILTER: u32 = 0x7fffffff;

// ---------------------------------------------------------------------------
// DT_FLAGS values (elf.h)
// ---------------------------------------------------------------------------
pub const DF_ORIGIN: u32 = 0x00000001;
pub const DF_SYMBOLIC: u32 = 0x00000002;
pub const DF_TEXTREL: u32 = 0x00000004;
pub const DF_BIND_NOW: u32 = 0x00000008;
pub const DF_STATIC_TLS: u32 = 0x00000010;

// ---------------------------------------------------------------------------
// DT_FLAGS_1 values (elf.h)
// ---------------------------------------------------------------------------
pub const DF_1_NOW: u32 = 0x00000001;
pub const DF_1_GLOBAL: u32 = 0x00000002;
pub const DF_1_GROUP: u32 = 0x00000004;
pub const DF_1_NODELETE: u32 = 0x00000008;
pub const DF_1_LOADFLTR: u32 = 0x00000010;
pub const DF_1_INITFIRST: u32 = 0x00000020;
pub const DF_1_NOOPEN: u32 = 0x00000040;
pub const DF_1_ORIGIN: u32 = 0x00000080;
pub const DF_1_DIRECT: u32 = 0x00000100;
pub const DF_1_TRANS: u32 = 0x00000200;
pub const DF_1_INTERPOSE: u32 = 0x00000400;
pub const DF_1_NODEFLIB: u32 = 0x00000800;
pub const DF_1_NODUMP: u32 = 0x00001000;
pub const DF_1_CONFALT: u32 = 0x00002000;
pub const DF_1_ENDFILTEE: u32 = 0x00004000;
pub const DF_1_DISPRELDNE: u32 = 0x00008000;
pub const DF_1_DISPRELPND: u32 = 0x00010000;
pub const DF_1_NODIRECT: u32 = 0x00020000;
pub const DF_1_IGNMULDEF: u32 = 0x00040000;
pub const DF_1_NOKSYMS: u32 = 0x00080000;
pub const DF_1_NOHDR: u32 = 0x00100000;
pub const DF_1_EDITED: u32 = 0x00200000;
pub const DF_1_NORELOC: u32 = 0x00400000;
pub const DF_1_SYMINTPOSE: u32 = 0x00800000;
pub const DF_1_GLOBAUDIT: u32 = 0x01000000;
pub const DF_1_SINGLETON: u32 = 0x02000000;
pub const DF_1_PIE: u32 = 0x08000000;

pub const DTF_1_PARINIT: u32 = 0x00000001;
pub const DTF_1_CONFEXP: u32 = 0x00000002;
pub const DF_P1_LAZYLOAD: u32 = 0x00000001;
pub const DF_P1_GROUPPERM: u32 = 0x00000002;

// ---------------------------------------------------------------------------
// Version Definition/Need Constants (elf.h)
// ---------------------------------------------------------------------------
pub const VER_DEF_NONE: u16 = 0;
pub const VER_DEF_CURRENT: u16 = 1;
pub const VER_DEF_NUM: u16 = 2;
pub const VER_FLG_BASE: u16 = 0x1;
pub const VER_FLG_WEAK: u16 = 0x2;
pub const VER_NDX_LOCAL: u16 = 0;
pub const VER_NDX_GLOBAL: u16 = 1;
pub const VER_NDX_LORESERVE: u16 = 0xff00;
pub const VER_NDX_ELIMINATE: u16 = 0xff01;
pub const VER_NEED_NONE: u16 = 0;
pub const VER_NEED_CURRENT: u16 = 1;
pub const VER_NEED_NUM: u16 = 2;

// ---------------------------------------------------------------------------
// Auxiliary Vector Types (elf.h)
// ---------------------------------------------------------------------------
pub const AT_NULL: u32 = 0;
pub const AT_IGNORE: u32 = 1;
pub const AT_EXECFD: u32 = 2;
pub const AT_PHDR: u32 = 3;
pub const AT_PHENT: u32 = 4;
pub const AT_PHNUM: u32 = 5;
pub const AT_PAGESZ: u32 = 6;
pub const AT_BASE: u32 = 7;
pub const AT_FLAGS: u32 = 8;
pub const AT_ENTRY: u32 = 9;
pub const AT_NOTELF: u32 = 10;
pub const AT_UID: u32 = 11;
pub const AT_EUID: u32 = 12;
pub const AT_GID: u32 = 13;
pub const AT_EGID: u32 = 14;
pub const AT_CLKTCK: u32 = 17;
pub const AT_PLATFORM: u32 = 15;
pub const AT_HWCAP: u32 = 16;
pub const AT_FPUCW: u32 = 18;
pub const AT_DCACHEBSIZE: u32 = 19;
pub const AT_ICACHEBSIZE: u32 = 20;
pub const AT_UCACHEBSIZE: u32 = 21;
pub const AT_IGNOREPPC: u32 = 22;
pub const AT_SECURE: u32 = 23;
pub const AT_BASE_PLATFORM: u32 = 24;
pub const AT_RANDOM: u32 = 25;
pub const AT_HWCAP2: u32 = 26;
pub const AT_EXECFN: u32 = 31;
pub const AT_SYSINFO: u32 = 32;
pub const AT_SYSINFO_EHDR: u32 = 33;
pub const AT_L1I_CACHESHAPE: u32 = 34;
pub const AT_L1D_CACHESHAPE: u32 = 35;
pub const AT_L2_CACHESHAPE: u32 = 36;
pub const AT_L3_CACHESHAPE: u32 = 37;

// ---------------------------------------------------------------------------
// i386 Relocation Types (elf.h lines 1198-1258)
// ---------------------------------------------------------------------------
pub const R_386_NONE: u32 = 0;
pub const R_386_32: u32 = 1;
pub const R_386_PC32: u32 = 2;
pub const R_386_GOT32: u32 = 3;
pub const R_386_PLT32: u32 = 4;
pub const R_386_COPY: u32 = 5;
pub const R_386_GLOB_DAT: u32 = 6;
pub const R_386_JMP_SLOT: u32 = 7;
pub const R_386_RELATIVE: u32 = 8;
pub const R_386_GOTOFF: u32 = 9;
pub const R_386_GOTPC: u32 = 10;
pub const R_386_32PLT: u32 = 11;
pub const R_386_TLS_TPOFF: u32 = 14;
pub const R_386_TLS_IE: u32 = 15;
pub const R_386_TLS_GOTIE: u32 = 16;
pub const R_386_TLS_LE: u32 = 17;
pub const R_386_TLS_GD: u32 = 18;
pub const R_386_TLS_LDM: u32 = 19;
pub const R_386_16: u32 = 20;
pub const R_386_PC16: u32 = 21;
pub const R_386_8: u32 = 22;
pub const R_386_PC8: u32 = 23;
pub const R_386_TLS_GD_32: u32 = 24;
pub const R_386_TLS_GD_PUSH: u32 = 25;
pub const R_386_TLS_GD_CALL: u32 = 26;
pub const R_386_TLS_GD_POP: u32 = 27;
pub const R_386_TLS_LDM_32: u32 = 28;
pub const R_386_TLS_LDM_PUSH: u32 = 29;
pub const R_386_TLS_LDM_CALL: u32 = 30;
pub const R_386_TLS_LDM_POP: u32 = 31;
pub const R_386_TLS_LDO_32: u32 = 32;
pub const R_386_TLS_IE_32: u32 = 33;
pub const R_386_TLS_LE_32: u32 = 34;
pub const R_386_TLS_DTPMOD32: u32 = 35;
pub const R_386_TLS_DTPOFF32: u32 = 36;
pub const R_386_TLS_TPOFF32: u32 = 37;
pub const R_386_SIZE32: u32 = 38;
pub const R_386_TLS_GOTDESC: u32 = 39;
pub const R_386_TLS_DESC_CALL: u32 = 40;
pub const R_386_TLS_DESC: u32 = 41;
pub const R_386_IRELATIVE: u32 = 42;
pub const R_386_GOT32X: u32 = 43;
pub const R_386_NUM: u32 = 44;

// ---------------------------------------------------------------------------
// x86-64 Relocation Types (elf.h lines 2871-2923)
// ---------------------------------------------------------------------------
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_16: u32 = 12;
pub const R_X86_64_PC16: u32 = 13;
pub const R_X86_64_8: u32 = 14;
pub const R_X86_64_PC8: u32 = 15;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_TLSGD: u32 = 19;
pub const R_X86_64_TLSLD: u32 = 20;
pub const R_X86_64_DTPOFF32: u32 = 21;
pub const R_X86_64_GOTTPOFF: u32 = 22;
pub const R_X86_64_TPOFF32: u32 = 23;
pub const R_X86_64_PC64: u32 = 24;
pub const R_X86_64_GOTOFF64: u32 = 25;
pub const R_X86_64_GOTPC32: u32 = 26;
pub const R_X86_64_GOT64: u32 = 27;
pub const R_X86_64_GOTPCREL64: u32 = 28;
pub const R_X86_64_GOTPC64: u32 = 29;
pub const R_X86_64_GOTPLT64: u32 = 30;
pub const R_X86_64_PLTOFF64: u32 = 31;
pub const R_X86_64_SIZE32: u32 = 32;
pub const R_X86_64_SIZE64: u32 = 33;
pub const R_X86_64_GOTPC32_TLSDESC: u32 = 34;
pub const R_X86_64_TLSDESC_CALL: u32 = 35;
pub const R_X86_64_TLSDESC: u32 = 36;
pub const R_X86_64_IRELATIVE: u32 = 37;
pub const R_X86_64_RELATIVE64: u32 = 38;
pub const R_X86_64_GOTPCRELX: u32 = 41;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;
pub const R_X86_64_NUM: u32 = 43;
pub const SHT_X86_64_UNWIND: u32 = 0x70000001;

// ---------------------------------------------------------------------------
// ARM Relocation Types (elf.h lines 2472-2552)
// ---------------------------------------------------------------------------
pub const R_ARM_NONE: u32 = 0;
pub const R_ARM_PC24: u32 = 1;
pub const R_ARM_ABS32: u32 = 2;
pub const R_ARM_REL32: u32 = 3;
pub const R_ARM_LDR_PC_G0: u32 = 4;
pub const R_ARM_ABS16: u32 = 5;
pub const R_ARM_ABS12: u32 = 6;
pub const R_ARM_THM_ABS5: u32 = 7;
pub const R_ARM_ABS8: u32 = 8;
pub const R_ARM_SBREL32: u32 = 9;
pub const R_ARM_THM_CALL: u32 = 10;
pub const R_ARM_THM_PC8: u32 = 11;
pub const R_ARM_BREL_ADJ: u32 = 12;
pub const R_ARM_TLS_DESC: u32 = 13;
pub const R_ARM_THM_SWI8: u32 = 14;
pub const R_ARM_XPC25: u32 = 15;
pub const R_ARM_THM_XPC22: u32 = 16;
pub const R_ARM_TLS_DTPMOD32: u32 = 17;
pub const R_ARM_TLS_DTPOFF32: u32 = 18;
pub const R_ARM_TLS_TPOFF32: u32 = 19;
pub const R_ARM_COPY: u32 = 20;
pub const R_ARM_GLOB_DAT: u32 = 21;
pub const R_ARM_JUMP_SLOT: u32 = 22;
pub const R_ARM_RELATIVE: u32 = 23;
pub const R_ARM_GOTOFF32: u32 = 24;
pub const R_ARM_BASE_PREL: u32 = 25;
pub const R_ARM_GOT_BREL: u32 = 26;
pub const R_ARM_PLT32: u32 = 27;
pub const R_ARM_CALL: u32 = 28;
pub const R_ARM_JUMP24: u32 = 29;
pub const R_ARM_THM_JUMP24: u32 = 30;
pub const R_ARM_BASE_ABS: u32 = 31;
pub const R_ARM_ALU_PCREL_7_0: u32 = 32;
pub const R_ARM_ALU_PCREL_15_8: u32 = 33;
pub const R_ARM_ALU_PCREL_23_15: u32 = 34;
pub const R_ARM_LDR_SBREL_11_0_NC: u32 = 35;
pub const R_ARM_ALU_SBREL_19_12_NC: u32 = 36;
pub const R_ARM_ALU_SBREL_27_20_CK: u32 = 37;
pub const R_ARM_TARGET1: u32 = 38;
pub const R_ARM_SBREL31: u32 = 39;
pub const R_ARM_V4BX: u32 = 40;
pub const R_ARM_TARGET2: u32 = 41;
pub const R_ARM_PREL31: u32 = 42;
pub const R_ARM_MOVW_ABS_NC: u32 = 43;
pub const R_ARM_MOVT_ABS: u32 = 44;
pub const R_ARM_MOVW_PREL_NC: u32 = 45;
pub const R_ARM_MOVT_PREL: u32 = 46;
pub const R_ARM_THM_MOVW_ABS_NC: u32 = 47;
pub const R_ARM_THM_MOVT_ABS: u32 = 48;
pub const R_ARM_THM_MOVW_PREL_NC: u32 = 49;
pub const R_ARM_THM_MOVT_PREL: u32 = 50;
pub const R_ARM_THM_JUMP19: u32 = 51;
pub const R_ARM_THM_JUMP6: u32 = 52;
pub const R_ARM_THM_ALU_PREL_11_0: u32 = 53;
pub const R_ARM_THM_PC12: u32 = 54;
pub const R_ARM_ABS32_NOI: u32 = 55;
pub const R_ARM_REL32_NOI: u32 = 56;
pub const R_ARM_ALU_PC_G0_NC: u32 = 57;
pub const R_ARM_ALU_PC_G0: u32 = 58;
pub const R_ARM_ALU_PC_G1_NC: u32 = 59;
pub const R_ARM_ALU_PC_G1: u32 = 60;
pub const R_ARM_ALU_PC_G2: u32 = 61;
pub const R_ARM_LDR_PC_G1: u32 = 62;
pub const R_ARM_LDR_PC_G2: u32 = 63;
pub const R_ARM_LDRS_PC_G0: u32 = 64;
pub const R_ARM_LDRS_PC_G1: u32 = 65;
pub const R_ARM_LDRS_PC_G2: u32 = 66;
pub const R_ARM_LDC_PC_G0: u32 = 67;
pub const R_ARM_LDC_PC_G1: u32 = 68;
pub const R_ARM_LDC_PC_G2: u32 = 69;
pub const R_ARM_ALU_SB_G0_NC: u32 = 70;
pub const R_ARM_ALU_SB_G0: u32 = 71;
pub const R_ARM_ALU_SB_G1_NC: u32 = 72;
pub const R_ARM_ALU_SB_G1: u32 = 73;
pub const R_ARM_ALU_SB_G2: u32 = 74;
pub const R_ARM_LDR_SB_G0: u32 = 75;
pub const R_ARM_LDR_SB_G1: u32 = 76;
pub const R_ARM_LDR_SB_G2: u32 = 77;
pub const R_ARM_LDRS_SB_G0: u32 = 78;
pub const R_ARM_LDRS_SB_G1: u32 = 79;
pub const R_ARM_LDRS_SB_G2: u32 = 80;
pub const R_ARM_LDC_SB_G0: u32 = 81;
pub const R_ARM_LDC_SB_G1: u32 = 82;
pub const R_ARM_LDC_SB_G2: u32 = 83;
pub const R_ARM_MOVW_BREL_NC: u32 = 84;
pub const R_ARM_MOVT_BREL: u32 = 85;
pub const R_ARM_MOVW_BREL: u32 = 86;
pub const R_ARM_THM_MOVW_BREL_NC: u32 = 87;
pub const R_ARM_THM_MOVT_BREL: u32 = 88;
pub const R_ARM_THM_MOVW_BREL: u32 = 89;
pub const R_ARM_TLS_GOTDESC: u32 = 90;
pub const R_ARM_TLS_CALL: u32 = 91;
pub const R_ARM_TLS_DESCSEQ: u32 = 92;
pub const R_ARM_THM_TLS_CALL: u32 = 93;
pub const R_ARM_PLT32_ABS: u32 = 94;
pub const R_ARM_GOT_ABS: u32 = 95;
pub const R_ARM_GOT_PREL: u32 = 96;
pub const R_ARM_GOT_BREL12: u32 = 97;
pub const R_ARM_GOTOFF12: u32 = 98;
pub const R_ARM_GOTRELAX: u32 = 99;
pub const R_ARM_GNU_VTENTRY: u32 = 100;
pub const R_ARM_GNU_VTINHERIT: u32 = 101;
pub const R_ARM_THM_JUMP11: u32 = 102;
pub const R_ARM_THM_JUMP8: u32 = 103;
pub const R_ARM_TLS_GD32: u32 = 104;
pub const R_ARM_TLS_LDM32: u32 = 105;
pub const R_ARM_TLS_LDO32: u32 = 106;
pub const R_ARM_TLS_IE32: u32 = 107;
pub const R_ARM_TLS_LE32: u32 = 108;
pub const R_ARM_TLS_LDO12: u32 = 109;
pub const R_ARM_TLS_LE12: u32 = 110;
pub const R_ARM_TLS_IE12GP: u32 = 111;
pub const R_ARM_PRIVATE_0: u32 = 112;
pub const R_ARM_PRIVATE_1: u32 = 113;
pub const R_ARM_PRIVATE_2: u32 = 114;
pub const R_ARM_PRIVATE_3: u32 = 115;
pub const R_ARM_PRIVATE_4: u32 = 116;
pub const R_ARM_PRIVATE_5: u32 = 117;
pub const R_ARM_PRIVATE_6: u32 = 118;
pub const R_ARM_PRIVATE_7: u32 = 119;
pub const R_ARM_PRIVATE_8: u32 = 120;
pub const R_ARM_PRIVATE_9: u32 = 121;
pub const R_ARM_PRIVATE_10: u32 = 122;
pub const R_ARM_PRIVATE_11: u32 = 123;
pub const R_ARM_PRIVATE_12: u32 = 124;
pub const R_ARM_PRIVATE_13: u32 = 125;
pub const R_ARM_PRIVATE_14: u32 = 126;
pub const R_ARM_PRIVATE_15: u32 = 127;
pub const R_ARM_ME_TOO: u32 = 128;
pub const R_ARM_THM_TLS_DESCSEQ16: u32 = 129;
pub const R_ARM_THM_TLS_DESCSEQ32: u32 = 130;
pub const R_ARM_THM_PC22: u32 = 10;
pub const R_ARM_IRELATIVE: u32 = 160;
pub const R_ARM_GOTPC: u32 = 25;
pub const R_ARM_GOTOFF: u32 = 24;
pub const R_ARM_GOT32: u32 = 26;
pub const R_ARM_NUM: u32 = 256;

// ---------------------------------------------------------------------------
// AArch64 Relocation Types (elf.h lines 2344-2468)
// ---------------------------------------------------------------------------
pub const R_AARCH64_NONE: u32 = 0;
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_ABS32: u32 = 258;
pub const R_AARCH64_ABS16: u32 = 259;
pub const R_AARCH64_PREL64: u32 = 260;
pub const R_AARCH64_PREL32: u32 = 261;
pub const R_AARCH64_PREL16: u32 = 262;
pub const R_AARCH64_MOVW_UABS_G0: u32 = 263;
pub const R_AARCH64_MOVW_UABS_G0_NC: u32 = 264;
pub const R_AARCH64_MOVW_UABS_G1: u32 = 265;
pub const R_AARCH64_MOVW_UABS_G1_NC: u32 = 266;
pub const R_AARCH64_MOVW_UABS_G2: u32 = 267;
pub const R_AARCH64_MOVW_UABS_G2_NC: u32 = 268;
pub const R_AARCH64_MOVW_UABS_G3: u32 = 269;
pub const R_AARCH64_MOVW_SABS_G0: u32 = 270;
pub const R_AARCH64_MOVW_SABS_G1: u32 = 271;
pub const R_AARCH64_MOVW_SABS_G2: u32 = 272;
pub const R_AARCH64_LD_PREL_LO19: u32 = 273;
pub const R_AARCH64_ADR_PREL_LO21: u32 = 274;
pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
pub const R_AARCH64_ADR_PREL_PG_HI21_NC: u32 = 276;
pub const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
pub const R_AARCH64_LDST8_ABS_LO12_NC: u32 = 278;
pub const R_AARCH64_TSTBR14: u32 = 279;
pub const R_AARCH64_CONDBR19: u32 = 280;
pub const R_AARCH64_JUMP26: u32 = 282;
pub const R_AARCH64_CALL26: u32 = 283;
pub const R_AARCH64_LDST16_ABS_LO12_NC: u32 = 284;
pub const R_AARCH64_LDST32_ABS_LO12_NC: u32 = 285;
pub const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
pub const R_AARCH64_MOVW_PREL_G0: u32 = 287;
pub const R_AARCH64_MOVW_PREL_G0_NC: u32 = 288;
pub const R_AARCH64_MOVW_PREL_G1: u32 = 289;
pub const R_AARCH64_MOVW_PREL_G1_NC: u32 = 290;
pub const R_AARCH64_MOVW_PREL_G2: u32 = 291;
pub const R_AARCH64_MOVW_PREL_G2_NC: u32 = 292;
pub const R_AARCH64_MOVW_PREL_G3: u32 = 293;
pub const R_AARCH64_LDST128_ABS_LO12_NC: u32 = 299;
pub const R_AARCH64_MOVW_GOTOFF_G0: u32 = 300;
pub const R_AARCH64_MOVW_GOTOFF_G0_NC: u32 = 301;
pub const R_AARCH64_MOVW_GOTOFF_G1: u32 = 302;
pub const R_AARCH64_MOVW_GOTOFF_G1_NC: u32 = 303;
pub const R_AARCH64_MOVW_GOTOFF_G2: u32 = 304;
pub const R_AARCH64_MOVW_GOTOFF_G2_NC: u32 = 305;
pub const R_AARCH64_MOVW_GOTOFF_G3: u32 = 306;
pub const R_AARCH64_GOTREL64: u32 = 307;
pub const R_AARCH64_GOTREL32: u32 = 308;
pub const R_AARCH64_GOT_LD_PREL19: u32 = 309;
pub const R_AARCH64_LD64_GOTOFF_LO15: u32 = 310;
pub const R_AARCH64_ADR_GOT_PAGE: u32 = 311;
pub const R_AARCH64_LD64_GOT_LO12_NC: u32 = 312;
pub const R_AARCH64_LD64_GOTPAGE_LO15: u32 = 313;
pub const R_AARCH64_TLSGD_ADR_PREL21: u32 = 512;
pub const R_AARCH64_TLSGD_ADR_PAGE21: u32 = 513;
pub const R_AARCH64_TLSGD_ADD_LO12_NC: u32 = 514;
pub const R_AARCH64_TLSGD_MOVW_G1: u32 = 515;
pub const R_AARCH64_TLSGD_MOVW_G0_NC: u32 = 516;
pub const R_AARCH64_TLSLD_ADR_PREL21: u32 = 517;
pub const R_AARCH64_TLSLD_ADR_PAGE21: u32 = 518;
pub const R_AARCH64_TLSLD_ADD_LO12_NC: u32 = 519;
pub const R_AARCH64_TLSLD_MOVW_G1: u32 = 520;
pub const R_AARCH64_TLSLD_MOVW_G0_NC: u32 = 521;
pub const R_AARCH64_TLSLD_LD_PREL19: u32 = 522;
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G2: u32 = 523;
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G1: u32 = 524;
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC: u32 = 525;
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G0: u32 = 526;
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC: u32 = 527;
pub const R_AARCH64_TLSLD_ADD_DTPREL_HI12: u32 = 528;
pub const R_AARCH64_TLSLD_ADD_DTPREL_LO12: u32 = 529;
pub const R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC: u32 = 530;
pub const R_AARCH64_TLSLD_LDST8_DTPREL_LO12: u32 = 531;
pub const R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC: u32 = 532;
pub const R_AARCH64_TLSLD_LDST16_DTPREL_LO12: u32 = 533;
pub const R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC: u32 = 534;
pub const R_AARCH64_TLSLD_LDST32_DTPREL_LO12: u32 = 535;
pub const R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC: u32 = 536;
pub const R_AARCH64_TLSLD_LDST64_DTPREL_LO12: u32 = 537;
pub const R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC: u32 = 538;
pub const R_AARCH64_TLSIE_MOVW_GOTTPREL_G1: u32 = 539;
pub const R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC: u32 = 540;
pub const R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21: u32 = 541;
pub const R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC: u32 = 542;
pub const R_AARCH64_TLSIE_LD_GOTTPREL_PREL19: u32 = 543;
pub const R_AARCH64_TLSLE_MOVW_TPREL_G2: u32 = 544;
pub const R_AARCH64_TLSLE_MOVW_TPREL_G1: u32 = 545;
pub const R_AARCH64_TLSLE_MOVW_TPREL_G1_NC: u32 = 546;
pub const R_AARCH64_TLSLE_MOVW_TPREL_G0: u32 = 547;
pub const R_AARCH64_TLSLE_MOVW_TPREL_G0_NC: u32 = 548;
pub const R_AARCH64_TLSLE_ADD_TPREL_HI12: u32 = 549;
pub const R_AARCH64_TLSLE_ADD_TPREL_LO12: u32 = 550;
pub const R_AARCH64_TLSLE_ADD_TPREL_LO12_NC: u32 = 551;
pub const R_AARCH64_TLSLE_LDST8_TPREL_LO12: u32 = 552;
pub const R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC: u32 = 553;
pub const R_AARCH64_TLSLE_LDST16_TPREL_LO12: u32 = 554;
pub const R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC: u32 = 555;
pub const R_AARCH64_TLSLE_LDST32_TPREL_LO12: u32 = 556;
pub const R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC: u32 = 557;
pub const R_AARCH64_TLSLE_LDST64_TPREL_LO12: u32 = 558;
pub const R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC: u32 = 559;
pub const R_AARCH64_TLSDESC_LD_PREL19: u32 = 560;
pub const R_AARCH64_TLSDESC_ADR_PREL21: u32 = 561;
pub const R_AARCH64_TLSDESC_ADR_PAGE21: u32 = 562;
pub const R_AARCH64_TLSDESC_LD64_LO12: u32 = 563;
pub const R_AARCH64_TLSDESC_ADD_LO12: u32 = 564;
pub const R_AARCH64_TLSDESC_OFF_G1: u32 = 565;
pub const R_AARCH64_TLSDESC_OFF_G0_NC: u32 = 566;
pub const R_AARCH64_TLSDESC_LDR: u32 = 567;
pub const R_AARCH64_TLSDESC_ADD: u32 = 568;
pub const R_AARCH64_TLSDESC_CALL: u32 = 569;
pub const R_AARCH64_TLSLE_LDST128_TPREL_LO12: u32 = 570;
pub const R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC: u32 = 571;
pub const R_AARCH64_TLSLD_LDST128_DTPREL_LO12: u32 = 572;
pub const R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC: u32 = 573;
pub const R_AARCH64_COPY: u32 = 1024;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;
pub const R_AARCH64_TLS_DTPMOD: u32 = 1028;
pub const R_AARCH64_TLS_DTPREL: u32 = 1029;
pub const R_AARCH64_TLS_TPREL: u32 = 1030;
pub const R_AARCH64_TLSDESC: u32 = 1031;
pub const R_AARCH64_IRELATIVE: u32 = 1032;
pub const R_AARCH64_NUM: u32 = 1033;

// ---------------------------------------------------------------------------
// RISC-V Relocation Types (elf.h lines 3262-3321)
// ---------------------------------------------------------------------------
pub const R_RISCV_NONE: u32 = 0;
pub const R_RISCV_32: u32 = 1;
pub const R_RISCV_64: u32 = 2;
pub const R_RISCV_RELATIVE: u32 = 3;
pub const R_RISCV_COPY: u32 = 4;
pub const R_RISCV_JUMP_SLOT: u32 = 5;
pub const R_RISCV_TLS_DTPMOD32: u32 = 6;
pub const R_RISCV_TLS_DTPMOD64: u32 = 7;
pub const R_RISCV_TLS_DTPREL32: u32 = 8;
pub const R_RISCV_TLS_DTPREL64: u32 = 9;
pub const R_RISCV_TLS_TPREL32: u32 = 10;
pub const R_RISCV_TLS_TPREL64: u32 = 11;
pub const R_RISCV_BRANCH: u32 = 16;
pub const R_RISCV_JAL: u32 = 17;
pub const R_RISCV_CALL: u32 = 18;
pub const R_RISCV_CALL_PLT: u32 = 19;
pub const R_RISCV_GOT_HI20: u32 = 20;
pub const R_RISCV_TLS_GOT_HI20: u32 = 21;
pub const R_RISCV_TLS_GD_HI20: u32 = 22;
pub const R_RISCV_PCREL_HI20: u32 = 23;
pub const R_RISCV_PCREL_LO12_I: u32 = 24;
pub const R_RISCV_PCREL_LO12_S: u32 = 25;
pub const R_RISCV_HI20: u32 = 26;
pub const R_RISCV_LO12_I: u32 = 27;
pub const R_RISCV_LO12_S: u32 = 28;
pub const R_RISCV_TPREL_HI20: u32 = 29;
pub const R_RISCV_TPREL_LO12_I: u32 = 30;
pub const R_RISCV_TPREL_LO12_S: u32 = 31;
pub const R_RISCV_TPREL_ADD: u32 = 32;
pub const R_RISCV_ADD8: u32 = 33;
pub const R_RISCV_ADD16: u32 = 34;
pub const R_RISCV_ADD32: u32 = 35;
pub const R_RISCV_ADD64: u32 = 36;
pub const R_RISCV_SUB8: u32 = 37;
pub const R_RISCV_SUB16: u32 = 38;
pub const R_RISCV_SUB32: u32 = 39;
pub const R_RISCV_SUB64: u32 = 40;
pub const R_RISCV_GNU_VTINHERIT: u32 = 41;
pub const R_RISCV_GNU_VTENTRY: u32 = 42;
pub const R_RISCV_ALIGN: u32 = 43;
pub const R_RISCV_RVC_BRANCH: u32 = 44;
pub const R_RISCV_RVC_JUMP: u32 = 45;
pub const R_RISCV_RVC_LUI: u32 = 46;
pub const R_RISCV_GPREL_I: u32 = 47;
pub const R_RISCV_GPREL_S: u32 = 48;
pub const R_RISCV_TPREL_I: u32 = 49;
pub const R_RISCV_TPREL_S: u32 = 50;
pub const R_RISCV_RELAX: u32 = 51;
pub const R_RISCV_SUB6: u32 = 52;
pub const R_RISCV_SET6: u32 = 53;
pub const R_RISCV_SET8: u32 = 54;
pub const R_RISCV_SET16: u32 = 55;
pub const R_RISCV_SET32: u32 = 56;
pub const R_RISCV_32_PCREL: u32 = 57;
pub const R_RISCV_IRELATIVE: u32 = 58;
pub const R_RISCV_PLT32: u32 = 59;
pub const R_RISCV_SET_ULEB128: u32 = 60;
pub const R_RISCV_SUB_ULEB128: u32 = 61;
pub const R_RISCV_NUM: u32 = 62;

// ---------------------------------------------------------------------------
// RISC-V ELF Flags (elf.h lines 3243-3260)
// ---------------------------------------------------------------------------
pub const EF_RISCV_RVC: u32 = 0x0001;
pub const EF_RISCV_FLOAT_ABI: u32 = 0x0006;
pub const EF_RISCV_FLOAT_ABI_SOFT: u32 = 0x0000;
pub const EF_RISCV_FLOAT_ABI_SINGLE: u32 = 0x0002;
pub const EF_RISCV_FLOAT_ABI_DOUBLE: u32 = 0x0004;
pub const EF_RISCV_FLOAT_ABI_QUAD: u32 = 0x0006;

// ---------------------------------------------------------------------------
// TI C6000 Relocation Types (elf.h lines 2559-2572)
// ---------------------------------------------------------------------------
pub const R_C60_NONE: u32 = 0;
pub const R_C60_32: u32 = 1;
pub const R_C60_GOT32: u32 = 3;
pub const R_C60_PLT32: u32 = 4;
pub const R_C60_COPY: u32 = 5;
pub const R_C60_GLOB_DAT: u32 = 6;
pub const R_C60_JMP_SLOT: u32 = 7;
pub const R_C60_RELATIVE: u32 = 8;
pub const R_C60_GOTOFF: u32 = 9;
pub const R_C60_GOTPC: u32 = 10;
pub const R_C60HI16: u32 = 85;
pub const R_C60LO16: u32 = 84;
pub const R_C60_NUM: u32 = 86;

// ---------------------------------------------------------------------------
// ARM-Specific ELF Constants (elf.h)
// ---------------------------------------------------------------------------
pub const EF_ARM_RELEXEC: u32 = 0x01;
pub const EF_ARM_HASENTRY: u32 = 0x02;
pub const EF_ARM_INTERWORK: u32 = 0x04;
pub const EF_ARM_APCS_26: u32 = 0x08;
pub const EF_ARM_APCS_FLOAT: u32 = 0x10;
pub const EF_ARM_PIC: u32 = 0x20;
pub const EF_ARM_ALIGN8: u32 = 0x40;
pub const EF_ARM_NEW_ABI: u32 = 0x80;
pub const EF_ARM_OLD_ABI: u32 = 0x100;
pub const EF_ARM_SOFT_FLOAT: u32 = 0x200;
pub const EF_ARM_VFP_FLOAT: u32 = 0x400;
pub const EF_ARM_MAVERICK_FLOAT: u32 = 0x800;
pub const EF_ARM_ABI_FLOAT_HARD: u32 = 0x00000400;
pub const EF_ARM_ABI_FLOAT_SOFT: u32 = 0x00000200;

pub const EF_ARM_SYMSARESORTED: u32 = 0x04;
pub const EF_ARM_DYNSYMSUSESEGIDX: u32 = 0x08;
pub const EF_ARM_MAPSYMSFIRST: u32 = 0x10;
pub const EF_ARM_EABIMASK: u32 = 0xFF000000;

pub const EF_ARM_BE8: u32 = 0x00800000;
pub const EF_ARM_LE8: u32 = 0x00400000;

pub const EF_ARM_EABI_VER1: u32 = 0x01000000;
pub const EF_ARM_EABI_VER2: u32 = 0x02000000;
pub const EF_ARM_EABI_VER3: u32 = 0x03000000;
pub const EF_ARM_EABI_VER4: u32 = 0x04000000;
pub const EF_ARM_EABI_VER5: u32 = 0x05000000;

pub const STT_ARM_TFUNC: u8 = STT_LOPROC;
pub const STT_ARM_16BIT: u8 = STT_HIPROC;
pub const SHF_ARM_ENTRYSECT: u32 = 0x10000000;
pub const SHF_ARM_COMDEF: u32 = 0x80000000;
pub const PF_ARM_SB: u32 = 0x10000000;
pub const PF_ARM_PI: u32 = 0x20000000;
pub const PF_ARM_ABS: u32 = 0x40000000;
pub const PT_ARM_EXIDX: u32 = PT_LOPROC + 1;
pub const SHT_ARM_EXIDX: u32 = SHT_LOPROC + 1;
pub const SHT_ARM_PREEMPTMAP: u32 = SHT_LOPROC + 2;
pub const SHT_ARM_ATTRIBUTES: u32 = SHT_LOPROC + 3;

// ---------------------------------------------------------------------------
// MIPS ELF Constants (elf.h)
// ---------------------------------------------------------------------------
pub const EF_MIPS_NOREORDER: u32 = 1;
pub const EF_MIPS_PIC: u32 = 2;
pub const EF_MIPS_CPIC: u32 = 4;
pub const EF_MIPS_XGOT: u32 = 8;
pub const EF_MIPS_64BIT_WHIRL: u32 = 16;
pub const EF_MIPS_ABI2: u32 = 32;
pub const EF_MIPS_ABI_ON32: u32 = 64;
pub const EF_MIPS_ARCH: u32 = 0xf0000000;
pub const EF_MIPS_ARCH_1: u32 = 0x00000000;
pub const EF_MIPS_ARCH_2: u32 = 0x10000000;
pub const EF_MIPS_ARCH_3: u32 = 0x20000000;
pub const EF_MIPS_ARCH_4: u32 = 0x30000000;
pub const EF_MIPS_ARCH_5: u32 = 0x40000000;
pub const EF_MIPS_ARCH_32: u32 = 0x50000000;
pub const EF_MIPS_ARCH_64: u32 = 0x60000000;
pub const EF_MIPS_ARCH_32R2: u32 = 0x70000000;
pub const EF_MIPS_ARCH_64R2: u32 = 0x80000000;

// MIPS Relocation Types
pub const R_MIPS_NONE: u32 = 0;
pub const R_MIPS_16: u32 = 1;
pub const R_MIPS_32: u32 = 2;
pub const R_MIPS_REL32: u32 = 3;
pub const R_MIPS_26: u32 = 4;
pub const R_MIPS_HI16: u32 = 5;
pub const R_MIPS_LO16: u32 = 6;
pub const R_MIPS_GPREL16: u32 = 7;
pub const R_MIPS_LITERAL: u32 = 8;
pub const R_MIPS_GOT16: u32 = 9;
pub const R_MIPS_PC16: u32 = 10;
pub const R_MIPS_CALL16: u32 = 11;
pub const R_MIPS_GPREL32: u32 = 12;
pub const R_MIPS_SHIFT5: u32 = 16;
pub const R_MIPS_SHIFT6: u32 = 17;
pub const R_MIPS_64: u32 = 18;
pub const R_MIPS_GOT_DISP: u32 = 19;
pub const R_MIPS_GOT_PAGE: u32 = 20;
pub const R_MIPS_GOT_OFST: u32 = 21;
pub const R_MIPS_GOT_HI16: u32 = 22;
pub const R_MIPS_GOT_LO16: u32 = 23;
pub const R_MIPS_SUB: u32 = 24;
pub const R_MIPS_INSERT_A: u32 = 25;
pub const R_MIPS_INSERT_B: u32 = 26;
pub const R_MIPS_DELETE: u32 = 27;
pub const R_MIPS_HIGHER: u32 = 28;
pub const R_MIPS_HIGHEST: u32 = 29;
pub const R_MIPS_CALL_HI16: u32 = 30;
pub const R_MIPS_CALL_LO16: u32 = 31;
pub const R_MIPS_SCN_DISP: u32 = 32;
pub const R_MIPS_REL16: u32 = 33;
pub const R_MIPS_ADD_IMMEDIATE: u32 = 34;
pub const R_MIPS_PJUMP: u32 = 35;
pub const R_MIPS_RELGOT: u32 = 36;
pub const R_MIPS_JALR: u32 = 37;
pub const R_MIPS_TLS_DTPMOD32: u32 = 38;
pub const R_MIPS_TLS_DTPREL32: u32 = 39;
pub const R_MIPS_TLS_DTPMOD64: u32 = 40;
pub const R_MIPS_TLS_DTPREL64: u32 = 41;
pub const R_MIPS_TLS_GD: u32 = 42;
pub const R_MIPS_TLS_LDM: u32 = 43;
pub const R_MIPS_TLS_DTPREL_HI16: u32 = 44;
pub const R_MIPS_TLS_DTPREL_LO16: u32 = 45;
pub const R_MIPS_TLS_GOTTPREL: u32 = 46;
pub const R_MIPS_TLS_TPREL32: u32 = 47;
pub const R_MIPS_TLS_TPREL64: u32 = 48;
pub const R_MIPS_TLS_TPREL_HI16: u32 = 49;
pub const R_MIPS_TLS_TPREL_LO16: u32 = 50;
pub const R_MIPS_GLOB_DAT: u32 = 51;
pub const R_MIPS_COPY: u32 = 126;
pub const R_MIPS_JUMP_SLOT: u32 = 127;
pub const R_MIPS_NUM: u32 = 128;

// SPARC Relocation Types (subset)
pub const R_SPARC_NONE: u32 = 0;
pub const R_SPARC_8: u32 = 1;
pub const R_SPARC_16: u32 = 2;
pub const R_SPARC_32: u32 = 3;
pub const R_SPARC_DISP8: u32 = 4;
pub const R_SPARC_DISP16: u32 = 5;
pub const R_SPARC_DISP32: u32 = 6;
pub const R_SPARC_WDISP30: u32 = 7;
pub const R_SPARC_WDISP22: u32 = 8;
pub const R_SPARC_HI22: u32 = 9;
pub const R_SPARC_22: u32 = 10;
pub const R_SPARC_13: u32 = 11;
pub const R_SPARC_LO10: u32 = 12;
pub const R_SPARC_GOT10: u32 = 13;
pub const R_SPARC_GOT13: u32 = 14;
pub const R_SPARC_GOT22: u32 = 15;
pub const R_SPARC_PC10: u32 = 16;
pub const R_SPARC_PC22: u32 = 17;
pub const R_SPARC_WPLT30: u32 = 18;
pub const R_SPARC_COPY: u32 = 19;
pub const R_SPARC_GLOB_DAT: u32 = 20;
pub const R_SPARC_JMP_SLOT: u32 = 21;
pub const R_SPARC_RELATIVE: u32 = 22;
pub const R_SPARC_UA32: u32 = 23;
pub const R_SPARC_PLT32: u32 = 24;
pub const R_SPARC_HIPLT22: u32 = 25;
pub const R_SPARC_LOPLT10: u32 = 26;
pub const R_SPARC_PCPLT32: u32 = 27;
pub const R_SPARC_PCPLT22: u32 = 28;
pub const R_SPARC_PCPLT10: u32 = 29;
pub const R_SPARC_10: u32 = 30;
pub const R_SPARC_11: u32 = 31;
pub const R_SPARC_64: u32 = 32;
pub const R_SPARC_OLO10: u32 = 33;
pub const R_SPARC_HH22: u32 = 34;
pub const R_SPARC_HM10: u32 = 35;
pub const R_SPARC_LM22: u32 = 36;
pub const R_SPARC_PC_HH22: u32 = 37;
pub const R_SPARC_PC_HM10: u32 = 38;
pub const R_SPARC_PC_LM22: u32 = 39;
pub const R_SPARC_WDISP16: u32 = 40;
pub const R_SPARC_WDISP19: u32 = 41;
pub const R_SPARC_7: u32 = 43;
pub const R_SPARC_5: u32 = 44;
pub const R_SPARC_6: u32 = 45;
pub const R_SPARC_GOTDATA_HIX22: u32 = 80;
pub const R_SPARC_GOTDATA_LOX10: u32 = 81;
pub const R_SPARC_GOTDATA_OP_HIX22: u32 = 82;
pub const R_SPARC_GOTDATA_OP_LOX10: u32 = 83;
pub const R_SPARC_GOTDATA_OP: u32 = 84;
pub const R_SPARC_GNU_VTINHERIT: u32 = 250;
pub const R_SPARC_GNU_VTENTRY: u32 = 251;
pub const R_SPARC_REV32: u32 = 252;
pub const R_SPARC_NUM: u32 = 253;

// ---------------------------------------------------------------------------
// PowerPC Relocation Types (elf.h lines 1308+)
// ---------------------------------------------------------------------------
pub const R_PPC_NONE: u32 = 0;
pub const R_PPC_ADDR32: u32 = 1;
pub const R_PPC_ADDR24: u32 = 2;
pub const R_PPC_ADDR16: u32 = 3;
pub const R_PPC_ADDR16_LO: u32 = 4;
pub const R_PPC_ADDR16_HI: u32 = 5;
pub const R_PPC_ADDR16_HA: u32 = 6;
pub const R_PPC_ADDR14: u32 = 7;
pub const R_PPC_ADDR14_BRTAKEN: u32 = 8;
pub const R_PPC_ADDR14_BRNTAKEN: u32 = 9;
pub const R_PPC_REL24: u32 = 10;
pub const R_PPC_REL14: u32 = 11;
pub const R_PPC_REL14_BRTAKEN: u32 = 12;
pub const R_PPC_REL14_BRNTAKEN: u32 = 13;
pub const R_PPC_GOT16: u32 = 14;
pub const R_PPC_GOT16_LO: u32 = 15;
pub const R_PPC_GOT16_HI: u32 = 16;
pub const R_PPC_GOT16_HA: u32 = 17;
pub const R_PPC_PLTREL24: u32 = 18;
pub const R_PPC_COPY: u32 = 19;
pub const R_PPC_GLOB_DAT: u32 = 20;
pub const R_PPC_JMP_SLOT: u32 = 21;
pub const R_PPC_RELATIVE: u32 = 22;
pub const R_PPC_LOCAL24PC: u32 = 23;
pub const R_PPC_UADDR32: u32 = 24;
pub const R_PPC_UADDR16: u32 = 25;
pub const R_PPC_REL32: u32 = 26;
pub const R_PPC_PLT32: u32 = 27;
pub const R_PPC_PLTREL32: u32 = 28;
pub const R_PPC_PLT16_LO: u32 = 29;
pub const R_PPC_PLT16_HI: u32 = 30;
pub const R_PPC_PLT16_HA: u32 = 31;
pub const R_PPC_SDAREL16: u32 = 32;
pub const R_PPC_SECTOFF: u32 = 33;
pub const R_PPC_SECTOFF_LO: u32 = 34;
pub const R_PPC_SECTOFF_HI: u32 = 35;
pub const R_PPC_SECTOFF_HA: u32 = 36;
pub const R_PPC_TLS: u32 = 67;
pub const R_PPC_DTPMOD32: u32 = 68;
pub const R_PPC_TPREL16: u32 = 69;
pub const R_PPC_TPREL16_LO: u32 = 70;
pub const R_PPC_TPREL16_HI: u32 = 71;
pub const R_PPC_TPREL16_HA: u32 = 72;
pub const R_PPC_TPREL32: u32 = 73;
pub const R_PPC_DTPREL16: u32 = 74;
pub const R_PPC_DTPREL16_LO: u32 = 75;
pub const R_PPC_DTPREL16_HI: u32 = 76;
pub const R_PPC_DTPREL16_HA: u32 = 77;
pub const R_PPC_DTPREL32: u32 = 78;
pub const R_PPC_GOT_TLSGD16: u32 = 79;
pub const R_PPC_GOT_TLSGD16_LO: u32 = 80;
pub const R_PPC_GOT_TLSGD16_HI: u32 = 81;
pub const R_PPC_GOT_TLSGD16_HA: u32 = 82;
pub const R_PPC_GOT_TLSLD16: u32 = 83;
pub const R_PPC_GOT_TLSLD16_LO: u32 = 84;
pub const R_PPC_GOT_TLSLD16_HI: u32 = 85;
pub const R_PPC_GOT_TLSLD16_HA: u32 = 86;
pub const R_PPC_GOT_TPREL16: u32 = 87;
pub const R_PPC_GOT_TPREL16_LO: u32 = 88;
pub const R_PPC_GOT_TPREL16_HI: u32 = 89;
pub const R_PPC_GOT_TPREL16_HA: u32 = 90;
pub const R_PPC_GOT_DTPREL16: u32 = 91;
pub const R_PPC_GOT_DTPREL16_LO: u32 = 92;
pub const R_PPC_GOT_DTPREL16_HI: u32 = 93;
pub const R_PPC_GOT_DTPREL16_HA: u32 = 94;
pub const R_PPC_TLSGD: u32 = 95;
pub const R_PPC_TLSLD: u32 = 96;
pub const R_PPC_EMB_NADDR32: u32 = 101;
pub const R_PPC_EMB_NADDR16: u32 = 102;
pub const R_PPC_EMB_NADDR16_LO: u32 = 103;
pub const R_PPC_EMB_NADDR16_HI: u32 = 104;
pub const R_PPC_EMB_NADDR16_HA: u32 = 105;
pub const R_PPC_EMB_SDAI16: u32 = 106;
pub const R_PPC_EMB_SDA2I16: u32 = 107;
pub const R_PPC_EMB_SDA2REL: u32 = 108;
pub const R_PPC_EMB_SDA21: u32 = 109;
pub const R_PPC_EMB_MRKREF: u32 = 110;
pub const R_PPC_EMB_RELSEC16: u32 = 111;
pub const R_PPC_EMB_RELST_LO: u32 = 112;
pub const R_PPC_EMB_RELST_HI: u32 = 113;
pub const R_PPC_EMB_RELST_HA: u32 = 114;
pub const R_PPC_EMB_BIT_FLD: u32 = 115;
pub const R_PPC_EMB_RELSDA: u32 = 116;
pub const R_PPC_DIAB_SDA21_LO: u32 = 180;
pub const R_PPC_DIAB_SDA21_HI: u32 = 181;
pub const R_PPC_DIAB_SDA21_HA: u32 = 182;
pub const R_PPC_DIAB_RELSDA_LO: u32 = 183;
pub const R_PPC_DIAB_RELSDA_HI: u32 = 184;
pub const R_PPC_DIAB_RELSDA_HA: u32 = 185;
pub const R_PPC_IRELATIVE: u32 = 248;
pub const R_PPC_REL16: u32 = 249;
pub const R_PPC_REL16_LO: u32 = 250;
pub const R_PPC_REL16_HI: u32 = 251;
pub const R_PPC_REL16_HA: u32 = 252;
pub const R_PPC_TOC16: u32 = 255;
pub const R_PPC_NUM: u32 = 256;

// PowerPC-specific DT values
pub const DT_PPC_GOT: u32 = 0x70000000;
pub const DT_PPC_NUM: u32 = 1;

// ---------------------------------------------------------------------------
// PowerPC64 Relocation Types (elf.h lines 1620+)
// ---------------------------------------------------------------------------
pub const R_PPC64_NONE: u32 = 0;
pub const R_PPC64_ADDR32: u32 = 1;
pub const R_PPC64_ADDR24: u32 = 2;
pub const R_PPC64_ADDR16: u32 = 3;
pub const R_PPC64_ADDR16_LO: u32 = 4;
pub const R_PPC64_ADDR16_HI: u32 = 5;
pub const R_PPC64_ADDR16_HA: u32 = 6;
pub const R_PPC64_ADDR14: u32 = 7;
pub const R_PPC64_ADDR14_BRTAKEN: u32 = 8;
pub const R_PPC64_ADDR14_BRNTAKEN: u32 = 9;
pub const R_PPC64_REL24: u32 = 10;
pub const R_PPC64_REL14: u32 = 11;
pub const R_PPC64_REL14_BRTAKEN: u32 = 12;
pub const R_PPC64_REL14_BRNTAKEN: u32 = 13;
pub const R_PPC64_GOT16: u32 = 14;
pub const R_PPC64_GOT16_LO: u32 = 15;
pub const R_PPC64_GOT16_HI: u32 = 16;
pub const R_PPC64_GOT16_HA: u32 = 17;
pub const R_PPC64_COPY: u32 = 19;
pub const R_PPC64_GLOB_DAT: u32 = 20;
pub const R_PPC64_JMP_SLOT: u32 = 21;
pub const R_PPC64_RELATIVE: u32 = 22;
pub const R_PPC64_UADDR32: u32 = 24;
pub const R_PPC64_UADDR16: u32 = 25;
pub const R_PPC64_REL32: u32 = 26;
pub const R_PPC64_PLT32: u32 = 27;
pub const R_PPC64_PLTREL32: u32 = 28;
pub const R_PPC64_PLT16_LO: u32 = 29;
pub const R_PPC64_PLT16_HI: u32 = 30;
pub const R_PPC64_PLT16_HA: u32 = 31;
pub const R_PPC64_SECTOFF: u32 = 33;
pub const R_PPC64_SECTOFF_LO: u32 = 34;
pub const R_PPC64_SECTOFF_HI: u32 = 35;
pub const R_PPC64_SECTOFF_HA: u32 = 36;
pub const R_PPC64_ADDR30: u32 = 37;
pub const R_PPC64_ADDR64: u32 = 38;
pub const R_PPC64_ADDR16_HIGHER: u32 = 39;
pub const R_PPC64_ADDR16_HIGHERA: u32 = 40;
pub const R_PPC64_ADDR16_HIGHEST: u32 = 41;
pub const R_PPC64_ADDR16_HIGHESTA: u32 = 42;
pub const R_PPC64_UADDR64: u32 = 43;
pub const R_PPC64_REL64: u32 = 44;
pub const R_PPC64_PLT64: u32 = 45;
pub const R_PPC64_PLTREL64: u32 = 46;
pub const R_PPC64_TOC16: u32 = 47;
pub const R_PPC64_TOC16_LO: u32 = 48;
pub const R_PPC64_TOC16_HI: u32 = 49;
pub const R_PPC64_TOC16_HA: u32 = 50;
pub const R_PPC64_TOC: u32 = 51;
pub const R_PPC64_PLTGOT16: u32 = 52;
pub const R_PPC64_PLTGOT16_LO: u32 = 53;
pub const R_PPC64_PLTGOT16_HI: u32 = 54;
pub const R_PPC64_PLTGOT16_HA: u32 = 55;
pub const R_PPC64_ADDR16_DS: u32 = 56;
pub const R_PPC64_ADDR16_LO_DS: u32 = 57;
pub const R_PPC64_GOT16_DS: u32 = 58;
pub const R_PPC64_GOT16_LO_DS: u32 = 59;
pub const R_PPC64_PLT16_LO_DS: u32 = 60;
pub const R_PPC64_SECTOFF_DS: u32 = 61;
pub const R_PPC64_SECTOFF_LO_DS: u32 = 62;
pub const R_PPC64_TOC16_DS: u32 = 63;
pub const R_PPC64_TOC16_LO_DS: u32 = 64;
pub const R_PPC64_PLTGOT16_DS: u32 = 65;
pub const R_PPC64_PLTGOT16_LO_DS: u32 = 66;
pub const R_PPC64_TLS: u32 = 67;
pub const R_PPC64_DTPMOD64: u32 = 68;
pub const R_PPC64_TPREL16: u32 = 69;
pub const R_PPC64_TPREL16_LO: u32 = 70;
pub const R_PPC64_TPREL16_HI: u32 = 71;
pub const R_PPC64_TPREL16_HA: u32 = 72;
pub const R_PPC64_TPREL64: u32 = 73;
pub const R_PPC64_DTPREL16: u32 = 74;
pub const R_PPC64_DTPREL16_LO: u32 = 75;
pub const R_PPC64_DTPREL16_HI: u32 = 76;
pub const R_PPC64_DTPREL16_HA: u32 = 77;
pub const R_PPC64_DTPREL64: u32 = 78;
pub const R_PPC64_GOT_TLSGD16: u32 = 79;
pub const R_PPC64_GOT_TLSGD16_LO: u32 = 80;
pub const R_PPC64_GOT_TLSGD16_HI: u32 = 81;
pub const R_PPC64_GOT_TLSGD16_HA: u32 = 82;
pub const R_PPC64_GOT_TLSLD16: u32 = 83;
pub const R_PPC64_GOT_TLSLD16_LO: u32 = 84;
pub const R_PPC64_GOT_TLSLD16_HI: u32 = 85;
pub const R_PPC64_GOT_TLSLD16_HA: u32 = 86;
pub const R_PPC64_GOT_TPREL16_DS: u32 = 87;
pub const R_PPC64_GOT_TPREL16_LO_DS: u32 = 88;
pub const R_PPC64_GOT_TPREL16_HI: u32 = 89;
pub const R_PPC64_GOT_TPREL16_HA: u32 = 90;
pub const R_PPC64_GOT_DTPREL16_DS: u32 = 91;
pub const R_PPC64_GOT_DTPREL16_LO_DS: u32 = 92;
pub const R_PPC64_GOT_DTPREL16_HI: u32 = 93;
pub const R_PPC64_GOT_DTPREL16_HA: u32 = 94;
pub const R_PPC64_TPREL16_DS: u32 = 95;
pub const R_PPC64_TPREL16_LO_DS: u32 = 96;
pub const R_PPC64_TPREL16_HIGHER: u32 = 97;
pub const R_PPC64_TPREL16_HIGHERA: u32 = 98;
pub const R_PPC64_TPREL16_HIGHEST: u32 = 99;
pub const R_PPC64_TPREL16_HIGHESTA: u32 = 100;
pub const R_PPC64_DTPREL16_DS: u32 = 101;
pub const R_PPC64_DTPREL16_LO_DS: u32 = 102;
pub const R_PPC64_DTPREL16_HIGHER: u32 = 103;
pub const R_PPC64_DTPREL16_HIGHERA: u32 = 104;
pub const R_PPC64_DTPREL16_HIGHEST: u32 = 105;
pub const R_PPC64_DTPREL16_HIGHESTA: u32 = 106;
pub const R_PPC64_TLSGD: u32 = 107;
pub const R_PPC64_TLSLD: u32 = 108;
pub const R_PPC64_TOCSAVE: u32 = 109;
pub const R_PPC64_ADDR16_HIGH: u32 = 110;
pub const R_PPC64_ADDR16_HIGHA: u32 = 111;
pub const R_PPC64_TPREL16_HIGH: u32 = 112;
pub const R_PPC64_TPREL16_HIGHA: u32 = 113;
pub const R_PPC64_DTPREL16_HIGH: u32 = 114;
pub const R_PPC64_DTPREL16_HIGHA: u32 = 115;
pub const R_PPC64_JMP_IREL: u32 = 247;
pub const R_PPC64_IRELATIVE: u32 = 248;
pub const R_PPC64_REL16: u32 = 249;
pub const R_PPC64_REL16_LO: u32 = 250;
pub const R_PPC64_REL16_HI: u32 = 251;
pub const R_PPC64_REL16_HA: u32 = 252;
pub const R_PPC64_NUM: u32 = 253;

// PPC64-specific DT values
pub const DT_PPC64_GLINK: u32 = 0x70000000;
pub const DT_PPC64_OPD: u32 = 0x70000001;
pub const DT_PPC64_OPDSZ: u32 = 0x70000002;
pub const DT_PPC64_NUM: u32 = 3;

pub const EF_PPC64_ABI: u32 = 3;

// ---------------------------------------------------------------------------
// S/390 Relocation Types (elf.h lines 2800-2870)
// ---------------------------------------------------------------------------
pub const R_390_NONE: u32 = 0;
pub const R_390_8: u32 = 1;
pub const R_390_12: u32 = 2;
pub const R_390_16: u32 = 3;
pub const R_390_32: u32 = 4;
pub const R_390_PC32: u32 = 5;
pub const R_390_GOT12: u32 = 6;
pub const R_390_GOT32: u32 = 7;
pub const R_390_PLT32: u32 = 8;
pub const R_390_COPY: u32 = 9;
pub const R_390_GLOB_DAT: u32 = 10;
pub const R_390_JMP_SLOT: u32 = 11;
pub const R_390_RELATIVE: u32 = 12;
pub const R_390_GOTOFF32: u32 = 13;
pub const R_390_GOTPC: u32 = 14;
pub const R_390_GOT16: u32 = 15;
pub const R_390_PC16: u32 = 16;
pub const R_390_PC16DBL: u32 = 17;
pub const R_390_PLT16DBL: u32 = 18;
pub const R_390_PC32DBL: u32 = 19;
pub const R_390_PLT32DBL: u32 = 20;
pub const R_390_GOTPCDBL: u32 = 21;
pub const R_390_64: u32 = 22;
pub const R_390_PC64: u32 = 23;
pub const R_390_GOT64: u32 = 24;
pub const R_390_PLT64: u32 = 25;
pub const R_390_GOTENT: u32 = 26;
pub const R_390_GOTOFF16: u32 = 27;
pub const R_390_GOTOFF64: u32 = 28;
pub const R_390_GOTPLT12: u32 = 29;
pub const R_390_GOTPLT16: u32 = 30;
pub const R_390_GOTPLT32: u32 = 31;
pub const R_390_GOTPLT64: u32 = 32;
pub const R_390_GOTPLTENT: u32 = 33;
pub const R_390_PLTOFF16: u32 = 34;
pub const R_390_PLTOFF32: u32 = 35;
pub const R_390_PLTOFF64: u32 = 36;
pub const R_390_TLS_LOAD: u32 = 37;
pub const R_390_TLS_GDCALL: u32 = 38;
pub const R_390_TLS_LDCALL: u32 = 39;
pub const R_390_TLS_GD32: u32 = 40;
pub const R_390_TLS_GD64: u32 = 41;
pub const R_390_TLS_GOTIE12: u32 = 42;
pub const R_390_TLS_GOTIE32: u32 = 43;
pub const R_390_TLS_GOTIE64: u32 = 44;
pub const R_390_TLS_LDM32: u32 = 45;
pub const R_390_TLS_LDM64: u32 = 46;
pub const R_390_TLS_IE32: u32 = 47;
pub const R_390_TLS_IE64: u32 = 48;
pub const R_390_TLS_IEENT: u32 = 49;
pub const R_390_TLS_LE32: u32 = 50;
pub const R_390_TLS_LE64: u32 = 51;
pub const R_390_TLS_LDO32: u32 = 52;
pub const R_390_TLS_LDO64: u32 = 53;
pub const R_390_TLS_DTPMOD: u32 = 54;
pub const R_390_TLS_DTPOFF: u32 = 55;
pub const R_390_TLS_TPOFF: u32 = 56;
pub const R_390_20: u32 = 57;
pub const R_390_GOT20: u32 = 58;
pub const R_390_GOTPLT20: u32 = 59;
pub const R_390_TLS_GOTIE20: u32 = 60;
pub const R_390_IRELATIVE: u32 = 61;
pub const R_390_NUM: u32 = 62;

// ---------------------------------------------------------------------------
// CRIS Relocation Types (elf.h)
// ---------------------------------------------------------------------------
pub const R_CRIS_NONE: u32 = 0;
pub const R_CRIS_8: u32 = 1;
pub const R_CRIS_16: u32 = 2;
pub const R_CRIS_32: u32 = 3;
pub const R_CRIS_8_PCREL: u32 = 4;
pub const R_CRIS_16_PCREL: u32 = 5;
pub const R_CRIS_32_PCREL: u32 = 6;
pub const R_CRIS_GNU_VTINHERIT: u32 = 7;
pub const R_CRIS_GNU_VTENTRY: u32 = 8;
pub const R_CRIS_COPY: u32 = 9;
pub const R_CRIS_GLOB_DAT: u32 = 10;
pub const R_CRIS_JUMP_SLOT: u32 = 11;
pub const R_CRIS_RELATIVE: u32 = 12;
pub const R_CRIS_16_GOT: u32 = 13;
pub const R_CRIS_32_GOT: u32 = 14;
pub const R_CRIS_16_GOTPLT: u32 = 15;
pub const R_CRIS_32_GOTPLT: u32 = 16;
pub const R_CRIS_32_GOTREL: u32 = 17;
pub const R_CRIS_32_PLT_GOTREL: u32 = 18;
pub const R_CRIS_32_PLT_PCREL: u32 = 19;
pub const R_CRIS_NUM: u32 = 20;

// ---------------------------------------------------------------------------
// SH Relocation Types (elf.h)
// ---------------------------------------------------------------------------
pub const R_SH_NONE: u32 = 0;
pub const R_SH_DIR32: u32 = 1;
pub const R_SH_REL32: u32 = 2;
pub const R_SH_DIR8WPN: u32 = 3;
pub const R_SH_IND12W: u32 = 4;
pub const R_SH_DIR8WPL: u32 = 5;
pub const R_SH_DIR8WPZ: u32 = 6;
pub const R_SH_DIR8BP: u32 = 7;
pub const R_SH_DIR8W: u32 = 8;
pub const R_SH_DIR8L: u32 = 9;
pub const R_SH_SWITCH16: u32 = 25;
pub const R_SH_SWITCH32: u32 = 26;
pub const R_SH_USES: u32 = 27;
pub const R_SH_COUNT: u32 = 28;
pub const R_SH_ALIGN: u32 = 29;
pub const R_SH_CODE: u32 = 30;
pub const R_SH_DATA: u32 = 31;
pub const R_SH_LABEL: u32 = 32;
pub const R_SH_SWITCH8: u32 = 33;
pub const R_SH_GNU_VTINHERIT: u32 = 34;
pub const R_SH_GNU_VTENTRY: u32 = 35;
pub const R_SH_TLS_GD_32: u32 = 144;
pub const R_SH_TLS_LD_32: u32 = 145;
pub const R_SH_TLS_LDO_32: u32 = 146;
pub const R_SH_TLS_IE_32: u32 = 147;
pub const R_SH_TLS_LE_32: u32 = 148;
pub const R_SH_TLS_DTPMOD32: u32 = 149;
pub const R_SH_TLS_DTPOFF32: u32 = 150;
pub const R_SH_TLS_TPOFF32: u32 = 151;
pub const R_SH_GOT32: u32 = 160;
pub const R_SH_PLT32: u32 = 161;
pub const R_SH_COPY: u32 = 162;
pub const R_SH_GLOB_DAT: u32 = 163;
pub const R_SH_JMP_SLOT: u32 = 164;
pub const R_SH_RELATIVE: u32 = 165;
pub const R_SH_GOTOFF: u32 = 166;
pub const R_SH_GOTPC: u32 = 167;
pub const R_SH_NUM: u32 = 256;

// ---------------------------------------------------------------------------
// IA-64 Relocation Types (elf.h)
// ---------------------------------------------------------------------------
pub const R_IA64_NONE: u32 = 0;
pub const R_IA64_IMM14: u32 = 33;
pub const R_IA64_IMM22: u32 = 34;
pub const R_IA64_IMM64: u32 = 35;
pub const R_IA64_DIR32MSB: u32 = 36;
pub const R_IA64_DIR32LSB: u32 = 37;
pub const R_IA64_DIR64MSB: u32 = 38;
pub const R_IA64_DIR64LSB: u32 = 39;
pub const R_IA64_GPREL22: u32 = 42;
pub const R_IA64_GPREL64I: u32 = 43;
pub const R_IA64_GPREL32MSB: u32 = 44;
pub const R_IA64_GPREL32LSB: u32 = 45;
pub const R_IA64_GPREL64MSB: u32 = 46;
pub const R_IA64_GPREL64LSB: u32 = 47;
pub const R_IA64_LTOFF22: u32 = 50;
pub const R_IA64_LTOFF64I: u32 = 51;
pub const R_IA64_PLTREL22: u32 = 58;
pub const R_IA64_PLTREL64I: u32 = 59;
pub const R_IA64_PLTREL64MSB: u32 = 62;
pub const R_IA64_PLTREL64LSB: u32 = 63;
pub const R_IA64_FPTR64I: u32 = 67;
pub const R_IA64_FPTR32MSB: u32 = 68;
pub const R_IA64_FPTR32LSB: u32 = 69;
pub const R_IA64_FPTR64MSB: u32 = 70;
pub const R_IA64_FPTR64LSB: u32 = 71;
pub const R_IA64_PCREL21B: u32 = 73;
pub const R_IA64_PCREL21M: u32 = 74;
pub const R_IA64_PCREL21F: u32 = 75;
pub const R_IA64_PCREL32MSB: u32 = 76;
pub const R_IA64_PCREL32LSB: u32 = 77;
pub const R_IA64_PCREL64MSB: u32 = 78;
pub const R_IA64_PCREL64LSB: u32 = 79;
pub const R_IA64_LTOFF_FPTR22: u32 = 82;
pub const R_IA64_LTOFF_FPTR64I: u32 = 83;
pub const R_IA64_LTOFF_FPTR32MSB: u32 = 84;
pub const R_IA64_LTOFF_FPTR32LSB: u32 = 85;
pub const R_IA64_LTOFF_FPTR64MSB: u32 = 86;
pub const R_IA64_LTOFF_FPTR64LSB: u32 = 87;
pub const R_IA64_SEGREL32MSB: u32 = 92;
pub const R_IA64_SEGREL32LSB: u32 = 93;
pub const R_IA64_SEGREL64MSB: u32 = 94;
pub const R_IA64_SEGREL64LSB: u32 = 95;
pub const R_IA64_SECREL32MSB: u32 = 100;
pub const R_IA64_SECREL32LSB: u32 = 101;
pub const R_IA64_SECREL64MSB: u32 = 102;
pub const R_IA64_SECREL64LSB: u32 = 103;
pub const R_IA64_REL32MSB: u32 = 108;
pub const R_IA64_REL32LSB: u32 = 109;
pub const R_IA64_REL64MSB: u32 = 110;
pub const R_IA64_REL64LSB: u32 = 111;
pub const R_IA64_LTV32MSB: u32 = 116;
pub const R_IA64_LTV32LSB: u32 = 117;
pub const R_IA64_LTV64MSB: u32 = 118;
pub const R_IA64_LTV64LSB: u32 = 119;
pub const R_IA64_PCREL21BI: u32 = 121;
pub const R_IA64_PCREL22: u32 = 122;
pub const R_IA64_PCREL64I: u32 = 123;
pub const R_IA64_IPLTMSB: u32 = 128;
pub const R_IA64_IPLTLSB: u32 = 129;
pub const R_IA64_COPY: u32 = 132;
pub const R_IA64_SUB: u32 = 133;
pub const R_IA64_LTOFF22X: u32 = 134;
pub const R_IA64_LDXMOV: u32 = 135;
pub const R_IA64_TPREL14: u32 = 145;
pub const R_IA64_TPREL22: u32 = 146;
pub const R_IA64_TPREL64I: u32 = 147;
pub const R_IA64_TPREL64MSB: u32 = 150;
pub const R_IA64_TPREL64LSB: u32 = 151;
pub const R_IA64_LTOFF_TPREL22: u32 = 154;
pub const R_IA64_DTPMOD64MSB: u32 = 166;
pub const R_IA64_DTPMOD64LSB: u32 = 167;
pub const R_IA64_LTOFF_DTPMOD22: u32 = 170;
pub const R_IA64_DTPREL14: u32 = 177;
pub const R_IA64_DTPREL22: u32 = 178;
pub const R_IA64_DTPREL64I: u32 = 179;
pub const R_IA64_DTPREL32MSB: u32 = 180;
pub const R_IA64_DTPREL32LSB: u32 = 181;
pub const R_IA64_DTPREL64MSB: u32 = 182;
pub const R_IA64_DTPREL64LSB: u32 = 183;
pub const R_IA64_LTOFF_DTPREL22: u32 = 186;

// ---------------------------------------------------------------------------
// M32R Relocation Types (elf.h)
// ---------------------------------------------------------------------------
pub const R_M32R_NONE: u32 = 0;
pub const R_M32R_16: u32 = 1;
pub const R_M32R_32: u32 = 2;
pub const R_M32R_24: u32 = 3;
pub const R_M32R_10_PCREL: u32 = 4;
pub const R_M32R_18_PCREL: u32 = 5;
pub const R_M32R_26_PCREL: u32 = 6;
pub const R_M32R_HI16_ULO: u32 = 7;
pub const R_M32R_HI16_SLO: u32 = 8;
pub const R_M32R_LO16: u32 = 9;
pub const R_M32R_SDA16: u32 = 10;
pub const R_M32R_GNU_VTINHERIT: u32 = 11;
pub const R_M32R_GNU_VTENTRY: u32 = 12;
pub const R_M32R_16_RELA: u32 = 33;
pub const R_M32R_32_RELA: u32 = 34;
pub const R_M32R_24_RELA: u32 = 35;
pub const R_M32R_10_PCREL_RELA: u32 = 36;
pub const R_M32R_18_PCREL_RELA: u32 = 37;
pub const R_M32R_26_PCREL_RELA: u32 = 38;
pub const R_M32R_HI16_ULO_RELA: u32 = 39;
pub const R_M32R_HI16_SLO_RELA: u32 = 40;
pub const R_M32R_LO16_RELA: u32 = 41;
pub const R_M32R_SDA16_RELA: u32 = 42;
pub const R_M32R_RELA_GNU_VTINHERIT: u32 = 43;
pub const R_M32R_RELA_GNU_VTENTRY: u32 = 44;
pub const R_M32R_REL32: u32 = 45;
pub const R_M32R_GOT24: u32 = 48;
pub const R_M32R_26_PLTREL: u32 = 49;
pub const R_M32R_COPY: u32 = 50;
pub const R_M32R_GLOB_DAT: u32 = 51;
pub const R_M32R_JMP_SLOT: u32 = 52;
pub const R_M32R_RELATIVE: u32 = 53;
pub const R_M32R_GOTOFF: u32 = 54;
pub const R_M32R_GOTPC24: u32 = 55;
pub const R_M32R_GOT16_HI_ULO: u32 = 56;
pub const R_M32R_GOT16_HI_SLO: u32 = 57;
pub const R_M32R_GOT16_LO: u32 = 58;
pub const R_M32R_GOTPC_HI_ULO: u32 = 59;
pub const R_M32R_GOTPC_HI_SLO: u32 = 60;
pub const R_M32R_GOTPC_LO: u32 = 61;
pub const R_M32R_GOTOFF_HI_ULO: u32 = 62;
pub const R_M32R_GOTOFF_HI_SLO: u32 = 63;
pub const R_M32R_GOTOFF_LO: u32 = 64;
pub const R_M32R_NUM: u32 = 256;

// ---------------------------------------------------------------------------
// MN10300 Relocation Types (elf.h)
// ---------------------------------------------------------------------------
pub const R_MN10300_NONE: u32 = 0;
pub const R_MN10300_32: u32 = 1;
pub const R_MN10300_16: u32 = 2;
pub const R_MN10300_8: u32 = 3;
pub const R_MN10300_PCREL32: u32 = 4;
pub const R_MN10300_PCREL16: u32 = 5;
pub const R_MN10300_PCREL8: u32 = 6;
pub const R_MN10300_GNU_VTINHERIT: u32 = 7;
pub const R_MN10300_GNU_VTENTRY: u32 = 8;
pub const R_MN10300_24: u32 = 9;
pub const R_MN10300_GOTPC32: u32 = 10;
pub const R_MN10300_GOTPC16: u32 = 11;
pub const R_MN10300_GOTOFF32: u32 = 12;
pub const R_MN10300_GOTOFF24: u32 = 13;
pub const R_MN10300_GOTOFF16: u32 = 14;
pub const R_MN10300_PLT32: u32 = 15;
pub const R_MN10300_PLT16: u32 = 16;
pub const R_MN10300_GOT32: u32 = 17;
pub const R_MN10300_GOT24: u32 = 18;
pub const R_MN10300_GOT16: u32 = 19;
pub const R_MN10300_COPY: u32 = 20;
pub const R_MN10300_GLOB_DAT: u32 = 21;
pub const R_MN10300_JMP_SLOT: u32 = 22;
pub const R_MN10300_RELATIVE: u32 = 23;
pub const R_MN10300_TLS_GD: u32 = 24;
pub const R_MN10300_TLS_LD: u32 = 25;
pub const R_MN10300_TLS_LDO: u32 = 26;
pub const R_MN10300_TLS_GOTIE: u32 = 27;
pub const R_MN10300_TLS_IE: u32 = 28;
pub const R_MN10300_TLS_LE: u32 = 29;
pub const R_MN10300_TLS_DTPMOD: u32 = 30;
pub const R_MN10300_TLS_DTPOFF: u32 = 31;
pub const R_MN10300_TLS_TPOFF: u32 = 32;
pub const R_MN10300_SYM_DIFF: u32 = 33;
pub const R_MN10300_ALIGN: u32 = 34;
pub const R_MN10300_NUM: u32 = 35;

// ---------------------------------------------------------------------------
// TILEPro Relocation Types (elf.h)
// ---------------------------------------------------------------------------
pub const R_TILEPRO_NONE: u32 = 0;
pub const R_TILEPRO_32: u32 = 1;
pub const R_TILEPRO_16: u32 = 2;
pub const R_TILEPRO_8: u32 = 3;
pub const R_TILEPRO_32_PCREL: u32 = 4;
pub const R_TILEPRO_16_PCREL: u32 = 5;
pub const R_TILEPRO_8_PCREL: u32 = 6;
pub const R_TILEPRO_LO16: u32 = 7;
pub const R_TILEPRO_HI16: u32 = 8;
pub const R_TILEPRO_HA16: u32 = 9;
pub const R_TILEPRO_COPY: u32 = 10;
pub const R_TILEPRO_GLOB_DAT: u32 = 11;
pub const R_TILEPRO_JMP_SLOT: u32 = 12;
pub const R_TILEPRO_RELATIVE: u32 = 13;
pub const R_TILEPRO_BROFF_X1: u32 = 14;
pub const R_TILEPRO_JOFFLONG_X1: u32 = 15;
pub const R_TILEPRO_JOFFLONG_X1_PLT: u32 = 16;
pub const R_TILEPRO_IMM8_X0: u32 = 17;
pub const R_TILEPRO_IMM8_Y0: u32 = 18;
pub const R_TILEPRO_IMM8_X1: u32 = 19;
pub const R_TILEPRO_IMM8_Y1: u32 = 20;
pub const R_TILEPRO_MT_IMM15_X1: u32 = 21;
pub const R_TILEPRO_MF_IMM15_X1: u32 = 22;
pub const R_TILEPRO_IMM16_X0: u32 = 23;
pub const R_TILEPRO_IMM16_X1: u32 = 24;
pub const R_TILEPRO_IMM16_X0_LO: u32 = 25;
pub const R_TILEPRO_IMM16_X1_LO: u32 = 26;
pub const R_TILEPRO_IMM16_X0_HI: u32 = 27;
pub const R_TILEPRO_IMM16_X1_HI: u32 = 28;
pub const R_TILEPRO_IMM16_X0_HA: u32 = 29;
pub const R_TILEPRO_IMM16_X1_HA: u32 = 30;
pub const R_TILEPRO_GNU_VTINHERIT: u32 = 128;
pub const R_TILEPRO_GNU_VTENTRY: u32 = 129;
pub const R_TILEPRO_NUM: u32 = 130;

// ---------------------------------------------------------------------------
// TILE-Gx Relocation Types (elf.h)
// ---------------------------------------------------------------------------
pub const R_TILEGX_NONE: u32 = 0;
pub const R_TILEGX_64: u32 = 1;
pub const R_TILEGX_32: u32 = 2;
pub const R_TILEGX_16: u32 = 3;
pub const R_TILEGX_8: u32 = 4;
pub const R_TILEGX_64_PCREL: u32 = 5;
pub const R_TILEGX_32_PCREL: u32 = 6;
pub const R_TILEGX_16_PCREL: u32 = 7;
pub const R_TILEGX_8_PCREL: u32 = 8;
pub const R_TILEGX_HW0: u32 = 9;
pub const R_TILEGX_HW1: u32 = 10;
pub const R_TILEGX_HW2: u32 = 11;
pub const R_TILEGX_HW3: u32 = 12;
pub const R_TILEGX_HW0_LAST: u32 = 13;
pub const R_TILEGX_HW1_LAST: u32 = 14;
pub const R_TILEGX_HW2_LAST: u32 = 15;
pub const R_TILEGX_COPY: u32 = 16;
pub const R_TILEGX_GLOB_DAT: u32 = 17;
pub const R_TILEGX_JMP_SLOT: u32 = 18;
pub const R_TILEGX_RELATIVE: u32 = 19;
pub const R_TILEGX_BROFF_X1: u32 = 20;
pub const R_TILEGX_JUMPOFF_X1: u32 = 21;
pub const R_TILEGX_JUMPOFF_X1_PLT: u32 = 22;
pub const R_TILEGX_IMM8_X0: u32 = 23;
pub const R_TILEGX_IMM8_Y0: u32 = 24;
pub const R_TILEGX_IMM8_X1: u32 = 25;
pub const R_TILEGX_IMM8_Y1: u32 = 26;
pub const R_TILEGX_DEST_IMM8_X1: u32 = 27;
pub const R_TILEGX_MT_IMM14_X1: u32 = 28;
pub const R_TILEGX_MF_IMM14_X1: u32 = 29;
pub const R_TILEGX_MMSTART_X0: u32 = 30;
pub const R_TILEGX_MMEND_X0: u32 = 31;
pub const R_TILEGX_SHAMT_X0: u32 = 32;
pub const R_TILEGX_SHAMT_X1: u32 = 33;
pub const R_TILEGX_SHAMT_Y0: u32 = 34;
pub const R_TILEGX_SHAMT_Y1: u32 = 35;
pub const R_TILEGX_GNU_VTINHERIT: u32 = 128;
pub const R_TILEGX_GNU_VTENTRY: u32 = 129;
pub const R_TILEGX_NUM: u32 = 130;

// ---------------------------------------------------------------------------
// Alpha Relocation Types (elf.h)
// ---------------------------------------------------------------------------
pub const R_ALPHA_NONE: u32 = 0;
pub const R_ALPHA_REFLONG: u32 = 1;
pub const R_ALPHA_REFQUAD: u32 = 2;
pub const R_ALPHA_GPREL32: u32 = 3;
pub const R_ALPHA_LITERAL: u32 = 4;
pub const R_ALPHA_LITUSE: u32 = 5;
pub const R_ALPHA_GPDISP: u32 = 6;
pub const R_ALPHA_BRADDR: u32 = 7;
pub const R_ALPHA_HINT: u32 = 8;
pub const R_ALPHA_SREL16: u32 = 9;
pub const R_ALPHA_SREL32: u32 = 10;
pub const R_ALPHA_SREL64: u32 = 11;
pub const R_ALPHA_GPRELHIGH: u32 = 17;
pub const R_ALPHA_GPRELLOW: u32 = 18;
pub const R_ALPHA_GPREL16: u32 = 19;
pub const R_ALPHA_COPY: u32 = 24;
pub const R_ALPHA_GLOB_DAT: u32 = 25;
pub const R_ALPHA_JMP_SLOT: u32 = 26;
pub const R_ALPHA_RELATIVE: u32 = 27;
pub const R_ALPHA_TLS_GD_HI: u32 = 28;
pub const R_ALPHA_TLSGD: u32 = 29;
pub const R_ALPHA_TLS_LDM: u32 = 30;
pub const R_ALPHA_DTPMOD64: u32 = 31;
pub const R_ALPHA_GOTDTPREL: u32 = 32;
pub const R_ALPHA_DTPREL64: u32 = 33;
pub const R_ALPHA_DTPRELHI: u32 = 34;
pub const R_ALPHA_DTPRELLO: u32 = 35;
pub const R_ALPHA_DTPREL16: u32 = 36;
pub const R_ALPHA_GOTTPREL: u32 = 37;
pub const R_ALPHA_TPREL64: u32 = 38;
pub const R_ALPHA_TPRELHI: u32 = 39;
pub const R_ALPHA_TPRELLO: u32 = 40;
pub const R_ALPHA_TPREL16: u32 = 41;
pub const R_ALPHA_NUM: u32 = 46;

// ---------------------------------------------------------------------------
// ELF Compression Types (elf.h)
// ---------------------------------------------------------------------------
pub const ELFCOMPRESS_ZLIB: u32 = 1;
pub const ELFCOMPRESS_LOOS: u32 = 0x60000000;
pub const ELFCOMPRESS_HIOS: u32 = 0x6fffffff;
pub const ELFCOMPRESS_LOPROC: u32 = 0x70000000;
pub const ELFCOMPRESS_HIPROC: u32 = 0x7fffffff;

// ---------------------------------------------------------------------------
// Architecture-Specific DT Tags (elf.h)
// ---------------------------------------------------------------------------
pub const DT_SPARC_REGISTER: u32 = 0x70000001;
pub const DT_SPARC_NUM: u32 = 2;
pub const DT_MIPS_RLD_VERSION: u32 = 0x70000001;
pub const DT_MIPS_TIME_STAMP: u32 = 0x70000002;
pub const DT_MIPS_ICHECKSUM: u32 = 0x70000003;
pub const DT_MIPS_IVERSION: u32 = 0x70000004;
pub const DT_MIPS_FLAGS: u32 = 0x70000005;
pub const DT_MIPS_BASE_ADDRESS: u32 = 0x70000006;
pub const DT_MIPS_MSYM: u32 = 0x70000007;
pub const DT_MIPS_CONFLICT: u32 = 0x70000008;
pub const DT_MIPS_LIBLIST: u32 = 0x70000009;
pub const DT_MIPS_LOCAL_GOTNO: u32 = 0x7000000a;
pub const DT_MIPS_CONFLICTNO: u32 = 0x7000000b;
pub const DT_MIPS_LIBLISTNO: u32 = 0x70000010;
pub const DT_MIPS_SYMTABNO: u32 = 0x70000011;
pub const DT_MIPS_UNREFEXTNO: u32 = 0x70000012;
pub const DT_MIPS_GOTSYM: u32 = 0x70000013;
pub const DT_MIPS_HIPAGENO: u32 = 0x70000014;
pub const DT_MIPS_RLD_MAP: u32 = 0x70000016;
pub const DT_MIPS_DELTA_CLASS: u32 = 0x70000017;
pub const DT_MIPS_DELTA_CLASS_NO: u32 = 0x70000018;
pub const DT_MIPS_DELTA_INSTANCE: u32 = 0x70000019;
pub const DT_MIPS_DELTA_INSTANCE_NO: u32 = 0x7000001a;
pub const DT_MIPS_DELTA_RELOC: u32 = 0x7000001b;
pub const DT_MIPS_DELTA_RELOC_NO: u32 = 0x7000001c;
pub const DT_MIPS_DELTA_SYM: u32 = 0x7000001d;
pub const DT_MIPS_DELTA_SYM_NO: u32 = 0x7000001e;
pub const DT_MIPS_DELTA_CLASSSYM: u32 = 0x70000020;
pub const DT_MIPS_DELTA_CLASSSYM_NO: u32 = 0x70000021;
pub const DT_MIPS_CXX_FLAGS: u32 = 0x70000022;
pub const DT_MIPS_PIXIE_INIT: u32 = 0x70000023;
pub const DT_MIPS_SYMBOL_LIB: u32 = 0x70000024;
pub const DT_MIPS_LOCALPAGE_GOTIDX: u32 = 0x70000025;
pub const DT_MIPS_LOCAL_GOTIDX: u32 = 0x70000026;
pub const DT_MIPS_HIDDEN_GOTIDX: u32 = 0x70000027;
pub const DT_MIPS_PROTECTED_GOTIDX: u32 = 0x70000028;
pub const DT_MIPS_OPTIONS: u32 = 0x70000029;
pub const DT_MIPS_INTERFACE: u32 = 0x7000002a;
pub const DT_MIPS_DYNSTR_ALIGN: u32 = 0x7000002b;
pub const DT_MIPS_INTERFACE_SIZE: u32 = 0x7000002c;
pub const DT_MIPS_RLD_TEXT_RESOLVE_ADDR: u32 = 0x7000002d;
pub const DT_MIPS_PERF_SUFFIX: u32 = 0x7000002e;
pub const DT_MIPS_COMPACT_SIZE: u32 = 0x7000002f;
pub const DT_MIPS_GP_VALUE: u32 = 0x70000030;
pub const DT_MIPS_AUX_DYNAMIC: u32 = 0x70000031;
pub const DT_MIPS_PLTGOT: u32 = 0x70000032;
pub const DT_MIPS_RWPLT: u32 = 0x70000034;
pub const DT_MIPS_RLD_MAP_REL: u32 = 0x70000035;
pub const DT_MIPS_NUM: u32 = 0x36;

// MIPS-specific section and flag constants
pub const SHT_MIPS_DWARF: u32 = 0x7000001e;
pub const SHT_MIPS_ABIFLAGS: u32 = 0x7000002a;
pub const SHF_MIPS_GPREL: u32 = 0x10000000;
pub const SHN_MIPS_ACOMMON: u32 = 0xff00;
pub const SHN_MIPS_TEXT: u32 = 0xff01;
pub const SHN_MIPS_DATA: u32 = 0xff02;
pub const PT_MIPS_ABIFLAGS: u32 = 0x70000003;

// GNU-specific constants
pub const ELF_NOTE_GNU: &str = "GNU";
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;


// ===========================================================================
// Additional ELF Constants - completing full elf.h coverage
// These constants ensure complete parity with the original TinyCC elf.h header
// covering architecture-specific relocation types, section types, program header
// types, and platform-specific flags.
// ===========================================================================

// ---------------------------------------------------------------------------
// Dynamic Section Types (Supplemental)
// ---------------------------------------------------------------------------
pub const DT_ALPHA_NUM: u32 = 1;
pub const DT_ALPHA_PLTRO: u32 = DT_LOPROC;
pub const DT_IA_64_NUM: u32 = 1;
pub const DT_IA_64_PLT_RESERVE: u32 = DT_LOPROC;

// ---------------------------------------------------------------------------
// ELF Flags (Supplemental)
// ---------------------------------------------------------------------------
/// PA-RISC 1.0 big-endian.
pub const EFA_PARISC_1_0: u32 = 0x020b;
/// PA-RISC 1.1 big-endian.
pub const EFA_PARISC_1_1: u32 = 0x0210;
/// PA-RISC 2.0 big-endian.
pub const EFA_PARISC_2_0: u32 = 0x0214;
/// All addresses must be < 2GB.
pub const EF_ALPHA_32BIT: u32 = 1;
/// Relocations for relaxing exist.
pub const EF_ALPHA_CANRELAX: u32 = 2;
pub const EF_ARM_EABI_UNKNOWN: u32 = 0x00000000;
pub const EF_CPU32: u32 = 0x00810000;
/// 64-bit ABI
pub const EF_IA_64_ABI64: u32 = 0x00000010;
/// arch. version mask
pub const EF_IA_64_ARCH: u32 = 0xff000000;
/// os-specific flags
pub const EF_IA_64_MASKOS: u32 = 0x0000000f;
/// Architecture version.
pub const EF_PARISC_ARCH: u32 = 0x0000ffff;
/// Program uses arch. extensions.
pub const EF_PARISC_EXT: u32 = 0x00020000;
/// Allow lazy swapping.
pub const EF_PARISC_LAZYSWAP: u32 = 0x00400000;
/// Program expects little endian.
pub const EF_PARISC_LSB: u32 = 0x00040000;
/// No kernel assisted branch
pub const EF_PARISC_NO_KABP: u32 = 0x00100000;
/// Trap nil pointer dereference.
pub const EF_PARISC_TRAPNIL: u32 = 0x00010000;
/// Program expects wide mode.
pub const EF_PARISC_WIDE: u32 = 0x00080000;
/// PowerPC embedded flag
pub const EF_PPC_EMB: u32 = 0x80000000;
/// PowerPC -mrelocatable flag
pub const EF_PPC_RELOCATABLE: u32 = 0x00010000;
/// PowerPC -mrelocatable-lib
pub const EF_PPC_RELOCATABLE_LIB: u32 = 0x00008000;
/// High GPRs kernel facility needed.
pub const EF_S390_HIGH_GPRS: u32 = 0x00000001;
pub const EF_SH1: u32 = 0x1;
pub const EF_SH2: u32 = 0x2;
pub const EF_SH2A: u32 = 0xd;
pub const EF_SH2A_NOFPU: u32 = 0x13;
pub const EF_SH2A_SH3E: u32 = 0x18;
pub const EF_SH2A_SH3_NOFPU: u32 = 0x16;
pub const EF_SH2A_SH4: u32 = 0x17;
pub const EF_SH2A_SH4_NOFPU: u32 = 0x15;
pub const EF_SH2E: u32 = 0xb;
pub const EF_SH3: u32 = 0x3;
pub const EF_SH3E: u32 = 0x8;
pub const EF_SH3_DSP: u32 = 0x5;
pub const EF_SH3_NOMMU: u32 = 0x14;
pub const EF_SH4: u32 = 0x9;
pub const EF_SH4A: u32 = 0xc;
pub const EF_SH4AL_DSP: u32 = 0x6;
pub const EF_SH4A_NOFPU: u32 = 0x11;
pub const EF_SH4_NOFPU: u32 = 0x10;
pub const EF_SH4_NOMMU_NOFPU: u32 = 0x12;
pub const EF_SH_DSP: u32 = 0x4;
pub const EF_SH_MACH_MASK: u32 = 0x1f;
pub const EF_SH_UNKNOWN: u32 = 0x0;
pub const EF_SPARCV9_MM: u32 = 3;
pub const EF_SPARCV9_PSO: u32 = 1;
pub const EF_SPARCV9_RMO: u32 = 2;
pub const EF_SPARCV9_TSO: u32 = 0;
/// generic V8+ features
pub const EF_SPARC_32PLUS: u32 = 0x000100;
pub const EF_SPARC_EXT_MASK: u32 = 0xFFFF00;
/// HAL R1 extensions
pub const EF_SPARC_HAL_R1: u32 = 0x000400;
/// little endian data
pub const EF_SPARC_LEDATA: u32 = 0x800000;
/// Sun `UltraSPARC1` extensions
pub const EF_SPARC_SUN_US1: u32 = 0x000200;
/// Sun `UltraSPARCIII` extensions
pub const EF_SPARC_SUN_US3: u32 = 0x000800;

// ---------------------------------------------------------------------------
// ELF Helper Constants (Supplemental)
// ---------------------------------------------------------------------------
/// ELF magic string
pub const ELFMAG: &[u8; 4] = b"\x7fELF";
/// Amiga Research OS.
pub const ELFOSABI_AROS: u32 = 15;
/// Linux TMS320C6000.
pub const ELFOSABI_C6000_LINUX: u32 = 65;
/// `FenixOS`.
pub const ELFOSABI_FENIXOS: u32 = 16;
/// Hewlett-Packard Non-Stop Kernel.
pub const ELFOSABI_NSK: u32 = 14;
pub const ELFOSABI_OPENVMS: u32 = 13;
/// Old name.
pub const ELF_NOTE_ABI: u32 = NT_GNU_ABI_TAG;
pub const ELF_NOTE_OS_FREEBSD: u32 = 3;
pub const ELF_NOTE_OS_GNU: u32 = 1;
pub const ELF_NOTE_OS_LINUX: u32 = 0;
pub const ELF_NOTE_OS_SOLARIS2: u32 = 2;
pub const ELF_NOTE_PAGESIZE_HINT: u32 = 1;
/// Solaris ELF note name
pub const ELF_NOTE_SOLARIS: &str = "SUNW Solaris";
pub const SELFMAG: usize = 4;

// ---------------------------------------------------------------------------
// Machine Types (Supplemental)
// ---------------------------------------------------------------------------
/// ARC Cores Tangent-A5
pub const EM_ARC_A5: u32 = 93;

// ---------------------------------------------------------------------------
// MIPS ELF Flags
// ---------------------------------------------------------------------------
/// -mips1 code.
pub const E_MIPS_ARCH_1: u32 = 0x00000000;
/// -mips2 code.
pub const E_MIPS_ARCH_2: u32 = 0x10000000;
/// -mips3 code.
pub const E_MIPS_ARCH_3: u32 = 0x20000000;
/// MIPS32 code.
pub const E_MIPS_ARCH_32: u32 = 0x60000000;
/// -mips4 code.
pub const E_MIPS_ARCH_4: u32 = 0x30000000;
/// -mips5 code.
pub const E_MIPS_ARCH_5: u32 = 0x40000000;
/// MIPS64 code.
pub const E_MIPS_ARCH_64: u32 = 0x70000000;

// ---------------------------------------------------------------------------
// Alpha LITUSE Types
// ---------------------------------------------------------------------------
pub const LITUSE_ALPHA_ADDR: u32 = 0;
pub const LITUSE_ALPHA_BASE: u32 = 1;
pub const LITUSE_ALPHA_BYTOFF: u32 = 2;
pub const LITUSE_ALPHA_JSR: u32 = 3;
pub const LITUSE_ALPHA_TLS_GD: u32 = 4;
pub const LITUSE_ALPHA_TLS_LDM: u32 = 5;

// ---------------------------------------------------------------------------
// MIPS Library List Flags
// ---------------------------------------------------------------------------
pub const LL_DELAY_LOAD: u32 = 1 << 4;
pub const LL_DELTA: u32 = 1 << 5;
/// Require exact match
pub const LL_EXACT_MATCH: u32 = 1 << 0;
pub const LL_EXPORTS: u32 = 1 << 3;
/// Ignore interface version
pub const LL_IGNORE_INT_VER: u32 = 1 << 1;
pub const LL_NONE: u32 = 0;
pub const LL_REQUIRE_MINOR: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// MIPS Options Kind Constants
// ---------------------------------------------------------------------------
/// Exception processing options.
pub const ODK_EXCEPTIONS: u32 = 2;
/// record the fill value used by the linker.
pub const ODK_FILL: u32 = 5;
/// HW workarounds.  'AND' bits when merging.
pub const ODK_HWAND: u32 = 7;
/// HW workarounds.  'OR' bits when merging.
pub const ODK_HWOR: u32 = 8;
/// Hardware workarounds performed
pub const ODK_HWPATCH: u32 = 4;
/// Undefined.
pub const ODK_NULL: u32 = 0;
/// Section padding options.
pub const ODK_PAD: u32 = 3;
/// Register usage information.
pub const ODK_REGINFO: u32 = 1;
/// reserve space for desktop tools to write.
pub const ODK_TAGS: u32 = 6;

// ---------------------------------------------------------------------------
// MIPS Exception Options
// ---------------------------------------------------------------------------
/// Dismiss invalid address faults?
pub const OEX_DISMISS: u32 = 0x80000;
/// Force floating point debug mode?
pub const OEX_FPDBUG: u32 = 0x40000;
pub const OEX_FPU_DIV0: u32 = 0x08;
pub const OEX_FPU_INEX: u32 = 0x01;
pub const OEX_FPU_INVAL: u32 = 0x10;
/// FPE's which MAY be enabled.
pub const OEX_FPU_MAX: u32 = 0x1f00;
/// FPE's which MUST be enabled.
pub const OEX_FPU_MIN: u32 = 0x1f;
pub const OEX_FPU_OFLO: u32 = 0x04;
pub const OEX_FPU_UFLO: u32 = 0x02;
/// page zero must be mapped.
pub const OEX_PAGE0: u32 = 0x10000;
pub const OEX_PRECISEFP: u32 = OEX_FPDBUG;
/// Force sequential memory mode?
pub const OEX_SMM: u32 = 0x20000;

// ---------------------------------------------------------------------------
// Miscellaneous ELF Constants
// ---------------------------------------------------------------------------
pub const OHWA0_R4KEOP_CHECKED: u32 = 0x00000001;
pub const OHWA1_R4KEOP_CLEAN: u32 = 0x00000002;
pub const _ELF_H: u32 = 1;

// ---------------------------------------------------------------------------
// MIPS Hardware Options
// ---------------------------------------------------------------------------
/// R4000 end-of-page patch.
pub const OHW_R4KEOP: u32 = 0x1;
/// R5000 cvt.[ds].l bug.  clean=1.
pub const OHW_R5KCVTL: u32 = 0x8;
/// R5000 end-of-page patch.
pub const OHW_R5KEOP: u32 = 0x4;
/// may need R8000 prefetch patch.
pub const OHW_R8KPFETCH: u32 = 0x2;

// ---------------------------------------------------------------------------
// MIPS Pad Options
// ---------------------------------------------------------------------------
pub const OPAD_POSTFIX: u32 = 0x2;
pub const OPAD_PREFIX: u32 = 0x1;
pub const OPAD_SYMBOL: u32 = 0x4;

// ---------------------------------------------------------------------------
// Program Header Flags (Supplemental)
// ---------------------------------------------------------------------------
pub const PF_HP_CODE: u32 = 0x01000000;
pub const PF_HP_FAR_SHARED: u32 = 0x00200000;
pub const PF_HP_LAZYSWAP: u32 = 0x04000000;
pub const PF_HP_MODIFY: u32 = 0x02000000;
pub const PF_HP_NEAR_SHARED: u32 = 0x00400000;
pub const PF_HP_PAGE_SIZE: u32 = 0x00100000;
pub const PF_HP_SBP: u32 = 0x08000000;
/// spec insns w/o recovery
pub const PF_IA_64_NORECOV: u32 = 0x80000000;
pub const PF_MIPS_LOCAL: u32 = 0x10000000;
pub const PF_PARISC_SBP: u32 = 0x08000000;

// ---------------------------------------------------------------------------
// Program Header Types (Supplemental)
// ---------------------------------------------------------------------------
pub const PT_HP_CORE_COMM: u32 = PT_LOOS + 0x4;
pub const PT_HP_CORE_KERNEL: u32 = PT_LOOS + 0x3;
pub const PT_HP_CORE_LOADABLE: u32 = PT_LOOS + 0x6;
pub const PT_HP_CORE_MMF: u32 = PT_LOOS + 0x9;
pub const PT_HP_CORE_NONE: u32 = PT_LOOS + 0x1;
pub const PT_HP_CORE_PROC: u32 = PT_LOOS + 0x5;
pub const PT_HP_CORE_SHM: u32 = PT_LOOS + 0x8;
pub const PT_HP_CORE_STACK: u32 = PT_LOOS + 0x7;
pub const PT_HP_CORE_VERSION: u32 = PT_LOOS + 0x2;
pub const PT_HP_FASTBIND: u32 = PT_LOOS + 0x11;
pub const PT_HP_HSL_ANNOT: u32 = PT_LOOS + 0x13;
pub const PT_HP_OPT_ANNOT: u32 = PT_LOOS + 0x12;
pub const PT_HP_PARALLEL: u32 = PT_LOOS + 0x10;
pub const PT_HP_STACK: u32 = PT_LOOS + 0x14;
pub const PT_HP_TLS: u32 = PT_LOOS;
/// arch extension bits
pub const PT_IA_64_ARCHEXT: u32 = PT_LOPROC;
pub const PT_IA_64_HP_HSL_ANOT: u32 = PT_LOOS + 0x13;
pub const PT_IA_64_HP_OPT_ANOT: u32 = PT_LOOS + 0x12;
pub const PT_IA_64_HP_STACK: u32 = PT_LOOS + 0x14;
/// ia64 unwind bits
pub const PT_IA_64_UNWIND: u32 = PT_LOPROC + 1;
pub const PT_MIPS_OPTIONS: u32 = 0x70000002;
/// Register usage information
pub const PT_MIPS_REGINFO: u32 = 0x70000000;
/// Runtime procedure table.
pub const PT_MIPS_RTPROC: u32 = 0x70000001;
pub const PT_PARISC_ARCHEXT: u32 = 0x70000000;
pub const PT_PARISC_UNWIND: u32 = 0x70000001;

// ---------------------------------------------------------------------------
// MIPS Runtime Hash Flags
// ---------------------------------------------------------------------------
pub const RHF_CORD: u32 = 1 << 12;
pub const RHF_DEFAULT_DELAY_LOAD: u32 = 1 << 9;
pub const RHF_DELTA_C_PLUS_PLUS: u32 = 1 << 6;
pub const RHF_GUARANTEE_INIT: u32 = 1 << 5;
pub const RHF_GUARANTEE_START_INIT: u32 = 1 << 7;
/// No flags
pub const RHF_NONE: u32 = 0;
/// Hash size not power of 2
pub const RHF_NOTPOT: u32 = 1 << 1;
/// Ignore `LD_LIBRARY_PATH`
pub const RHF_NO_LIBRARY_REPLACEMENT: u32 = 1 << 2;
pub const RHF_NO_MOVE: u32 = 1 << 3;
pub const RHF_NO_UNRES_UNDEF: u32 = 1 << 13;
pub const RHF_PIXIE: u32 = 1 << 8;
/// Use quickstart
pub const RHF_QUICKSTART: u32 = 1 << 0;
pub const RHF_REQUICKSTART: u32 = 1 << 10;
pub const RHF_REQUICKSTARTED: u32 = 1 << 11;
pub const RHF_RLD_ORDER_SAFE: u32 = 1 << 14;
pub const RHF_SGI_ONLY: u32 = 1 << 4;

// ---------------------------------------------------------------------------
// M68K Relocation Types
// ---------------------------------------------------------------------------
/// Direct 16 bit
pub const R_68K_16: u32 = 2;
/// Direct 32 bit
pub const R_68K_32: u32 = 1;
/// Direct 8 bit
pub const R_68K_8: u32 = 3;
/// Copy symbol at runtime
pub const R_68K_COPY: u32 = 19;
/// Create GOT entry
pub const R_68K_GLOB_DAT: u32 = 20;
/// 16 bit PC relative GOT entry
pub const R_68K_GOT16: u32 = 8;
/// 16 bit GOT offset
pub const R_68K_GOT16O: u32 = 11;
/// 32 bit PC relative GOT entry
pub const R_68K_GOT32: u32 = 7;
/// 32 bit GOT offset
pub const R_68K_GOT32O: u32 = 10;
/// 8 bit PC relative GOT entry
pub const R_68K_GOT8: u32 = 9;
/// 8 bit GOT offset
pub const R_68K_GOT8O: u32 = 12;
/// Create PLT entry
pub const R_68K_JMP_SLOT: u32 = 21;
/// No reloc
pub const R_68K_NONE: u32 = 0;
pub const R_68K_NUM: u32 = 43;
/// PC relative 16 bit
pub const R_68K_PC16: u32 = 5;
/// PC relative 32 bit
pub const R_68K_PC32: u32 = 4;
/// PC relative 8 bit
pub const R_68K_PC8: u32 = 6;
/// 16 bit PC relative PLT address
pub const R_68K_PLT16: u32 = 14;
/// 16 bit PLT offset
pub const R_68K_PLT16O: u32 = 17;
/// 32 bit PC relative PLT address
pub const R_68K_PLT32: u32 = 13;
/// 32 bit PLT offset
pub const R_68K_PLT32O: u32 = 16;
/// 8 bit PC relative PLT address
pub const R_68K_PLT8: u32 = 15;
/// 8 bit PLT offset
pub const R_68K_PLT8O: u32 = 18;
/// Adjust by program base
pub const R_68K_RELATIVE: u32 = 22;
/// 32 bit module number
pub const R_68K_TLS_DTPMOD32: u32 = 40;
/// 32 bit module-relative offset
pub const R_68K_TLS_DTPREL32: u32 = 41;
/// 16 bit GOT offset for GD
pub const R_68K_TLS_GD16: u32 = 26;
/// 32 bit GOT offset for GD
pub const R_68K_TLS_GD32: u32 = 25;
/// 8 bit GOT offset for GD
pub const R_68K_TLS_GD8: u32 = 27;
/// 16 bit GOT offset for IE
pub const R_68K_TLS_IE16: u32 = 35;
/// 32 bit GOT offset for IE
pub const R_68K_TLS_IE32: u32 = 34;
/// 8 bit GOT offset for IE
pub const R_68K_TLS_IE8: u32 = 36;
/// 16 bit GOT offset for LDM
pub const R_68K_TLS_LDM16: u32 = 29;
/// 32 bit GOT offset for LDM
pub const R_68K_TLS_LDM32: u32 = 28;
/// 8 bit GOT offset for LDM
pub const R_68K_TLS_LDM8: u32 = 30;
/// 16 bit module-relative offset
pub const R_68K_TLS_LDO16: u32 = 32;
/// 32 bit module-relative offset
pub const R_68K_TLS_LDO32: u32 = 31;
/// 8 bit module-relative offset
pub const R_68K_TLS_LDO8: u32 = 33;
/// 16 bit offset relative to
pub const R_68K_TLS_LE16: u32 = 38;
/// 32 bit offset relative to
pub const R_68K_TLS_LE32: u32 = 37;
/// 8 bit offset relative to
pub const R_68K_TLS_LE8: u32 = 39;
/// 32 bit TP-relative offset
pub const R_68K_TLS_TPREL32: u32 = 42;

// ---------------------------------------------------------------------------
// AArch64 Relocation Types (Supplemental)
// ---------------------------------------------------------------------------
/// Module number, 64 bit.
pub const R_AARCH64_TLS_DTPMOD64: u32 = 1028;
/// Module-relative offset, 64 bit.
pub const R_AARCH64_TLS_DTPREL64: u32 = 1029;
/// TP-relative offset, 64 bit.
pub const R_AARCH64_TLS_TPREL64: u32 = 1030;

// ---------------------------------------------------------------------------
// ARM Relocation Types (Supplemental)
// ---------------------------------------------------------------------------
pub const R_ARM_ALU_SBREL_19_12: u32 = 36;
pub const R_ARM_ALU_SBREL_27_20: u32 = 37;
pub const R_ARM_AMP_VCALL9: u32 = 12;
pub const R_ARM_LDR_SBREL_11_0: u32 = 35;
pub const R_ARM_PC13: u32 = 4;
pub const R_ARM_RABS22: u32 = 253;
pub const R_ARM_RBASE: u32 = 255;
pub const R_ARM_RPC24: u32 = 254;
pub const R_ARM_RREL32: u32 = 252;
pub const R_ARM_RSBREL32: u32 = 250;
pub const R_ARM_RXPC25: u32 = 249;
/// Obsolete static relocation.
pub const R_ARM_SWI24: u32 = 13;
/// thumb unconditional branch
pub const R_ARM_THM_PC11: u32 = 102;
/// thumb conditional branch
pub const R_ARM_THM_PC9: u32 = 103;
pub const R_ARM_THM_RPC22: u32 = 251;
pub const R_ARM_THM_TLS_DESCSEQ: u32 = 129;

// ---------------------------------------------------------------------------
// IA-64 Relocation Types
// ---------------------------------------------------------------------------
/// @pcrel(sym + add), brl
pub const R_IA64_PCREL60B: u32 = 0x48;
/// @pltoff(sym + add), add imm22
pub const R_IA64_PLTOFF22: u32 = 0x3a;
/// @pltoff(sym + add), mov imm64
pub const R_IA64_PLTOFF64I: u32 = 0x3b;
/// @pltoff(sym + add), data8 LSB
pub const R_IA64_PLTOFF64LSB: u32 = 0x3f;
/// @pltoff(sym + add), data8 MSB
pub const R_IA64_PLTOFF64MSB: u32 = 0x3e;

// ---------------------------------------------------------------------------
// PA-RISC Relocation Types
// ---------------------------------------------------------------------------
/// Copy relocation.
pub const R_PARISC_COPY: u32 = 128;
/// 14 bits of eff. address.
pub const R_PARISC_DIR14DR: u32 = 84;
/// Right 14 bits of eff. address.
pub const R_PARISC_DIR14R: u32 = 6;
/// 14 bits of eff. address.
pub const R_PARISC_DIR14WR: u32 = 83;
/// 16 bits of eff. address.
pub const R_PARISC_DIR16DF: u32 = 87;
/// 16 bits of eff. address.
pub const R_PARISC_DIR16F: u32 = 85;
/// 16 bits of eff. address.
pub const R_PARISC_DIR16WF: u32 = 86;
/// 17 bits of eff. address.
pub const R_PARISC_DIR17F: u32 = 4;
/// Right 17 bits of eff. address.
pub const R_PARISC_DIR17R: u32 = 3;
/// Left 21 bits of eff. address.
pub const R_PARISC_DIR21L: u32 = 2;
/// Direct 32-bit reference.
pub const R_PARISC_DIR32: u32 = 1;
/// 64 bits of eff. address.
pub const R_PARISC_DIR64: u32 = 80;
/// Right 14 bits of rel. address.
pub const R_PARISC_DPREL14R: u32 = 22;
/// Left 21 bits of rel. address.
pub const R_PARISC_DPREL21L: u32 = 18;
/// Dynamic reloc, exported PLT
pub const R_PARISC_EPLT: u32 = 130;
/// 64 bits function address.
pub const R_PARISC_FPTR64: u32 = 64;
pub const R_PARISC_GNU_VTENTRY: u32 = 232;
pub const R_PARISC_GNU_VTINHERIT: u32 = 233;
/// GP-rel. address, right 14 bits.
pub const R_PARISC_GPREL14DR: u32 = 92;
/// GP-relative, right 14 bits.
pub const R_PARISC_GPREL14R: u32 = 30;
/// GP-rel. address, right 14 bits.
pub const R_PARISC_GPREL14WR: u32 = 91;
/// 16 bits GP-rel. address.
pub const R_PARISC_GPREL16DF: u32 = 95;
/// 16 bits GP-rel. address.
pub const R_PARISC_GPREL16F: u32 = 93;
/// 16 bits GP-rel. address.
pub const R_PARISC_GPREL16WF: u32 = 94;
/// GP-relative, left 21 bits.
pub const R_PARISC_GPREL21L: u32 = 26;
/// 64 bits of GP-rel. address.
pub const R_PARISC_GPREL64: u32 = 88;
pub const R_PARISC_HIRESERVE: u32 = 255;
/// Dynamic reloc, imported PLT
pub const R_PARISC_IPLT: u32 = 129;
pub const R_PARISC_LORESERVE: u32 = 128;
/// LT-rel. address, right 14 bits.
pub const R_PARISC_LTOFF14DR: u32 = 100;
/// LT-relative, right 14 bits.
pub const R_PARISC_LTOFF14R: u32 = 38;
/// LT-rel. address, right 14 bits.
pub const R_PARISC_LTOFF14WR: u32 = 99;
/// 16 bits LT-rel. address.
pub const R_PARISC_LTOFF16DF: u32 = 103;
/// 16 bits LT-rel. address.
pub const R_PARISC_LTOFF16F: u32 = 101;
/// 16 bits LT-rel. address.
pub const R_PARISC_LTOFF16WF: u32 = 102;
/// LT-relative, left 21 bits.
pub const R_PARISC_LTOFF21L: u32 = 34;
/// 64 bits LT-rel. address.
pub const R_PARISC_LTOFF64: u32 = 96;
/// LT-rel. fct. ptr., right 14 bits.
pub const R_PARISC_LTOFF_FPTR14DR: u32 = 124;
/// LT-rel. fct ptr, right 14 bits.
pub const R_PARISC_LTOFF_FPTR14R: u32 = 62;
/// LT-rel. fct. ptr., right 14 bits.
pub const R_PARISC_LTOFF_FPTR14WR: u32 = 123;
/// 16 bits LT-rel. function ptr.
pub const R_PARISC_LTOFF_FPTR16DF: u32 = 127;
/// 16 bits LT-rel. function ptr.
pub const R_PARISC_LTOFF_FPTR16F: u32 = 125;
/// 16 bits LT-rel. function ptr.
pub const R_PARISC_LTOFF_FPTR16WF: u32 = 126;
/// LT-rel. fct ptr, left 21 bits.
pub const R_PARISC_LTOFF_FPTR21L: u32 = 58;
/// 32 bits LT-rel. function pointer.
pub const R_PARISC_LTOFF_FPTR32: u32 = 57;
/// 64 bits LT-rel. function ptr.
pub const R_PARISC_LTOFF_FPTR64: u32 = 120;
/// LT-TP-rel. address, right 14 bits.
pub const R_PARISC_LTOFF_TP14DR: u32 = 228;
/// 14 bits LT-TP-rel. address.
pub const R_PARISC_LTOFF_TP14F: u32 = 167;
/// LT-TP-rel. address, right 14 bits.
pub const R_PARISC_LTOFF_TP14R: u32 = 166;
/// LT-TP-rel. address, right 14 bits.
pub const R_PARISC_LTOFF_TP14WR: u32 = 227;
/// 16 bits LT-TP-rel. address.
pub const R_PARISC_LTOFF_TP16DF: u32 = 231;
/// 16 bits LT-TP-rel. address.
pub const R_PARISC_LTOFF_TP16F: u32 = 229;
/// 16 bits LT-TP-rel. address.
pub const R_PARISC_LTOFF_TP16WF: u32 = 230;
/// LT-TP-rel. address, left 21 bits.
pub const R_PARISC_LTOFF_TP21L: u32 = 162;
/// 64 bits LT-TP-rel. address.
pub const R_PARISC_LTOFF_TP64: u32 = 224;
/// No reloc.
pub const R_PARISC_NONE: u32 = 0;
/// PC rel. address, right 14 bits.
pub const R_PARISC_PCREL14DR: u32 = 76;
/// Right 14 bits of rel. address.
pub const R_PARISC_PCREL14R: u32 = 14;
/// PC-rel. address, right 14 bits.
pub const R_PARISC_PCREL14WR: u32 = 75;
/// 16 bits PC-rel. address.
pub const R_PARISC_PCREL16DF: u32 = 79;
/// 16 bits PC-rel. address.
pub const R_PARISC_PCREL16F: u32 = 77;
/// 16 bits PC-rel. address.
pub const R_PARISC_PCREL16WF: u32 = 78;
/// 17 bits of rel. address.
pub const R_PARISC_PCREL17F: u32 = 12;
/// Right 17 bits of rel. address.
pub const R_PARISC_PCREL17R: u32 = 11;
/// Left 21 bits of rel. address.
pub const R_PARISC_PCREL21L: u32 = 10;
/// 22 bits PC-rel. address.
pub const R_PARISC_PCREL22F: u32 = 74;
/// 32-bit rel. address.
pub const R_PARISC_PCREL32: u32 = 9;
/// 64 bits PC-rel. address.
pub const R_PARISC_PCREL64: u32 = 72;
/// Right 14 bits of fdesc address.
pub const R_PARISC_PLABEL14R: u32 = 70;
/// Left 21 bits of fdesc address.
pub const R_PARISC_PLABEL21L: u32 = 66;
/// 32 bits function address.
pub const R_PARISC_PLABEL32: u32 = 65;
/// PLT-rel. address, right 14 bits.
pub const R_PARISC_PLTOFF14DR: u32 = 116;
/// PLT rel. address, right 14 bits.
pub const R_PARISC_PLTOFF14R: u32 = 54;
/// PLT-rel. address, right 14 bits.
pub const R_PARISC_PLTOFF14WR: u32 = 115;
/// 16 bits PLT-rel. address.
pub const R_PARISC_PLTOFF16DF: u32 = 119;
/// 16 bits LT-rel. address.
pub const R_PARISC_PLTOFF16F: u32 = 117;
/// 16 bits PLT-rel. address.
pub const R_PARISC_PLTOFF16WF: u32 = 118;
/// PLT rel. address, left 21 bits.
pub const R_PARISC_PLTOFF21L: u32 = 50;
/// 32 bits section rel. address.
pub const R_PARISC_SECREL32: u32 = 41;
/// 64 bits section rel. address.
pub const R_PARISC_SECREL64: u32 = 104;
/// No relocation, set segment base.
pub const R_PARISC_SEGBASE: u32 = 48;
/// 32 bits segment rel. address.
pub const R_PARISC_SEGREL32: u32 = 49;
/// 64 bits segment rel. address.
pub const R_PARISC_SEGREL64: u32 = 112;
/// DTP module 32-bit.
pub const R_PARISC_TLS_DTPMOD32: u32 = 242;
/// DTP module 64-bit.
pub const R_PARISC_TLS_DTPMOD64: u32 = 243;
/// DTP offset 32-bit.
pub const R_PARISC_TLS_DTPOFF32: u32 = 244;
/// DTP offset 32-bit.
pub const R_PARISC_TLS_DTPOFF64: u32 = 245;
/// GD 14-bit right.
pub const R_PARISC_TLS_GD14R: u32 = 235;
/// GD 21-bit left.
pub const R_PARISC_TLS_GD21L: u32 = 234;
/// GD call to __`t_g_a`.
pub const R_PARISC_TLS_GDCALL: u32 = 236;
pub const R_PARISC_TLS_IE14R: u32 = R_PARISC_LTOFF_TP14R;
pub const R_PARISC_TLS_IE21L: u32 = R_PARISC_LTOFF_TP21L;
/// LD module 14-bit right.
pub const R_PARISC_TLS_LDM14R: u32 = 238;
/// LD module 21-bit left.
pub const R_PARISC_TLS_LDM21L: u32 = 237;
/// LD module call to __`t_g_a`.
pub const R_PARISC_TLS_LDMCALL: u32 = 239;
/// LD offset 14-bit right.
pub const R_PARISC_TLS_LDO14R: u32 = 241;
/// LD offset 21-bit left.
pub const R_PARISC_TLS_LDO21L: u32 = 240;
pub const R_PARISC_TLS_LE14R: u32 = R_PARISC_TPREL14R;
pub const R_PARISC_TLS_LE21L: u32 = R_PARISC_TPREL21L;
pub const R_PARISC_TLS_TPREL32: u32 = R_PARISC_TPREL32;
pub const R_PARISC_TLS_TPREL64: u32 = R_PARISC_TPREL64;
/// TP-rel. address, right 14 bits.
pub const R_PARISC_TPREL14DR: u32 = 220;
/// TP-rel. address, right 14 bits.
pub const R_PARISC_TPREL14R: u32 = 158;
/// TP-rel. address, right 14 bits.
pub const R_PARISC_TPREL14WR: u32 = 219;
/// 16 bits TP-rel. address.
pub const R_PARISC_TPREL16DF: u32 = 223;
/// 16 bits TP-rel. address.
pub const R_PARISC_TPREL16F: u32 = 221;
/// 16 bits TP-rel. address.
pub const R_PARISC_TPREL16WF: u32 = 222;
/// TP-rel. address, left 21 bits.
pub const R_PARISC_TPREL21L: u32 = 154;
/// 32 bits TP-rel. address.
pub const R_PARISC_TPREL32: u32 = 153;
/// 64 bits TP-rel. address.
pub const R_PARISC_TPREL64: u32 = 216;

// ---------------------------------------------------------------------------
// SPARC Relocation Types (Supplemental)
// ---------------------------------------------------------------------------
/// PC relative 64 bit
pub const R_SPARC_DISP64: u32 = 46;
/// was part of v9 ABI but was removed
pub const R_SPARC_GLOB_JMP: u32 = 42;
pub const R_SPARC_H34: u32 = 85;
/// Direct high 12 of 44 bit
pub const R_SPARC_H44: u32 = 50;
/// High 22 bit complemented
pub const R_SPARC_HIX22: u32 = 48;
pub const R_SPARC_IRELATIVE: u32 = 249;
pub const R_SPARC_JMP_IREL: u32 = 248;
/// Direct low 10 of 44 bit
pub const R_SPARC_L44: u32 = 52;
/// Truncated 11 bit complemented
pub const R_SPARC_LOX10: u32 = 49;
/// Direct mid 22 of 44 bit
pub const R_SPARC_M44: u32 = 51;
/// Direct 64 bit ref to PLT entry
pub const R_SPARC_PLT64: u32 = 47;
/// Global register usage
pub const R_SPARC_REGISTER: u32 = 53;
pub const R_SPARC_SIZE32: u32 = 86;
pub const R_SPARC_SIZE64: u32 = 87;
pub const R_SPARC_TLS_DTPMOD32: u32 = 74;
pub const R_SPARC_TLS_DTPMOD64: u32 = 75;
pub const R_SPARC_TLS_DTPOFF32: u32 = 76;
pub const R_SPARC_TLS_DTPOFF64: u32 = 77;
pub const R_SPARC_TLS_GD_ADD: u32 = 58;
pub const R_SPARC_TLS_GD_CALL: u32 = 59;
pub const R_SPARC_TLS_GD_HI22: u32 = 56;
pub const R_SPARC_TLS_GD_LO10: u32 = 57;
pub const R_SPARC_TLS_IE_ADD: u32 = 71;
pub const R_SPARC_TLS_IE_HI22: u32 = 67;
pub const R_SPARC_TLS_IE_LD: u32 = 69;
pub const R_SPARC_TLS_IE_LDX: u32 = 70;
pub const R_SPARC_TLS_IE_LO10: u32 = 68;
pub const R_SPARC_TLS_LDM_ADD: u32 = 62;
pub const R_SPARC_TLS_LDM_CALL: u32 = 63;
pub const R_SPARC_TLS_LDM_HI22: u32 = 60;
pub const R_SPARC_TLS_LDM_LO10: u32 = 61;
pub const R_SPARC_TLS_LDO_ADD: u32 = 66;
pub const R_SPARC_TLS_LDO_HIX22: u32 = 64;
pub const R_SPARC_TLS_LDO_LOX10: u32 = 65;
pub const R_SPARC_TLS_LE_HIX22: u32 = 72;
pub const R_SPARC_TLS_LE_LOX10: u32 = 73;
pub const R_SPARC_TLS_TPOFF32: u32 = 78;
pub const R_SPARC_TLS_TPOFF64: u32 = 79;
/// Direct 16 bit unaligned
pub const R_SPARC_UA16: u32 = 55;
/// Direct 64 bit unaligned
pub const R_SPARC_UA64: u32 = 54;
pub const R_SPARC_WDISP10: u32 = 88;

// ---------------------------------------------------------------------------
// Tile-GX Relocation Types (Supplemental)
// ---------------------------------------------------------------------------
/// X0 pipe hword 0
pub const R_TILEGX_IMM16_X0_HW0: u32 = 36;
/// X0 pipe hword 0 GOT offset
pub const R_TILEGX_IMM16_X0_HW0_GOT: u32 = 64;
/// X0 pipe last hword 0
pub const R_TILEGX_IMM16_X0_HW0_LAST: u32 = 44;
/// X0 pipe last hword 0 GOT offset
pub const R_TILEGX_IMM16_X0_HW0_LAST_GOT: u32 = 72;
/// X0 pipe PC-rel last hword 0
pub const R_TILEGX_IMM16_X0_HW0_LAST_PCREL: u32 = 58;
/// X0 pipe PC-rel PLT last hword 0
pub const R_TILEGX_IMM16_X0_HW0_LAST_PLT_PCREL: u32 = 94;
/// X0 pipe last hword 0 GD off
pub const R_TILEGX_IMM16_X0_HW0_LAST_TLS_GD: u32 = 86;
/// X0 pipe last hword 0 IE off
pub const R_TILEGX_IMM16_X0_HW0_LAST_TLS_IE: u32 = 100;
/// X0 pipe last hword 0 LE off
pub const R_TILEGX_IMM16_X0_HW0_LAST_TLS_LE: u32 = 82;
/// X0 pipe PC relative hword 0
pub const R_TILEGX_IMM16_X0_HW0_PCREL: u32 = 50;
/// X0 pipe PC-rel PLT hword 0
pub const R_TILEGX_IMM16_X0_HW0_PLT_PCREL: u32 = 66;
/// X0 pipe hword 0 TLS GD offset
pub const R_TILEGX_IMM16_X0_HW0_TLS_GD: u32 = 78;
/// X0 pipe hword 0 TLS IE offset
pub const R_TILEGX_IMM16_X0_HW0_TLS_IE: u32 = 92;
/// X0 pipe hword 0 TLS LE offset
pub const R_TILEGX_IMM16_X0_HW0_TLS_LE: u32 = 80;
/// X0 pipe hword 1
pub const R_TILEGX_IMM16_X0_HW1: u32 = 38;
/// X0 pipe last hword 1
pub const R_TILEGX_IMM16_X0_HW1_LAST: u32 = 46;
/// X0 pipe last hword 1 GOT offset
pub const R_TILEGX_IMM16_X0_HW1_LAST_GOT: u32 = 74;
/// X0 pipe PC-rel last hword 1
pub const R_TILEGX_IMM16_X0_HW1_LAST_PCREL: u32 = 60;
/// X0 pipe PC-rel PLT last hword 1
pub const R_TILEGX_IMM16_X0_HW1_LAST_PLT_PCREL: u32 = 96;
/// X0 pipe last hword 1 GD off
pub const R_TILEGX_IMM16_X0_HW1_LAST_TLS_GD: u32 = 88;
/// X0 pipe last hword 1 IE off
pub const R_TILEGX_IMM16_X0_HW1_LAST_TLS_IE: u32 = 102;
/// X0 pipe last hword 1 LE off
pub const R_TILEGX_IMM16_X0_HW1_LAST_TLS_LE: u32 = 84;
/// X0 pipe PC relative hword 1
pub const R_TILEGX_IMM16_X0_HW1_PCREL: u32 = 52;
/// X0 pipe PC-rel PLT hword 1
pub const R_TILEGX_IMM16_X0_HW1_PLT_PCREL: u32 = 68;
/// X0 pipe hword 2
pub const R_TILEGX_IMM16_X0_HW2: u32 = 40;
/// X0 pipe last hword 2
pub const R_TILEGX_IMM16_X0_HW2_LAST: u32 = 48;
/// X0 pipe PC-rel last hword 2
pub const R_TILEGX_IMM16_X0_HW2_LAST_PCREL: u32 = 62;
/// X0 pipe PC-rel PLT last hword 2
pub const R_TILEGX_IMM16_X0_HW2_LAST_PLT_PCREL: u32 = 98;
/// X0 pipe PC relative hword 2
pub const R_TILEGX_IMM16_X0_HW2_PCREL: u32 = 54;
/// X0 pipe PC-rel PLT hword 2
pub const R_TILEGX_IMM16_X0_HW2_PLT_PCREL: u32 = 70;
/// X0 pipe hword 3
pub const R_TILEGX_IMM16_X0_HW3: u32 = 42;
/// X0 pipe PC relative hword 3
pub const R_TILEGX_IMM16_X0_HW3_PCREL: u32 = 56;
/// X0 pipe PC-rel PLT hword 3
pub const R_TILEGX_IMM16_X0_HW3_PLT_PCREL: u32 = 76;
/// X1 pipe hword 0
pub const R_TILEGX_IMM16_X1_HW0: u32 = 37;
/// X1 pipe hword 0 GOT offset
pub const R_TILEGX_IMM16_X1_HW0_GOT: u32 = 65;
/// X1 pipe last hword 0
pub const R_TILEGX_IMM16_X1_HW0_LAST: u32 = 45;
/// X1 pipe last hword 0 GOT offset
pub const R_TILEGX_IMM16_X1_HW0_LAST_GOT: u32 = 73;
/// X1 pipe PC-rel last hword 0
pub const R_TILEGX_IMM16_X1_HW0_LAST_PCREL: u32 = 59;
/// X1 pipe PC-rel PLT last hword 0
pub const R_TILEGX_IMM16_X1_HW0_LAST_PLT_PCREL: u32 = 95;
/// X1 pipe last hword 0 GD off
pub const R_TILEGX_IMM16_X1_HW0_LAST_TLS_GD: u32 = 87;
/// X1 pipe last hword 0 IE off
pub const R_TILEGX_IMM16_X1_HW0_LAST_TLS_IE: u32 = 101;
/// X1 pipe last hword 0 LE off
pub const R_TILEGX_IMM16_X1_HW0_LAST_TLS_LE: u32 = 83;
/// X1 pipe PC relative hword 0
pub const R_TILEGX_IMM16_X1_HW0_PCREL: u32 = 51;
/// X1 pipe PC-rel PLT hword 0
pub const R_TILEGX_IMM16_X1_HW0_PLT_PCREL: u32 = 67;
/// X1 pipe hword 0 TLS GD offset
pub const R_TILEGX_IMM16_X1_HW0_TLS_GD: u32 = 79;
/// X1 pipe hword 0 TLS IE offset
pub const R_TILEGX_IMM16_X1_HW0_TLS_IE: u32 = 93;
/// X1 pipe hword 0 TLS LE offset
pub const R_TILEGX_IMM16_X1_HW0_TLS_LE: u32 = 81;
/// X1 pipe hword 1
pub const R_TILEGX_IMM16_X1_HW1: u32 = 39;
/// X1 pipe last hword 1
pub const R_TILEGX_IMM16_X1_HW1_LAST: u32 = 47;
/// X1 pipe last hword 1 GOT offset
pub const R_TILEGX_IMM16_X1_HW1_LAST_GOT: u32 = 75;
/// X1 pipe PC-rel last hword 1
pub const R_TILEGX_IMM16_X1_HW1_LAST_PCREL: u32 = 61;
/// X1 pipe PC-rel PLT last hword 1
pub const R_TILEGX_IMM16_X1_HW1_LAST_PLT_PCREL: u32 = 97;
/// X1 pipe last hword 1 GD off
pub const R_TILEGX_IMM16_X1_HW1_LAST_TLS_GD: u32 = 89;
/// X1 pipe last hword 1 IE off
pub const R_TILEGX_IMM16_X1_HW1_LAST_TLS_IE: u32 = 103;
/// X1 pipe last hword 1 LE off
pub const R_TILEGX_IMM16_X1_HW1_LAST_TLS_LE: u32 = 85;
/// X1 pipe PC relative hword 1
pub const R_TILEGX_IMM16_X1_HW1_PCREL: u32 = 53;
/// X1 pipe PC-rel PLT hword 1
pub const R_TILEGX_IMM16_X1_HW1_PLT_PCREL: u32 = 69;
/// X1 pipe hword 2
pub const R_TILEGX_IMM16_X1_HW2: u32 = 41;
/// X1 pipe last hword 2
pub const R_TILEGX_IMM16_X1_HW2_LAST: u32 = 49;
/// X1 pipe PC-rel last hword 2
pub const R_TILEGX_IMM16_X1_HW2_LAST_PCREL: u32 = 63;
/// X1 pipe PC-rel PLT last hword 2
pub const R_TILEGX_IMM16_X1_HW2_LAST_PLT_PCREL: u32 = 99;
/// X1 pipe PC relative hword 2
pub const R_TILEGX_IMM16_X1_HW2_PCREL: u32 = 55;
/// X1 pipe PC-rel PLT hword 2
pub const R_TILEGX_IMM16_X1_HW2_PLT_PCREL: u32 = 71;
/// X1 pipe hword 3
pub const R_TILEGX_IMM16_X1_HW3: u32 = 43;
/// X1 pipe PC relative hword 3
pub const R_TILEGX_IMM16_X1_HW3_PCREL: u32 = 57;
/// X1 pipe PC-rel PLT hword 3
pub const R_TILEGX_IMM16_X1_HW3_PLT_PCREL: u32 = 77;
/// X0 pipe "addi" for TLS GD/IE
pub const R_TILEGX_IMM8_X0_TLS_ADD: u32 = 118;
/// X0 pipe "addi" for TLS GD
pub const R_TILEGX_IMM8_X0_TLS_GD_ADD: u32 = 113;
/// X1 pipe "addi" for TLS GD/IE
pub const R_TILEGX_IMM8_X1_TLS_ADD: u32 = 119;
/// X1 pipe "addi" for TLS GD
pub const R_TILEGX_IMM8_X1_TLS_GD_ADD: u32 = 114;
/// Y0 pipe "addi" for TLS GD/IE
pub const R_TILEGX_IMM8_Y0_TLS_ADD: u32 = 120;
/// Y0 pipe "addi" for TLS GD
pub const R_TILEGX_IMM8_Y0_TLS_GD_ADD: u32 = 115;
/// Y1 pipe "addi" for TLS GD/IE
pub const R_TILEGX_IMM8_Y1_TLS_ADD: u32 = 121;
/// Y1 pipe "addi" for TLS GD
pub const R_TILEGX_IMM8_Y1_TLS_GD_ADD: u32 = 116;
/// 32-bit ID of symbol's module
pub const R_TILEGX_TLS_DTPMOD32: u32 = 109;
/// 64-bit ID of symbol's module
pub const R_TILEGX_TLS_DTPMOD64: u32 = 106;
/// 32-bit offset in TLS block
pub const R_TILEGX_TLS_DTPOFF32: u32 = 110;
/// 64-bit offset in TLS block
pub const R_TILEGX_TLS_DTPOFF64: u32 = 107;
/// "jal" for TLS GD
pub const R_TILEGX_TLS_GD_CALL: u32 = 112;
/// "`ld_tls`" for TLS IE
pub const R_TILEGX_TLS_IE_LOAD: u32 = 117;
/// 32-bit offset in static TLS block
pub const R_TILEGX_TLS_TPOFF32: u32 = 111;
/// 64-bit offset in static TLS block
pub const R_TILEGX_TLS_TPOFF64: u32 = 108;

// ---------------------------------------------------------------------------
// TILEPro Relocation Types (Supplemental)
// ---------------------------------------------------------------------------
/// X1 pipe destination 8-bit
pub const R_TILEPRO_DEST_IMM8_X1: u32 = 55;
/// X0 pipe 16-bit GOT offset
pub const R_TILEPRO_IMM16_X0_GOT: u32 = 39;
/// X0 pipe `ha()` 16-bit GOT offset
pub const R_TILEPRO_IMM16_X0_GOT_HA: u32 = 45;
/// X0 pipe high 16-bit GOT offset
pub const R_TILEPRO_IMM16_X0_GOT_HI: u32 = 43;
/// X0 pipe low 16-bit GOT offset
pub const R_TILEPRO_IMM16_X0_GOT_LO: u32 = 41;
/// X0 pipe PC relative `ha()` 16 bit
pub const R_TILEPRO_IMM16_X0_HA_PCREL: u32 = 37;
/// X0 pipe PC relative high 16 bit
pub const R_TILEPRO_IMM16_X0_HI_PCREL: u32 = 35;
/// X0 pipe PC relative low 16 bit
pub const R_TILEPRO_IMM16_X0_LO_PCREL: u32 = 33;
/// X0 pipe PC relative 16 bit
pub const R_TILEPRO_IMM16_X0_PCREL: u32 = 31;
/// X0 pipe 16-bit TLS GD offset
pub const R_TILEPRO_IMM16_X0_TLS_GD: u32 = 66;
/// X0 pipe `ha()` 16-bit TLS GD offset
pub const R_TILEPRO_IMM16_X0_TLS_GD_HA: u32 = 72;
/// X0 pipe high 16-bit TLS GD offset
pub const R_TILEPRO_IMM16_X0_TLS_GD_HI: u32 = 70;
/// X0 pipe low 16-bit TLS GD offset
pub const R_TILEPRO_IMM16_X0_TLS_GD_LO: u32 = 68;
/// X0 pipe 16-bit TLS IE offset
pub const R_TILEPRO_IMM16_X0_TLS_IE: u32 = 74;
/// X0 pipe `ha()` 16-bit TLS IE offset
pub const R_TILEPRO_IMM16_X0_TLS_IE_HA: u32 = 80;
/// X0 pipe high 16-bit TLS IE offset
pub const R_TILEPRO_IMM16_X0_TLS_IE_HI: u32 = 78;
/// X0 pipe low 16-bit TLS IE offset
pub const R_TILEPRO_IMM16_X0_TLS_IE_LO: u32 = 76;
/// X0 pipe 16-bit TLS LE offset
pub const R_TILEPRO_IMM16_X0_TLS_LE: u32 = 85;
/// X0 pipe `ha()` 16-bit TLS LE offset
pub const R_TILEPRO_IMM16_X0_TLS_LE_HA: u32 = 91;
/// X0 pipe high 16-bit TLS LE offset
pub const R_TILEPRO_IMM16_X0_TLS_LE_HI: u32 = 89;
/// X0 pipe low 16-bit TLS LE offset
pub const R_TILEPRO_IMM16_X0_TLS_LE_LO: u32 = 87;
/// X1 pipe 16-bit GOT offset
pub const R_TILEPRO_IMM16_X1_GOT: u32 = 40;
/// X1 pipe `ha()` 16-bit GOT offset
pub const R_TILEPRO_IMM16_X1_GOT_HA: u32 = 46;
/// X1 pipe high 16-bit GOT offset
pub const R_TILEPRO_IMM16_X1_GOT_HI: u32 = 44;
/// X1 pipe low 16-bit GOT offset
pub const R_TILEPRO_IMM16_X1_GOT_LO: u32 = 42;
/// X1 pipe PC relative `ha()` 16 bit
pub const R_TILEPRO_IMM16_X1_HA_PCREL: u32 = 38;
/// X1 pipe PC relative high 16 bit
pub const R_TILEPRO_IMM16_X1_HI_PCREL: u32 = 36;
/// X1 pipe PC relative low 16 bit
pub const R_TILEPRO_IMM16_X1_LO_PCREL: u32 = 34;
/// X1 pipe PC relative 16 bit
pub const R_TILEPRO_IMM16_X1_PCREL: u32 = 32;
/// X1 pipe 16-bit TLS GD offset
pub const R_TILEPRO_IMM16_X1_TLS_GD: u32 = 67;
/// X1 pipe `ha()` 16-bit TLS GD offset
pub const R_TILEPRO_IMM16_X1_TLS_GD_HA: u32 = 73;
/// X1 pipe high 16-bit TLS GD offset
pub const R_TILEPRO_IMM16_X1_TLS_GD_HI: u32 = 71;
/// X1 pipe low 16-bit TLS GD offset
pub const R_TILEPRO_IMM16_X1_TLS_GD_LO: u32 = 69;
/// X1 pipe 16-bit TLS IE offset
pub const R_TILEPRO_IMM16_X1_TLS_IE: u32 = 75;
/// X1 pipe `ha()` 16-bit TLS IE offset
pub const R_TILEPRO_IMM16_X1_TLS_IE_HA: u32 = 81;
/// X1 pipe high 16-bit TLS IE offset
pub const R_TILEPRO_IMM16_X1_TLS_IE_HI: u32 = 79;
/// X1 pipe low 16-bit TLS IE offset
pub const R_TILEPRO_IMM16_X1_TLS_IE_LO: u32 = 77;
/// X1 pipe 16-bit TLS LE offset
pub const R_TILEPRO_IMM16_X1_TLS_LE: u32 = 86;
/// X1 pipe `ha()` 16-bit TLS LE offset
pub const R_TILEPRO_IMM16_X1_TLS_LE_HA: u32 = 92;
/// X1 pipe high 16-bit TLS LE offset
pub const R_TILEPRO_IMM16_X1_TLS_LE_HI: u32 = 90;
/// X1 pipe low 16-bit TLS LE offset
pub const R_TILEPRO_IMM16_X1_TLS_LE_LO: u32 = 88;
/// X0 pipe "addi" for TLS GD
pub const R_TILEPRO_IMM8_X0_TLS_GD_ADD: u32 = 61;
/// X1 pipe "addi" for TLS GD
pub const R_TILEPRO_IMM8_X1_TLS_GD_ADD: u32 = 62;
/// Y0 pipe "addi" for TLS GD
pub const R_TILEPRO_IMM8_Y0_TLS_GD_ADD: u32 = 63;
/// Y1 pipe "addi" for TLS GD
pub const R_TILEPRO_IMM8_Y1_TLS_GD_ADD: u32 = 64;
/// X0 pipe mm "end"
pub const R_TILEPRO_MMEND_X0: u32 = 48;
/// X1 pipe mm "end"
pub const R_TILEPRO_MMEND_X1: u32 = 50;
/// X0 pipe mm "start"
pub const R_TILEPRO_MMSTART_X0: u32 = 47;
/// X1 pipe mm "start"
pub const R_TILEPRO_MMSTART_X1: u32 = 49;
/// X0 pipe shift amount
pub const R_TILEPRO_SHAMT_X0: u32 = 51;
/// X1 pipe shift amount
pub const R_TILEPRO_SHAMT_X1: u32 = 52;
/// Y0 pipe shift amount
pub const R_TILEPRO_SHAMT_Y0: u32 = 53;
/// Y1 pipe shift amount
pub const R_TILEPRO_SHAMT_Y1: u32 = 54;
/// ID of module containing symbol
pub const R_TILEPRO_TLS_DTPMOD32: u32 = 82;
/// Offset in TLS block
pub const R_TILEPRO_TLS_DTPOFF32: u32 = 83;
/// "jal" for TLS GD
pub const R_TILEPRO_TLS_GD_CALL: u32 = 60;
/// "`lw_tls`" for TLS IE
pub const R_TILEPRO_TLS_IE_LOAD: u32 = 65;
/// Offset in static TLS block
pub const R_TILEPRO_TLS_TPOFF32: u32 = 84;

// ---------------------------------------------------------------------------
// Section Header Flags (Supplemental)
// ---------------------------------------------------------------------------
pub const SHF_ALPHA_GPREL: u32 = 0x10000000;
/// spec insns w/o recovery
pub const SHF_IA_64_NORECOV: u32 = 0x20000000;
/// section near gp
pub const SHF_IA_64_SHORT: u32 = 0x10000000;
pub const SHF_MIPS_ADDR: u32 = 0x40000000;
pub const SHF_MIPS_LOCAL: u32 = 0x04000000;
pub const SHF_MIPS_MERGE: u32 = 0x20000000;
pub const SHF_MIPS_NAMES: u32 = 0x02000000;
pub const SHF_MIPS_NODUPE: u32 = 0x01000000;
pub const SHF_MIPS_NOSTRIP: u32 = 0x08000000;
pub const SHF_MIPS_STRINGS: u32 = 0x80000000;
/// Section far from gp.
pub const SHF_PARISC_HUGE: u32 = 0x40000000;
/// Static branch prediction code.
pub const SHF_PARISC_SBP: u32 = 0x80000000;
/// Section with short addressing.
pub const SHF_PARISC_SHORT: u32 = 0x20000000;

// ---------------------------------------------------------------------------
// Special Section Indices (Supplemental)
// ---------------------------------------------------------------------------
/// Small common symbols
pub const SHN_MIPS_SCOMMON: u32 = 0xff03;
/// Small undefined symbols
pub const SHN_MIPS_SUNDEFINED: u32 = 0xff04;
/// Section for tentatively declared
pub const SHN_PARISC_ANSI_COMMON: u32 = 0xff00;
/// Common blocks in huge model.
pub const SHN_PARISC_HUGE_COMMON: u32 = 0xff01;

// ---------------------------------------------------------------------------
// Section Header Types (Supplemental)
// ---------------------------------------------------------------------------
pub const SHT_ALPHA_DEBUG: u32 = 0x70000001;
pub const SHT_ALPHA_REGINFO: u32 = 0x70000002;
/// extension bits
pub const SHT_IA_64_EXT: u32 = SHT_LOPROC;
/// unwind bits
pub const SHT_IA_64_UNWIND: u32 = SHT_LOPROC + 1;
pub const SHT_MIPS_AUXSYM: u32 = 0x70000016;
/// Conflicting symbols
pub const SHT_MIPS_CONFLICT: u32 = 0x70000002;
pub const SHT_MIPS_CONTENT: u32 = 0x7000000c;
/// MIPS ECOFF debugging information
pub const SHT_MIPS_DEBUG: u32 = 0x70000005;
pub const SHT_MIPS_DELTACLASS: u32 = 0x7000001d;
pub const SHT_MIPS_DELTADECL: u32 = 0x7000001f;
pub const SHT_MIPS_DELTAINST: u32 = 0x7000001c;
pub const SHT_MIPS_DELTASYM: u32 = 0x7000001b;
pub const SHT_MIPS_DENSE: u32 = 0x70000013;
pub const SHT_MIPS_EH_REGION: u32 = 0x70000027;
/// Event section.
pub const SHT_MIPS_EVENTS: u32 = 0x70000021;
pub const SHT_MIPS_EXTSYM: u32 = 0x70000012;
pub const SHT_MIPS_FDESC: u32 = 0x70000011;
/// Global data area sizes
pub const SHT_MIPS_GPTAB: u32 = 0x70000003;
pub const SHT_MIPS_IFACE: u32 = 0x7000000b;
/// Shared objects used in link
pub const SHT_MIPS_LIBLIST: u32 = 0x70000000;
pub const SHT_MIPS_LINE: u32 = 0x70000019;
pub const SHT_MIPS_LOCSTR: u32 = 0x70000018;
pub const SHT_MIPS_LOCSYM: u32 = 0x70000015;
pub const SHT_MIPS_MSYM: u32 = 0x70000001;
/// Miscellaneous options.
pub const SHT_MIPS_OPTIONS: u32 = 0x7000000d;
pub const SHT_MIPS_OPTSYM: u32 = 0x70000017;
pub const SHT_MIPS_PACKAGE: u32 = 0x70000007;
pub const SHT_MIPS_PACKSYM: u32 = 0x70000008;
pub const SHT_MIPS_PDESC: u32 = 0x70000014;
pub const SHT_MIPS_PDR_EXCEPTION: u32 = 0x70000029;
pub const SHT_MIPS_PIXIE: u32 = 0x70000023;
/// Register usage information
pub const SHT_MIPS_REGINFO: u32 = 0x70000006;
pub const SHT_MIPS_RELD: u32 = 0x70000009;
pub const SHT_MIPS_RFDESC: u32 = 0x7000001a;
pub const SHT_MIPS_SHDR: u32 = 0x70000010;
pub const SHT_MIPS_SYMBOL_LIB: u32 = 0x70000020;
pub const SHT_MIPS_TRANSLATE: u32 = 0x70000022;
/// Reserved for SGI/MIPS compilers
pub const SHT_MIPS_UCODE: u32 = 0x70000004;
pub const SHT_MIPS_WHIRL: u32 = 0x70000026;
pub const SHT_MIPS_XLATE: u32 = 0x70000024;
pub const SHT_MIPS_XLATE_DEBUG: u32 = 0x70000025;
pub const SHT_MIPS_XLATE_OLD: u32 = 0x70000028;
/// Debug info for optimized code.
pub const SHT_PARISC_DOC: u32 = 0x70000002;
/// Contains product specific ext.
pub const SHT_PARISC_EXT: u32 = 0x70000000;
/// Unwind information.
pub const SHT_PARISC_UNWIND: u32 = 0x70000001;

// ---------------------------------------------------------------------------
// Symbol Binding (Supplemental)
// ---------------------------------------------------------------------------
pub const STB_MIPS_SPLIT_COMMON: u8 = 13;

// ---------------------------------------------------------------------------
// Symbol Other Values (Supplemental)
// ---------------------------------------------------------------------------
/// No PV required.
pub const STO_ALPHA_NOPV: u8 = 0x80;
/// PV only used for initial ldgp.
pub const STO_ALPHA_STD_GPLOAD: u8 = 0x88;
pub const STO_MIPS_DEFAULT: u8 = 0x0;
pub const STO_MIPS_HIDDEN: u8 = 0x2;
pub const STO_MIPS_INTERNAL: u8 = 0x1;
pub const STO_MIPS_PLT: u8 = 0x8;
pub const STO_MIPS_PROTECTED: u8 = 0x3;
pub const STO_MIPS_SC_ALIGN_UNUSED: u8 = 0xff;

// ---------------------------------------------------------------------------
// Symbol Types (Supplemental)
// ---------------------------------------------------------------------------
pub const STT_HP_OPAQUE: u8 = STT_LOOS + 0x1;
pub const STT_HP_STUB: u8 = STT_LOOS + 0x2;
/// Millicode function entry point.
pub const STT_PARISC_MILLICODE: u8 = 13;
/// Global register reserved to app.
pub const STT_SPARC_REGISTER: u8 = 13;

// ---------------------------------------------------------------------------
// ELF Helper Functions (additional macro equivalents from elf.h)
// Note: elf_st_bind/type/info/visibility, elf32/64_r_sym/type/info already
// exist above. These add the remaining ELF macro function translations.
// ---------------------------------------------------------------------------

/// ELF32 move symbol index (from `ELF32_M_SYM` macro)
#[inline]
pub const fn elf32_m_sym(info: u32) -> u32 { info >> 8 }
/// ELF32 move size (from `ELF32_M_SIZE` macro)
#[inline]
pub const fn elf32_m_size(info: u32) -> u8 { info as u8 }
/// ELF32 move info (from `ELF32_M_INFO` macro)
#[inline]
pub const fn elf32_m_info(sym: u32, size: u8) -> u32 { (sym << 8) + (size as u32) }
/// ELF64 move symbol index (from `ELF64_M_SYM` macro)
#[inline]
pub const fn elf64_m_sym(info: u64) -> u64 { info >> 8 }
/// ELF64 move size (from `ELF64_M_SIZE` macro)
#[inline]
pub const fn elf64_m_size(info: u64) -> u8 { info as u8 }
/// ELF64 move info (from `ELF64_M_INFO` macro)
#[inline]
pub const fn elf64_m_info(sym: u64, size: u8) -> u64 { (sym << 8) + (size as u64) }

/// ELF32 ST bind (from `ELF32_ST_BIND` macro)
#[inline]
pub const fn elf32_st_bind(val: u8) -> u8 { val >> 4 }
/// ELF32 ST type (from `ELF32_ST_TYPE` macro)
#[inline]
pub const fn elf32_st_type(val: u8) -> u8 { val & 0xf }
/// ELF32 ST info (from `ELF32_ST_INFO` macro)
#[inline]
pub const fn elf32_st_info(bind: u8, stype: u8) -> u8 { (bind << 4) + (stype & 0xf) }
/// ELF32 ST visibility (from `ELF32_ST_VISIBILITY` macro)
#[inline]
pub const fn elf32_st_visibility(o: u8) -> u8 { o & 0x03 }

/// ELF64 ST bind (from `ELF64_ST_BIND` macro)
#[inline]
pub const fn elf64_st_bind(val: u8) -> u8 { val >> 4 }
/// ELF64 ST type (from `ELF64_ST_TYPE` macro)
#[inline]
pub const fn elf64_st_type(val: u8) -> u8 { val & 0xf }
/// ELF64 ST info (from `ELF64_ST_INFO` macro)
#[inline]
pub const fn elf64_st_info(bind: u8, stype: u8) -> u8 { (bind << 4) + (stype & 0xf) }
/// ELF64 ST visibility (from `ELF64_ST_VISIBILITY` macro)
#[inline]
pub const fn elf64_st_visibility(o: u8) -> u8 { o & 0x03 }

/// Extract ARM EABI version from ELF flags (from `EF_ARM_EABI_VERSION` macro)
#[inline]
pub const fn ef_arm_eabi_version(flags: u32) -> u32 { flags & EF_ARM_EABIMASK }

/// Dynamic tag value index (from `DT_VALTAGIDX` macro)
#[inline]
pub const fn dt_valtagidx(tag: u32) -> u32 { DT_VALRNGHI.wrapping_sub(tag) }
/// Dynamic tag address index (from `DT_ADDRTAGIDX` macro)
#[inline]
pub const fn dt_addrtagidx(tag: u32) -> u32 { DT_ADDRRNGHI.wrapping_sub(tag) }
/// Dynamic tag version index (from `DT_VERSIONTAGIDX` macro)
#[inline]
pub const fn dt_versiontagidx(tag: u32) -> u32 { DT_VERNEEDNUM.wrapping_sub(tag) }
