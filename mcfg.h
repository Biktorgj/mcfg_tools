#include <argp.h>
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __MCFG_H__
#define __MCFG_H__

#define MCFG_FILE_HEADER_MAGIC "MCFG"
#define MCFG_FILE_FOOTER_MAGIC "MCFG_TRL"

//#define ELF_OFFSET 8192 // shouldnt hardcode this
#define VERSION_NUM 4995
/* ELF Headers */

/* 32-bit ELF base types. */
typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t Elf32_Sword;
typedef uint32_t Elf32_Word;

#define EI_NIDENT 16
#define ELFMAG "\177ELF"

struct ElfN_Ehdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

/* These constants define the permissions on sections in the program
   header, p_flags. */
#define PF_R 0x4
#define PF_W 0x2
#define PF_X 0x1

struct elf32_phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* sh_type */
#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_SHLIB 10
#define SHT_DYNSYM 11
#define SHT_NUM 12
#define SHT_LOPROC 0x70000000
#define SHT_HIPROC 0x7fffffff
#define SHT_LOUSER 0x80000000
#define SHT_HIUSER 0xffffffff

/* sh_flags */
#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define SHF_RELA_LIVEPATCH 0x00100000
#define SHF_RO_AFTER_INIT 0x00200000
#define SHF_MASKPROC 0xf0000000

/* special section indexes */
#define SHN_UNDEF 0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_LIVEPATCH 0xff20
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff

typedef struct elf32_shdr {
  Elf32_Word sh_name;
  Elf32_Word sh_type;
  Elf32_Word sh_flags;
  Elf32_Addr sh_addr;
  Elf32_Off sh_offset;
  Elf32_Word sh_size;
  Elf32_Word sh_link;
  Elf32_Word sh_info;
  Elf32_Word sh_addralign;
  Elf32_Word sh_entsize;
} Elf32_Shdr;

/*
        version: int  # Header version number
        type: int  # Type of "image" (always 0x3?)
        flash_addr: int  # Location of image in flash (always 0?)
        dest_addr: int  # Physical address of loaded hash segment data
        total_size: int  # = code_size + signature_size + cert_chain_size
        hash_size: int  # Size of SHA256 hashes for each program segment
        signature_addr: int  # Physical address of loaded attestation signature
        signature_size: int  # Size of attestation signature
        cert_chain_addr: int  # Physical address of loaded certificate chain
        cert_chain_size: int  # Size of certificate chain
*/
struct hash_segment_header {
  uint32_t version;         // 0x00
  uint32_t type;            // 0x03
  uint32_t flash_addr;      // 0x00
  uint32_t dest_addr;       // 0x28 0x10 0x00 0x00
  uint32_t total_size;      // 60 00 00 00
  uint32_t hash_size;       // 60 00 00 00
  uint32_t signature_addr;  // 88 10 00 00
  uint32_t signature_size;  // 00 00 00 00
  uint32_t cert_chain_addr; // 88 10 00 00
  uint32_t cert_chain_size; // 00 00 00 00
  uint8_t hash1[32];
  uint8_t padding[32];
  uint8_t hash2[32];
  /*
  uint8_t hash1[32]; //b5 10 06 96 85 4e b8 1e f2 12 bb d4 92 99 de fe 1f 5b 53
  26 8e 04 98 d8 a0 e0 45 e8 d9 48 a4 45 uint8_t padding[32]; // 0x00 uint8_t
  hash2[32]; //45 81 10 ce 40 ba ea fa e0 a8 06 12 8e cc 37 91 d6 9c c8 fd eb 24
  4d 76 04 8d eb da 76 20 b3 ca uint8_t padding[32]; // 0x00 all the rest of the
  file (hash1 + padding + hash2 == 0x60 (96byte)

  */
};

struct mcfg_file_header {
  unsigned char magic[4];  // MCFG
  uint16_t format_version; // 0x02 0x00
  uint16_t config_type;    // MCFG_HW is 0, MCFG_SW is 1
  uint32_t no_of_items;    // Number of items in the file
  uint8_t padding[4];      // 0x00
} __attribute__((packed));

struct mcfg_sub_version_data { // unsure
  uint16_t version;            // 0x83 0x13
  uint16_t unknown1;           // 0x04 0x00
  uint16_t unknown2;           // 0x01 0x00 || 0x03 0x00
  uint8_t unknown3;            // 0xe0
  uint8_t unknown4;            // 0x02
} __attribute__((packed));

struct mcfg_nvitem {
  uint16_t id;           // EFS NV element?
  uint16_t payload_size; // Size of the rest of the item
  uint8_t *payload[0];
} __attribute__((packed));

struct mcfg_nvfile_part {
  uint16_t file_section; // 0x01 for filename, 0x02 for file contents
  uint16_t section_len;  // size of this piece
  uint8_t *payload[0];
} __attribute__((packed));

struct mcfg_item {
  uint32_t id;      // EFS NV element?
  uint8_t type;     // 0x01 || <-- ITEM TYPE?
  uint8_t attrib;   // 0x09 0x29? <-- Attributes?
  uint16_t padding; // 0x00 0x00
} __attribute__((packed));

// Constant, some magic identifier?
struct mcfg_footer_section_0 {
  uint8_t id;    // 0x00
  uint16_t len;  // 2 bytes
  uint16_t data; // 256
} __attribute__((packed));

// This changes in different files, although structure stays
struct mcfg_footer_section_1 {
  uint8_t id;    // 0x01
  uint16_t len;  // 4 bytes
  uint32_t data; // 33625405
} __attribute__((packed));

// Network
struct mcfg_footer_section_2 {
  uint8_t id;   // 0x01
  uint16_t len; // 4 bytes
  uint16_t mcc; // 460
  uint16_t mnc; // 01
} __attribute__((packed));

// Carrier name, as shown in QMBNCFG?
struct mcfg_footer_section_3 {
  uint8_t id;   // 3
  uint16_t len; // 19 <-- len?
  uint8_t *carrier_config_name[];
} __attribute__((packed));

// No fucking clue
/*
Is this something about the iccids?
https://forums.quectel.com/t/document-sharing-sim-card/16046
https://blog.karthisoftek.com/a?ID=00900-29badf5d-bd0a-47f7-b3fc-eb900c57e003
*/
struct mcfg_footer_section_4 {
  uint8_t id;          // 4
  uint16_t len;        // 10
  uint8_t foot14;      // 0
  uint8_t num_iccids;  // 2?
  uint32_t *iccids[0]; // 898601 898601
} __attribute__((packed));

struct mcfg_footer {
  uint32_t len;
  uint32_t u1;
  uint16_t u2;
  uint16_t u3;
  unsigned char magic[8];
} __attribute__((packed));

/* MOTHERFUCKERS!
Just like fucking QMI */
struct mcfg_footer_samp {
  uint32_t len;
  uint32_t u1;
  uint16_t u2;
  uint16_t u3;
  uint8_t magic[8];
  /* MOTHERFUCKERS!
  Just like fucking QMI */

  // Type Len Value

  // This one seems constant
  uint8_t foot0;  // 0
  uint16_t foot1; // 2 len
  uint16_t foot2; // 256

  uint8_t foot3;  // 1
  uint16_t foot4; // 4
  uint32_t foot5; // 33625405

  // This looks like network
  uint8_t foot6;  // 2
  uint16_t foot7; // 4 len
  uint16_t foot8; // 460
  uint16_t foot9; // 1

  // Carrier name, what gets shown in QMBNCONF?
  uint8_t foot10;  // 3
  uint16_t foot11; // 19 <-- len?
  uint8_t carrier_config_name[19];

  // No fucking clue
  uint8_t foot12;     // 4
  uint16_t foot13;    // 10
  uint8_t foot14;     // 0
  uint8_t foot15;     // 2?
  uint32_t foot16[2]; // 898601 898601
  // And we have some other bytes here at the end
  // 00 00 50 00 00 00
} __attribute__((packed));

// Base item IDs
enum {
  MCFG_CARRIER_NAME = 0x00000019,
};

/* Item types, borrowed from
 * https://github.com/JohnBel/EfsTools/blob/master/EfsTools/Mbn/ItemType.cs */
enum {
  MCFG_ITEM_TYPE_NV = 0x01,
  MCFG_ITEM_TYPE_NVFILE = 0x02,
  MCFG_ITEM_TYPE_FILE = 0x04,
  MCFG_ITEM_TYPE_TRAIL = 0xA1,
};

/* Attributes */
enum {
  ATTRIB_MODE_09 = 0x09,
  ATTRIB_MODE_29 = 0x29,
  ATTRIB_MODE_2A = 0x2A,
};

/* EFS file sections */
enum {
  EFS_FILENAME = 0x01,
  EFS_FILECONTENTS = 0x02,
};

#endif
