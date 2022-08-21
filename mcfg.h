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
#define MAX_NUM_ICCIDS 32
#define MAX_OBJ_SIZE 16384
/* ELF Headers */

/* 32-bit ELF base types. */
typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t Elf32_Sword;
typedef uint32_t Elf32_Word;

#define EI_NIDENT 16
#define ELFMAG "\177ELF"

struct nv_item {
  uint32_t id;
  uint8_t type;
  uint16_t offset;
  uint16_t size;
  uint8_t blob[MAX_OBJ_SIZE];
};

struct Elf32_Ehdr {
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
  26 8e 04 98 d8 a0 e0 45 e8 d9 48 a4 45 
  uint8_t padding[32]; // 0x00 
  uint8_t hash2[32]; //45 81 10 ce 40 ba ea fa e0 a8 06 12 8e cc 37 91 d6 9c c8 fd eb 24
  4d 76 04 8d eb da 76 20 b3 ca 
  uint8_t padding[32]; // 0x00 all the rest of the file (hash1 + padding + hash2 == 0x60 (96byte)

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

struct mcfg_footer_header {
  uint16_t id; // 0xa1 0x00
  uint16_t len;

} __attribute__((packed));

struct mcfg_footer_proto {
  uint8_t id;
  uint16_t len;
  uint8_t *data[0];
} __attribute__((packed));

// *ALMOST* constant, some magic identifier or version?
struct mcfg_footer_section_0 {
  uint8_t id;    // 0x00
  uint16_t len;  // 2 bytes
  uint16_t data; // 256
} __attribute__((packed));

// This changes in different files, although structure stays and numbers match inside firmwares
// Seems like some version number too?
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

/*
Apparently it's a list of partial ICCIDs to match the SIMs
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

// Unknown, some have it, some don't
struct mcfg_footer_section_5 {
  uint8_t id;          // 5
  uint16_t len;        // 4
  uint8_t *data; 
} __attribute__((packed));


struct mcfg_footer {
  uint32_t len;
  uint32_t footer_magic1; // 0x0a 00 00 00
  uint16_t footer_magic2; // 0xa1 00 
  uint16_t size_trimmed; // No confindence on this, its always len -0x10
  unsigned char magic[8]; // MCFG_TRL
} __attribute__((packed));

enum {
  MCFG_FILETYPE_HW = 0,
  MCFG_FILETYPE_SW = 1,
};
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
  MCFG_ITEM_TYPE_FOOT = 0x0A,
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
