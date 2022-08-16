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

#define ELF_OFFSET 8192 // shouldnt hardcode this
#define VERSION_NUM 4995

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
    uint16_t section_len; // size of this piece
    uint8_t *payload[0];
} __attribute__((packed));

struct mcfg_item {
  uint32_t id; // EFS NV element?
  uint8_t type;       // 0x01 || <-- ITEM TYPE?
  uint8_t attrib;       // 0x09 0x29? <-- Attributes?
  uint16_t padding; // 0x00 0x00
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
  MCFG_ITEM_TYPE_TRAIL = 0x0A,
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
