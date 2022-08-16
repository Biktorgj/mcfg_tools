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

// Constant, some magic identifier?
struct mcfg_footer_section_0 {
    uint8_t id; // 0x00
    uint16_t len; // 2 bytes
    uint16_t data; // 256
} __attribute__((packed));

// This changes in different files, although structure stays
struct mcfg_footer_section_1 {
    uint8_t id; // 0x01
    uint16_t len; // 4 bytes
    uint32_t data; // 33625405
} __attribute__((packed));

// Network
struct mcfg_footer_section_2 {
    uint8_t id; // 0x01
    uint16_t len; // 4 bytes
    uint16_t mcc; // 460
    uint16_t mnc; // 01
} __attribute__((packed));

// Carrier name, as shown in QMBNCFG?
struct mcfg_footer_section_3 {
  uint8_t id; // 3
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
  uint8_t id; // 4
  uint16_t len; // 10
  uint8_t foot14; // 0
  uint8_t num_iccids; // 2?
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
  uint8_t foot0; // 0
  uint16_t foot1; // 2 len
  uint16_t foot2; // 256

  uint8_t foot3; // 1
  uint16_t foot4; // 4
  uint32_t foot5; // 33625405

// This looks like network
  uint8_t foot6; // 2
  uint16_t foot7; // 4 len
  uint16_t foot8; // 460
  uint16_t foot9; // 1
  
// Carrier name, what gets shown in QMBNCONF?
  uint8_t foot10; // 3
  uint16_t foot11; // 19 <-- len?
  uint8_t carrier_config_name[19];

// No fucking clue
  uint8_t foot12; // 4
  uint16_t foot13; // 10
  uint8_t foot14; // 0
  uint8_t foot15; // 2?
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
