#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>

#ifndef __MCFG_H__
#define __MCFG_H__

#define MCFG_FILE_HEADER_MAGIC "MCFG"
#define ELF_OFFSET 8192
#define VERSION_NUM 4995

struct mcfg_file_header {
    unsigned char magic[4]; //MCFG
    uint16_t format_version; // 0x02 0x00 
    uint16_t config_type; // MCFG_HW is 0, MCFG_SW is 1
    uint32_t no_of_items; // Number of items in the file 
    uint8_t padding[4]; // 0x00
} __attribute__((packed));

 struct mcfg_sub_version_data { // unsure
    uint16_t version; // 0x83 0x13
    uint16_t unknown1; // 0x04 0x00
    uint16_t unknown2; // 0x01 0x00 || 0x03 0x00 
    uint8_t unknown3; // 0xe0
    uint8_t unknown4; // 0x02
} __attribute__((packed));

struct mcfg_config_item {
    uint16_t id; // EFS NV element?
    uint16_t payload_size; // Size of the rest of the item
    uint8_t *payload[0];
} __attribute__((packed));

struct mcfg_item {
    uint32_t item_id; // EFS NV element?
    uint8_t u1; // 0x01
    uint8_t u2; // 0x09 0x29?
    uint16_t padding; // 0x00 0x00
    struct mcfg_config_item item;
} __attribute__((packed));

enum {
    MCFG_CARRIER_NAME = 0x00000019,
};

#endif
