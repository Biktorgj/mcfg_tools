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

struct mcfg_file_header {
    uint8_t magic[4]; //MCFG
    uint16_t str1; // 0x02 0x00 
    uint16_t str2; // 0x01 0x00
    uint16_t str3; // 0x07 0x00 Either 2 or 7 are version numbers
    uint8_t padding[6]; // 0x00
} __attribute__((packed));

 struct mcfg_carrier_specific_version { // unsure
    uint8_t const1; // 0x83
    uint8_t const2; // 0x13;
    uint16_t unknown1; // 0x04 0x00
    uint16_t unknown2; // 0x01 0x00 || 0x03 0x00 
    uint8_t unknown3; // 0xe0
    uint8_t unknown4; // 0x02
} __attribute__((packed));

struct mcfg_item {
    uint32_t item_id; // EFS NV element?
    uint8_t unk1; // 0x01
    uint8_t unkn2; // 0x09
    uint16_t padding; // 0x00 0x00
    uint16_t unkn3; // 0x47 0x00, 0xb2 0x00...
    uint16_t payload_size; // Size of the rest of the item
    uint8_t *payload[0];
} __attribute__((packed));

#endif
