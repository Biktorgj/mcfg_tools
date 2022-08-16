#include "mcfg.h"
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint8_t *file_buff;
size_t sz;
size_t current_file_offset;
size_t prev_file_offset;
struct mcfg_file_header mcfg_file;

/* So, some notes here:
1. 16 byte header
2. A second header, seemingly 8 byte in size
Then we have some sort of encapsulated QMI like message, with
[uint32_t],[u8],[u8],0x00,0x00,[u16] ID,[u16] Length and [u8*]data
There are some magic numbers for whatever the type of the data is
So, first things we get the header to know the number of items





*/
void showHelp() {
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, "  read_mcfg -i INPUT_FILE \n");
  fprintf(stdout, "Arguments: \n"
                  "\t-i: Input file to read\n");
}

int check_file_header() {
  struct mcfg_file_header *mcfg_head;
  mcfg_head = (struct mcfg_file_header *)(file_buff + ELF_OFFSET);
  if (memcmp(mcfg_head->magic, MCFG_FILE_HEADER_MAGIC, 4) == 0) {
    fprintf(stdout,
            "Header is OK:\n"
            "\t- Magic: %s \n"
            "\t- Format: %i \n"
            "\t- Config type: %s\n"
            "\t- Number of elements in file: %i\n",
            mcfg_head->magic, mcfg_head->format_version,
            mcfg_head->config_type < 1 ? "HW" : "SW", mcfg_head->no_of_items);
    mcfg_file.no_of_items = mcfg_head->no_of_items;
    mcfg_file.config_type = mcfg_head->config_type;
    mcfg_file.format_version = mcfg_head->format_version;

    // First element is some kind of subheader with the carrier name?
    // Offset gets poluted with nv data
    struct mcfg_sub_version_data *version =
        (struct mcfg_sub_version_data *)(file_buff + ELF_OFFSET +
                                         sizeof(struct mcfg_file_header));
    if (version->version == VERSION_NUM) {
      fprintf(stdout, "Version is %.4x |%.4x |%.2x |%.2x\n", version->unknown1,
              version->unknown2, version->unknown3, version->unknown4);
      current_file_offset = ELF_OFFSET + sizeof(struct mcfg_file_header) +
                            sizeof(struct mcfg_sub_version_data);
    } else {
      fprintf(stderr, "Oopsies, something is wrong\n");
      return -EINVAL;
    }
    version = NULL;

    fprintf(stdout, "--------------------------\n");
  } else {
    fprintf(stderr, "ERROR: Header doesn't match\n");
    return -EINVAL;
  }
  return 0;
}
/*
Example EFS/NV item:
                                               ........... We start here, u32 ID
00002180  02 00 08 00 05 00 00 00  00 01 00 00 29 00 00 00  |............)...|
          u1 u2 [pad] fname u16sz  <----------------------
00002190  02 09 00 00 01 00 12 00  2f 73 64 2f 72 61 74 5f  |......../sd/rat_|
          -----------------------------> fcont u16sz <----
000021a0  61 63 71 5f 6f 72 64 65  72 00 02 00 07 00 03 e7  |acq_order.......|
          -------------> || NEXT FILE...
000021b0  00 03 09 05 03 39 00 00  00 02 09 00 00 01 00 27  |.....9.........'|
*/
/* Example NV Item type
    ....                          ..u32 id...  ty at padd
00002010  83 13 04 00 3d 15 01 02  19 00 00 00 01 09 00 00  |....=...........|
          nvid  len   <--------payload of (len)-----------
00002020  47 00 0d 00 43 68 69 6e  61 55 6e 69 63 6f 6d 00  |G...ChinaUnicom.|
          -> ..u32 id..  ty at paddin nvid  len   paylo
00002030  00 0e 00 00 00 01 09 00  00 4a 00 02 00 01 01 0e  |.........J......|
00002040  00 00 00 01 09 00 00 4b  00 02 00 01 01 0f 00 00  |.......K........|
00002050  00 01 29 00 00 50 03 03  00 00 02 00 0f 00 00 00  |..)..P..........|
*/
int dump_contents() {
  uint8_t tmpbuffer[sz];
  for (int i = 0; i < mcfg_file.no_of_items; i++) {
    struct mcfg_item *item;
    item = (struct mcfg_item *)(file_buff + current_file_offset);

    fprintf(stdout, "[%s]: Item %i, type %.2x, attributes %.2x \n", __func__, i,
            item->type, item->attrib);
    struct mcfg_nvitem *tmpnvitem;
    struct mcfg_nvfile_part *this_file_part;
    current_file_offset += sizeof(struct mcfg_item);
    switch (item->type) {
    case MCFG_ITEM_TYPE_NV:
      tmpnvitem = (struct mcfg_nvitem *)(file_buff + current_file_offset);
      fprintf(stdout, "NV Item at offset %ld of size %i: ", current_file_offset,
              tmpnvitem->payload_size);
      memset(tmpbuffer, 0, sz);
      memcpy(tmpbuffer, tmpnvitem->payload, tmpnvitem->payload_size);
      for (int k = 0; k < tmpnvitem->payload_size; k++) {
        fprintf(stdout, "%c ", tmpbuffer[k]);
      }
      fprintf(stdout, "\n");
      current_file_offset +=
          sizeof(struct mcfg_nvitem) + tmpnvitem->payload_size;
      tmpnvitem = NULL;
      // Do stuff
      break;
    case MCFG_ITEM_TYPE_NVFILE:
    case MCFG_ITEM_TYPE_FILE:
      for (int k = 0; k < 2; k++) {
        this_file_part =
            (struct mcfg_nvfile_part *)(file_buff + current_file_offset);
        switch (this_file_part->file_section) {
        case EFS_FILENAME:
          // FILE NAME
          fprintf(stdout,
                  "File at offset %ld of size %i: ", current_file_offset,
                  this_file_part->section_len);
          memset(tmpbuffer, 0, sz);
          memcpy(tmpbuffer, this_file_part->payload,
                 this_file_part->section_len);
          for (int k = 0; k < this_file_part->section_len; k++) {
            fprintf(stdout, "%c", tmpbuffer[k]);
          }
          fprintf(stdout, "\n");
          current_file_offset +=
              sizeof(struct mcfg_nvfile_part) + this_file_part->section_len;
          this_file_part = NULL;
          break;
        case EFS_FILECONTENTS:
          // FILE CONTENTS
          this_file_part =
              (struct mcfg_nvfile_part *)(file_buff + current_file_offset);
          fprintf(stdout,
                  "Contents at offset %ld of size %i: ", current_file_offset,
                  this_file_part->section_len);
          memset(tmpbuffer, 0, sz);
          memcpy(tmpbuffer, this_file_part->payload,
                 this_file_part->section_len);
          for (int k = 0; k < this_file_part->section_len; k++) {
            fprintf(stdout, "%.2x ", tmpbuffer[k]);
          }
          fprintf(stdout, "\n");
          current_file_offset +=
              sizeof(struct mcfg_nvfile_part) + this_file_part->section_len;
          this_file_part = NULL;
          break;
        }
      }

      break;
    case MCFG_ITEM_TYPE_TRAIL:
      fprintf(stdout, "File footer (don't know how to handle this\n");
      for (int k = current_file_offset; k < sz; k++) {
        fprintf(stdout, "%.2x ", file_buff[k]);
      }
      fprintf(stdout, "\n");
      break;
    default:
      fprintf(stderr, "I'm broken (type %i):(\n", item->type);
      break;
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  char *input_file;
  int c;
  FILE *fp;
  fprintf(stdout, "Qualcomm MCFG binary file reader \n");
  if (argc < 2) {
    showHelp();
    return 0;
  }

  while ((c = getopt(argc, argv, "i:")) != -1)
    switch (c) {
    case 'i':
      if (optarg == NULL) {
        fprintf(stderr, "You need to give me something to work with\n");
        return 0;
      }
      input_file = optarg;
      break;
    case 'h':
    default:
      showHelp();
      return 0;
    }

  fp = fopen(input_file, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error opening input file %s\n", input_file);
    return 1;
  }
  fseek(fp, 0L, SEEK_END);
  sz = ftell(fp);
  file_buff = malloc(sz);
  fseek(fp, 0L, SEEK_SET);
  fread(file_buff, sz, 1, fp);

  current_file_offset = prev_file_offset = 0;
  fclose(fp);
  if (check_file_header() < 0) {
    free(file_buff);
    return 1;
  }

  if (dump_contents() < 0) {
    free(file_buff);
    return 1;
  }
  free(file_buff);
  return 0;
}