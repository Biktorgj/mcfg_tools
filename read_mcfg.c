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
size_t ELF_OFFSET;
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

/* Example footer
    ......                         ..u32 len..?...u32 id..
00002b40  02 00 04 00 01 00 00 00  4e 00 00 00 0a 00 00 00  |........N.......|
          footer len?  M  C  F  G   _  T  R  L  0   2    256-> 
00002b50  a1 00 3e 00 4d 43 46 47  5f 54 52 4c 00 02 00 00  |..>.MCFG_TRL....|
           >  1     4      33625405   2    4    460    1    3 
00002b60  01 01 04 00 3d 15 01 02  02 04 00 cc 01 01 00 03  |....=...........|
           19  C  o  m  m  e  r   c  i  a  l   -  C U  -
00002b70  13 00 43 6f 6d 6d 65 72  63 69 61 6c 2d 43 55 2d  |..Commercial-CU-|
           C S  -  S  S   4   10      0    2   898601     898601
00002b80  43 53 2d 53 53 04 0a 00  00 02 29 b6 0d 00 29 b6  |CS-SS.....)...).|
00002b90  0d 00 00 00 50 00 00 00                           |....P...|
00002b98

4e000000 <-- len
0a000000 <-- const
a100 <-- const
3e00 <-- changes
MCFG_TRL
00 02 00 <-- const

*/
int dump_contents() {
  uint8_t tmpbuffer[sz];
  for (int i = 0; i < mcfg_file.no_of_items - 1; i++) {
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
    default:
      fprintf(stderr, "I'm broken (type %i):(\n", item->type);
      break;
    }
  }

  fprintf(stdout, "File footer (don't know how to handle this\n");
  for (int k = current_file_offset; k < sz; k++) {
    fprintf(stdout, "%.2x ", file_buff[k]);
  }
  fprintf(stdout, "\n");
  struct mcfg_footer *footer = (struct mcfg_footer *)(file_buff+current_file_offset);
  fprintf(stdout, "Checking in: %s, size %i bytes\n", footer->magic, footer->len);
  current_file_offset+=sizeof(struct mcfg_footer);
  struct mcfg_footer_section_0 *sec0 = (struct mcfg_footer_section_0 *)(file_buff+current_file_offset);
  fprintf(stdout, "Footer section 0 id %i of size %i, data %i\n", sec0->id, sec0->len, sec0->data);
  current_file_offset+=sizeof(struct mcfg_footer_section_0);
  struct mcfg_footer_section_1 *sec1 = (struct mcfg_footer_section_1 *)(file_buff+current_file_offset);
  fprintf(stdout, "Footer section 1 id %i of size %i, data %i\n", sec1->id, sec1->len, sec1->data);
  current_file_offset+=sizeof(struct mcfg_footer_section_1);
  struct mcfg_footer_section_2 *sec2 = (struct mcfg_footer_section_2 *)(file_buff+current_file_offset);
  fprintf(stdout, "Footer section 2 id %i of size %i, MCC-MNC %i-%i\n", sec2->id, sec2->len, sec2->mcc, sec2->mnc);
  current_file_offset+=sizeof(struct mcfg_footer_section_2);
  struct mcfg_footer_section_3 *sec3 = (struct mcfg_footer_section_3 *)(file_buff+current_file_offset);
  fprintf(stdout, "Footer section 3 id %i of size %i, name %s\n", sec3->id, sec3->len, sec3->carrier_config_name);
  current_file_offset+=sizeof(struct mcfg_footer_section_3) + sec3->len;
  struct mcfg_footer_section_4 *sec4 = (struct mcfg_footer_section_4 *)(file_buff+current_file_offset);
  fprintf(stdout, "Footer section 4 id %i of size %i, data %i\n", sec4->id, sec4->len, sec4->iccids[0]);
  
  return 0;
}

int main(int argc, char *argv[]) {
  char *input_file;
  int c;
  FILE *fp;
  ELF_OFFSET = 0;
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

  for (int k = 0 ; k < sz; k++) {
    if (file_buff[k] == 'M' && 
        file_buff[k+1] == 'C' && 
        file_buff[k+2] == 'F' && 
        file_buff[k+3] == 'G') {
          ELF_OFFSET = k;
          break;
        }
  }
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