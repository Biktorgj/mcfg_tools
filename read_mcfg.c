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
    struct mcfg_sub_version_data *version = (struct mcfg_sub_version_data *)(file_buff + ELF_OFFSET + sizeof(struct mcfg_file_header));
    if (version->version == VERSION_NUM) {
        fprintf(stdout, "Version is %.4x |%.4x |%.2x |%.2x\n", version->unknown1, version->unknown2, version->unknown3, version->unknown4);
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

int dump_contents() {
  fprintf(stdout, "[%s:%i]: Start \n", __func__, __LINE__);
  return 0;
  struct mcfg_file_header *mcfg_head;
  mcfg_head = (struct mcfg_file_header *)(file_buff + ELF_OFFSET);
  struct mcfg_item *tptr;
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
    struct mcfg_sub_version_data *version = (struct mcfg_sub_version_data *)(file_buff + ELF_OFFSET + sizeof(struct mcfg_file_header));
    if (version->version == VERSION_NUM) {
        fprintf(stdout, "Version is %.4x |%.4x |%.2x |%.2x\n", version->unknown1, version->unknown2, version->unknown3, version->unknown4);
    } else {
        fprintf(stderr, "Oopsies, something is wrong\n");
        return -EINVAL;
    }
    version = NULL;
    
    fprintf(stdout, "--------------------------\n");
    // We assign the first element by hand, then we will go moving the offset as we parse
    tptr = (struct mcfg_item*) (file_buff + ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data));
    current_file_offset = ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data);

    size_t newoffset = 0;
    
    // I'm not counting as I should
    for (int i = 0; i < mcfg_head->no_of_items; i++) {
        fprintf(stdout, "Item #%i\n", i);
        fprintf(stdout, " |- Block ID: %.8x \n |- u1: %.2x\n |- u2: %.2x\n", tptr->item_id, tptr->u1, tptr->u2);
        fprintf(stdout, " |-- Item: %.4x of size %.4x\n", tptr->item.id, tptr->item.payload_size);
        uint8_t buffer[4096];
        memset(buffer, 0, 4096);
        if (tptr->item.payload_size < 4096)
            memcpy(buffer, tptr->item.payload, tptr->item.payload_size);
        fprintf(stdout, " |-- Payload: %s\n", buffer);
        if (tptr->u1 == 0x02 && tptr->u2 == 0x09) {
            fprintf(stdout, " |-- NV Item: %s\n", buffer);

        }
        switch(tptr->u1) {
            case MCFG_ITEM_TYPE_NV:
            fprintf(stdout, "MCFG_ITEM_TYPE_NV: %s\n", buffer);

            break;
            case MCFG_ITEM_TYPE_NVFILE:
            fprintf(stdout, "MCFG_ITEM_TYPE_NVFILE: %s\n", buffer);
            
            break;
            case MVFG_ITEM_TYPE_FILE:
            fprintf(stdout, "MVFG_ITEM_TYPE_FILE: %s\n", buffer);
            break;
            default:
            fprintf(stdout, "Unkonwn ID %.4x\n", tptr->item.id);
            break;
        }

        newoffset+= (sizeof(struct mcfg_item)+ htole16(tptr->item.payload_size ));
        fprintf(stdout, " * Next offset: %ld\n", ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data) +newoffset);
        if (ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data) +newoffset > sz) {
          fprintf(stdout, "Err: overflowed!\n");
          return 1;
        }
        tptr = (struct mcfg_item*) (file_buff + ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data) +newoffset);
    }
    // End of the file
    size_t curr_position = (ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data) +newoffset);
    fprintf(stdout, "end of the file: (%ld from %ld)\n", curr_position, sz);
    for (size_t k = curr_position; k < sz; k++) {
        fprintf(stdout, "%.2x ", file_buff[k]);
    }
    fprintf(stdout, "\n");
  } else {
    fprintf(stderr, "ERROR: Header doesn't match\n");
    return -EINVAL;
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