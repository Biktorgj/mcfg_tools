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
    
    // First element is some kind of subheader with the carrier name?
    struct mcfg_sub_version_data *version = (struct mcfg_sub_version_data *)(file_buff + ELF_OFFSET + sizeof(struct mcfg_file_header));
    if (version->version == VERSION_NUM) {
        fprintf(stdout, "Version is %.4x |%.4x |%.2x |%.2x\n", version->unknown1, version->unknown2, version->unknown3, version->unknown4);
    } else {
        fprintf(stderr, "Oopsies, something is wrong\n");
        return -EINVAL;
    }
    version = NULL;
    
    
    // We assign the first element by hand, then we will go moving the offset as we parse
    tptr = (struct mcfg_item*) (file_buff + ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data));
    int newoffset = 0;
    for (int i = 0; i < mcfg_head->no_of_items; i++) {
        fprintf(stdout, "Trying to read item %i...\n", i);
        fprintf(stdout, "Item ID: %.4x | u1: %.2x | u2 %.2x\n", tptr->item_id, tptr->u1, tptr->u2);
        fprintf(stdout, "Item inside: %.4x of size %.4x\n", tptr->item.id, tptr->item.payload_size);
        uint8_t buffer[256];
        if (tptr->item.payload_size < 256)
            memcpy(buffer, tptr->item.payload, tptr->item.payload_size);
        fprintf(stdout, "Payload: %s\n", buffer);


        newoffset+= (sizeof(struct mcfg_item)+ htole16(tptr->item.payload_size ));
        tptr = (struct mcfg_item*) (file_buff + ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data) +newoffset);
    }
    // End of the file
    fprintf(stdout, "end of the file:\n");
    for (int k = (ELF_OFFSET + sizeof(struct mcfg_file_header)+ sizeof(struct mcfg_sub_version_data) +newoffset); k < sz; k++) {
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
  fclose(fp);
  if (check_file_header() < 0) {
    free(file_buff);
    return 1;
  }

  free(file_buff);
  return 0;
}