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

void showHelp() {
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, "  read_mcfg -i INPUT_FILE \n");
  fprintf(stdout, "Arguments: \n"
                  "\t-i: Input file to read\n");
}

int check_file_header() {
  struct mcfg_file_header *mcfg_head;
  mcfg_head = (struct mcfg_file_header *)(file_buff + ELF_OFFSET);
  struct mcfg_config_item *tptr;
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
    tptr = (struct mcfg_config_item*) (file_buff + ELF_OFFSET + sizeof(struct mcfg_file_header));

    for (int i = 0; i < mcfg_head->no_of_items; i++) {
        fprintf(stdout, "Trying to read item %i...\n", i);
        switch (tptr->item_id) {
            case VERSION_DATA:
                fprintf(stdout, "Version data, size %i\n", tptr->payload_size);
                break;
        }
    }
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