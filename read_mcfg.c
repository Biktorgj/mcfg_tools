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
  fprintf(stdout, "Qualcomm MCFG binary file reader \n");
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, "  read_mcfg -i INPUT_FILE \n");
  fprintf(stdout, "Arguments: \n"
                  "\t-i: Input file to read\n");
}

void parse_data() {
  fprintf(stdout, "PARSE\n");
  struct mcfg_file_header *mcfg_head;
  mcfg_head = (struct mcfg_file_header *)(file_buff + ELF_OFFSET);
  if (memcmp(mcfg_head->magic, MCFG_FILE_HEADER_MAGIC, 4) != 0) {
    fprintf(stderr, "ERROR: Header doesn't match\n");
    return;
  } else {
    fprintf(stdout,
            "Header match:\n"
            "\tMagic: %s \n"
            "\tFormat: %i \n"
            "\tConfig type: %s\n"
            "\tNumber of elements: %i\n",
            mcfg_head->magic, mcfg_head->format_version,
            mcfg_head->config_type < 1 ? "HW" : "SW", mcfg_head->no_of_items);
  }

}

int main(int argc, char *argv[]) {
  char *input_file;
  int c;
  FILE *fp;
  fprintf(stdout, "%s: Oh hai!\n", __func__);
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

  fprintf(stdout, "\tInput file: %s\n", input_file);
  fp = fopen(input_file, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error opening input file %s\n", input_file);
    return 1;
  }
  fseek(fp, 0L, SEEK_END);
  sz = ftell(fp);
  file_buff = malloc(sz);
  fprintf(stdout, "Allocated size: %ld bytes\n", sz);
  fseek(fp, 0L, SEEK_SET);
  fread(file_buff, sz, 1, fp);
  fclose(fp);
  fprintf(stdout, "Got the file!\n");
  parse_data();
  free(file_buff);
  return 0;
}