#include "mcfg.h"
#include "nvitems.h"
#include "sha256.h"
#include <asm-generic/errno-base.h>
#include <ctype.h>
#include <endian.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NUM_ITEMS 512
#define MAX_PATH_SIZE 1024
// Settings
uint8_t debug;

// Input file: dumplist
struct mcfg_dump_list_proto {
  uint32_t id;
  uint8_t type;
  uint8_t attrib;
  uint32_t size;
  char filename[MAX_PATH_SIZE];
  uint8_t blob[MAX_OBJ_SIZE];
  char diskpath[MAX_PATH_SIZE];
} mcfg_dump_list[MAX_NUM_ITEMS];
uint32_t num_elements;

size_t INPUT_ELF_OFFSET;
FILE *file_in;
uint8_t *file_in_buff;
uint32_t file_in_sz;
/* We use these to calculate the output buffer size */
uint32_t input_nvitems_size;
uint32_t input_footer_size;

struct Elf32_Ehdr *elf_hdr_in;
struct elf32_phdr *ph0_in;
struct elf32_phdr *ph1_in;
struct elf32_phdr *ph2_in;
struct hash_segment_header *hash_in;
struct mcfg_file_header *mcfg_head_in;
struct mcfg_sub_version_data *mcfg_sub_in;
struct mcfg_footer_section footer_items[MAX_FOOTER_SECTIONS];
// Output file
FILE *file_out;
struct Elf32_Ehdr *elfbuf;
struct elf32_phdr *ph0;
struct elf32_phdr *ph1;
struct elf32_phdr *ph2;
struct hash_segment_header *hash;
struct mcfg_file_header *mcfg_head_out;
struct mcfg_sub_version_data *mcfg_sub_out;
struct mcfg_footer *footer_out;

uint8_t *file_out_buff;
uint32_t file_out_sz;

struct mcfg_file_meta {
  uint32_t elf_offset;
  uint32_t ph0_offset;
  uint32_t ph1_offset;
  uint32_t ph2_offset;
  uint32_t hash_offset;
  uint32_t mcfg_start_offset;
  uint32_t mcfg_footer_offset;
};

void print_help() {
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, "  pack_mcfg -i INPUT_FILE -o OUTPUT_FILE\n");
  fprintf(stdout, "Arguments: \n"
                  "\t-i: Input dump list file\n"
                  "\t-o: Output file\n"
                  "\t-d: Print hex dumps\n");
}

int make_elf_header(uint32_t offset) {
  elfbuf = (struct Elf32_Ehdr *)file_out_buff + offset;
  memcpy(elfbuf->e_ident, ELFMAG, 4);
  elfbuf->e_ident[4] = 0x01;
  elfbuf->e_ident[5] = 0x01;
  elfbuf->e_ident[6] = 0x01;
  elfbuf->e_type = 2;
  elfbuf->e_machine = 0;
  elfbuf->e_version = 1;
  elfbuf->e_entry = 0;
  elfbuf->e_phoff = 0x0034;
  elfbuf->e_shoff = 0;
  elfbuf->e_flags = 5;
  elfbuf->e_ehsize = 52;
  elfbuf->e_phentsize = 32;
  elfbuf->e_phnum = 3;
  elfbuf->e_shentsize = 40;
  elfbuf->e_shnum = 0;
  elfbuf->e_shstrndx = 0;
  if (debug) {
    fprintf(stdout, "ELF Header hex dump:\n");
    int count = 0;
    for (int i = 0; i < sizeof(struct Elf32_Ehdr); i++) {
      fprintf(stdout, "%.2x ", file_out_buff[i]);
      count++;
      if (count > 15) {
        fprintf(stdout, "\n");
        count = 0;
      }
    }
    fprintf(stdout, "\n");
  }
  return sizeof(struct Elf32_Ehdr);
}

/*
 * MCFG_SW files use 3 program headers
 */
int make_default_program_headers(uint32_t offset) {

  // First header
  int totalsize = 3 * sizeof(struct elf32_phdr);
  fprintf(stdout, "Program Headers: %ld bytes each, %i bytes total\n",
          sizeof(struct elf32_phdr), totalsize);
  ph0 = (struct elf32_phdr *)(file_out_buff + offset);
  ph0->p_filesz = 0;        // Gets filled later, size of the elf+ph headers
  ph0->p_flags = 0x7000000; // This one stays

  // This header indicates where the SHA256 signatures are stored
  ph1 =
      (struct elf32_phdr *)(file_out_buff + offset + sizeof(struct elf32_phdr));
  ph1->p_offset = 0x1000; // Offset 1 at 4096 bytes
  ph1->p_vaddr = 0x5000;
  ph1->p_paddr = 0x5000;
  ph1->p_filesz = 0; // Gets filled later
  ph1->p_flags = 0x2200000;
  ph1->p_align = 4096;   // 4096
  ph1->p_memsz = 0x1000; // Address where the hashes are

  // This header indicates where does the actual MCFG data start
  ph2 = (struct elf32_phdr *)(file_out_buff + offset +
                              (2 * sizeof(struct elf32_phdr)));
  ph2->p_type = 1;
  ph2->p_offset = 0x2000; // Our entry point is at 8192 bytes
  ph2->p_vaddr = 0;
  ph2->p_paddr = 0;
  ph2->p_filesz = 0; // Gets filled later, size of the actual MCFG file
  ph2->p_memsz = 0;  // Gets filled later, size of the actual MCFG file
  ph2->p_flags = 0x6;
  ph2->p_align = 4;

  return totalsize;
}

/*
 * Make hash structure with placeholders.
 */

int make_default_hash_headers(uint32_t offset) {
  fprintf(stdout, " - Building default hash structure\n");
  int size = sizeof(struct hash_segment_header);
  hash = (struct hash_segment_header *)(file_out_buff + offset);

  hash->version = 0x00;
  hash->type = 0x03;
  hash->flash_addr = 0x00;
  hash->dest_addr = 0x5028;
  hash->total_size = 0x60;
  hash->hash_size = 0x60;
  hash->signature_addr = 0x5088;
  hash->signature_size = 0x00;
  hash->cert_chain_addr = 0x5088;
  hash->cert_chain_size = 0x00;
  // We can't yet calculate the hash here
  return size;
}

int make_mcfg_header(uint32_t offset) {
  int size = offset + sizeof(struct mcfg_file_header) +
             sizeof(struct mcfg_sub_version_data);
  mcfg_head_out = (struct mcfg_file_header *)(file_out_buff + offset);
  mcfg_sub_out =
      (struct mcfg_sub_version_data *)(file_out_buff +
                                       (offset +
                                        sizeof(struct mcfg_file_header)));
  /* HEADER */
  memcpy(mcfg_head_out->magic, MCFG_FILE_HEADER_MAGIC, 4);
  mcfg_head_out->config_type = 1;
  mcfg_head_out->format_version = 3;
  mcfg_head_out->no_of_items = num_elements; // We need to account for the header
  mcfg_head_out->carrier_id = mcfg_head_in->carrier_id;
  mcfg_head_out->padding = 0x00;

  /* Whatever this is */
  mcfg_sub_out->magic = SUB_MAGIC_NUM;
  mcfg_sub_out->len = 4;
  mcfg_sub_out->carrier_version = mcfg_sub_in->carrier_version;

  return size;
}

int recreate_output_file_hash() {
  int shabufsize =
      sizeof(struct Elf32_Ehdr) + (elfbuf->e_phnum * sizeof(struct elf32_phdr));
  uint8_t shabuf[shabufsize];
  memcpy(shabuf, file_out_buff, sizeof(struct Elf32_Ehdr));
  memcpy(shabuf + sizeof(struct Elf32_Ehdr), file_out_buff + elfbuf->e_phoff,
         elfbuf->e_phnum * sizeof(struct elf32_phdr));

  /* Compute SHA-256 sum. */
  // Hash 1:
  char hex_hash1[SHA256_HEX_SIZE];
  char hex_hash2[SHA256_HEX_SIZE];
  sha256_hex((shabuf), shabufsize, hex_hash1);
  sha256_bytes((shabuf), shabufsize, hash->hash1);

  // Hash 2:
  sha256_hex((file_out_buff + MCFG_DATA_OFFSET), file_out_sz - MCFG_DATA_OFFSET,
             hex_hash2);
  sha256_bytes((file_out_buff + MCFG_DATA_OFFSET),
               file_out_sz - MCFG_DATA_OFFSET, hash->hash2);

  /* Print result. */
  printf("  - Hash 1 (headers) SHA-256 sum is: %s\n", hex_hash1);
  printf("  - Hash 2 (contents) SHA-256 sum is: %s\n", hex_hash2);
  return 0;
}

void print_elf_data(char *text, struct Elf32_Ehdr *elf_hdr) {
  fprintf(stdout, "%s: Elf header details:\n", text);
  fprintf(stdout, " * Type: %x\n", elf_hdr->e_type);
  fprintf(stdout, " * Machine: %x\n", elf_hdr->e_machine);
  fprintf(stdout, " * Version: %x\n", elf_hdr->e_version);
  fprintf(stdout, " * Entry: %x\n", elf_hdr->e_entry);
  fprintf(stdout, " * Program headers offset: %x\n", elf_hdr->e_phoff);
  fprintf(stdout, " * Section headers offset: %i\n", elf_hdr->e_shoff);
  fprintf(stdout, " * Flags: %x\n", elf_hdr->e_flags);
  fprintf(stdout, " * ELF Header size: %i\n", elf_hdr->e_ehsize);
  fprintf(stdout, " * Program header size: %i\n", elf_hdr->e_phentsize);
  fprintf(stdout, " * Program header num: %x\n", elf_hdr->e_phnum);
  fprintf(stdout, " * Section header size: %i\n", elf_hdr->e_shentsize);
  fprintf(stdout, " * Section header num: %x\n", elf_hdr->e_shnum);
  fprintf(stdout, " * Section header idx: %x\n", elf_hdr->e_shstrndx);
}

void print_ph_data(char *text, int i, struct elf32_phdr *phdr) {
  fprintf(stdout, "%s: Program header %i details:\n", text, i);
  fprintf(stdout, " * p_type %x\n", phdr->p_type);
  fprintf(stdout, " * p_offset at %i bytes (0x%x)\n", phdr->p_offset,
          phdr->p_offset);
  fprintf(stdout, " * p_vaddr %x\n", phdr->p_vaddr);
  fprintf(stdout, " * p_paddr %x\n", phdr->p_paddr);
  fprintf(stdout, " * p_filesz %i\n", phdr->p_filesz);
  fprintf(stdout, " * p_memsz %x\n", phdr->p_memsz);
  fprintf(stdout, " * p_flags 0x%x\n", phdr->p_flags);
  fprintf(stdout, " * p_align %i\n", phdr->p_align);
}

void print_hash_data(char *text, struct hash_segment_header *hash_segment) {
  fprintf(stdout, "%s: Hash section:\n", text);
  fprintf(stdout, " * Version %x \n", hash_segment->version);
  fprintf(stdout, " * type %x \n", hash_segment->type);
  fprintf(stdout, " * flash_addr %x \n", hash_segment->flash_addr);
  fprintf(stdout, " * dest_addr %x \n", hash_segment->dest_addr);
  fprintf(stdout, " * total_size %x \n", hash_segment->total_size);
  fprintf(stdout, " * hash_size %x \n", hash_segment->hash_size);
  fprintf(stdout, " * signature_addr %x \n", hash_segment->signature_addr);
  fprintf(stdout, " * signature_size %x \n", hash_segment->signature_size);
  fprintf(stdout, " * cert_chain_addr %x \n", hash_segment->cert_chain_addr);
  fprintf(stdout, " * cert_chain_size %x \n", hash_segment->cert_chain_size);
  for (int i = 0; i < 32; i++) {
    fprintf(stdout, "%.2x ", hash_segment->hash1[i]);
  }
  fprintf(stdout, " hash1 \n");
  for (int i = 0; i < 32; i++) {
    fprintf(stdout, "%.2x ", hash_segment->hash2[i]);
  }

  fprintf(stdout, "\n");
}

int prepare_output_file(char *output_file) {
  file_out = fopen(output_file, "wb");
  if (file_out == NULL) {
    fprintf(stderr, "Error creating output file %s!\n", output_file);
    return -EINVAL;
  }
  return 0;
}

/* Do various checks and set pointers to the primary sections of the input file
 */
int check_input_file() {
  /*
   * We know MCFG must start at least at 0x2000 bytes without signature, or
   * 0x3000 with it So for now it's enough to check for the minimum size and do
   * more checks later on
   */
  if (file_in_sz < 0x2000) {
    fprintf(stderr, "Error: File is to small!\n");
    return -EINVAL;
  }

  fprintf(stdout, "Checking ELF header... ");
  elf_hdr_in = (struct Elf32_Ehdr *)file_in_buff;
  if (memcmp(elf_hdr_in->e_ident, ELFMAG, 4) != 0) {
    fprintf(stderr, "Error: ELF header doesn't match!\n");
    return -EINVAL;
  }
  fprintf(stdout, "OK!\n");
  if (debug) {
    fprintf(stdout, "ELF Header hex dump:\n");
    int count = 0;
    for (int i = 0; i < sizeof(struct Elf32_Ehdr); i++) {
      fprintf(stdout, "%.2x ", file_in_buff[i]);
      count++;
      if (count > 15) {
        fprintf(stdout, "\n");
        count = 0;
      }
    }
    fprintf(stdout, "\n");
  }
  fprintf(stdout, "Checking program headers... \n");
  if (elf_hdr_in->e_phnum < 3) {
    fprintf(stderr,
            "Error: Not enough program headers, is this a valid file?\n");
    return -EINVAL;
  }
  /* Program headers */
  fprintf(stdout, "ELF PH0 Offset: 0x%.4x %i\n", elf_hdr_in->e_phoff,
          elf_hdr_in->e_phoff);
  ph0_in =
      (struct elf32_phdr *)(file_in_buff + (elf_hdr_in->e_phoff +
                                            0 * (sizeof(struct elf32_phdr))));
  fprintf(stdout, " - ELF data should be at %i bytes (file is %i bytes)\n",
          ph0_in->p_offset, file_in_sz);
  if (file_in_sz < ph0_in->p_offset) {
    fprintf(stderr, "Error: Offset is either bigger than the file or at the "
                    "end of it! (PH0)\n");
    return -EINVAL;
  }
  /* Now we check the program header */
  ph1_in =
      (struct elf32_phdr *)(file_in_buff + (elf_hdr_in->e_phoff +
                                            1 * (sizeof(struct elf32_phdr))));
  fprintf(stdout,
          " - Hash data data should be at %i bytes (file is %i bytes)\n",
          ph1_in->p_offset, file_in_sz);
  if (file_in_sz < ph1_in->p_offset) {
    fprintf(stderr, "Error: Offset is either bigger than the file or at the "
                    "end of it! (PH1)\n");
    return -EINVAL;
  }

  /* Now we check the program header */
  ph2_in =
      (struct elf32_phdr *)(file_in_buff + (elf_hdr_in->e_phoff +
                                            2 * (sizeof(struct elf32_phdr))));
  fprintf(stdout, " - MCFG data should be at %i bytes (file is %i bytes)\n",
          ph2_in->p_offset, file_in_sz);
  if (file_in_sz < ph2_in->p_offset) {
    fprintf(stderr, "Error: Offset is either bigger than the file or at the "
                    "end of it! (PH2)\n");
    return -EINVAL;
  }

  hash_in = (struct hash_segment_header *)(file_in_buff + ph1_in->p_offset);
  fprintf(stdout, " - Checking MCFG header and data... ");
  /* And finally we check if we have the magic string in its expected position
   */
  mcfg_head_in = (struct mcfg_file_header *)(file_in_buff + ph2_in->p_offset);
  if (memcmp(mcfg_head_in->magic, MCFG_FILE_HEADER_MAGIC, 4) != 0) {
    fprintf(stderr, "Error: Invalid  MCFG file MAGIC!\n");
    return -EINVAL;
  }
  mcfg_sub_in =
      (struct mcfg_sub_version_data *)(file_in_buff + ph2_in->p_offset +
                                       sizeof(struct mcfg_file_header));

  fprintf(stdout, "Found it!\n");
  fprintf(stdout, "   - Format version: %i\n", mcfg_head_in->format_version);
  fprintf(stdout, "   - Configuration type: %s\n",
          mcfg_head_in->config_type < 1 ? "HW Config" : "SW Config");
  fprintf(stdout, "   - Number of items in config: %i\n",
          mcfg_head_in->no_of_items);
  fprintf(stdout, "   - Carrier ID %i \n", mcfg_head_in->carrier_id);
  fprintf(stdout, "   - Sub-header data:\n");
  fprintf(stdout, "     - Magic: %x\n", mcfg_sub_in->magic);
  fprintf(stdout, "     - Size: %i\n", mcfg_sub_in->len);
  fprintf(stdout, "     - Data: %.8x\n", mcfg_sub_in->carrier_version);

  if (mcfg_head_in->config_type != MCFG_FILETYPE_SW) {
    fprintf(stderr,
            "Error: Sorry, this program does not support HW filetypes\n");
    return -EINVAL;
  }

  fprintf(stdout, "File is OK!\n");
  return 0;
}

int repack_mcfg_data() {
  file_out_sz = 0;
  input_nvitems_size = 0;
  input_footer_size = 0;
  file_in_sz = mcfg_dump_list[0].size;
  file_in_buff = malloc(file_in_sz);
  memcpy(file_in_buff, mcfg_dump_list[0].blob, file_in_sz);
  char *tmptr = NULL;
  if (check_input_file() < 0) {
    fprintf(stderr, "FATAL: Error parsing the header file!(\n");
    return -EINVAL;
  }

  for (int i = 1; i < num_elements; i++) {
    if (mcfg_dump_list[i].type == MCFG_ITEM_TYPE_FOOT) {
      input_footer_size = mcfg_dump_list[i].size;
    } else if (mcfg_dump_list[i].type == MCFG_ITEM_TYPE_NV) {
    //  input_nvitems_size += sizeof(struct mcfg_item);
     // input_nvitems_size += sizeof(struct mcfg_nvitem);
      input_nvitems_size+= mcfg_dump_list[i].size;
    } else if (mcfg_dump_list[i].type == MCFG_ITEM_TYPE_NVFILE ||
               mcfg_dump_list[i].type == MCFG_ITEM_TYPE_FILE) {
    //  input_nvitems_size += sizeof(struct mcfg_item); // Item
    //  input_nvitems_size += sizeof(struct mcfg_nvfile_part); // File path descriptor + contents
      input_nvitems_size+= mcfg_dump_list[i].size; // Contents
      printf("This is a efs item (%i): %s\n", i, mcfg_dump_list[i].filename);
      tmptr = mcfg_dump_list[i].filename;
      while (tmptr) {
        if (*tmptr == '/') {
          input_nvitems_size += strlen(tmptr)-1; // Path in section 1
          printf("Filepath: %s %ld\n", tmptr, strlen(tmptr) -1);
          memcpy(mcfg_dump_list[i].diskpath, tmptr, strlen(tmptr)-1);
          break;
        } else {
          tmptr++;
        }
      }
    }
  }

  file_out_sz = MCFG_DATA_OFFSET + 
                sizeof(struct mcfg_file_header) +
                sizeof(struct mcfg_sub_version_data) + 
                input_nvitems_size +
                input_footer_size;

  fprintf(stdout, "Target file will be %i bytes (%i %i %i) \n", file_out_sz,
          MCFG_DATA_OFFSET, input_nvitems_size, input_footer_size);
  int output_offset = 0;
  fprintf(stdout, "Recreating file...\n");
  fprintf(stdout, " - Allocating %i bytes for the output file\n", file_out_sz);
  file_out_buff = calloc(file_out_sz, sizeof(uint8_t));
  memset(file_out_buff, 0x00, file_out_sz);

  fprintf(stdout, " - ELF header...\n");
  output_offset = make_elf_header(output_offset);

  fprintf(stdout, " - Program headers\n");
  output_offset += make_default_program_headers(output_offset);

  fprintf(stdout, " - Building the hash section\n");
  output_offset += make_default_hash_headers(HASH_SECTION_OFFSET);

  fprintf(stdout, " - Modem Config Write begin\n");
  output_offset = MCFG_DATA_OFFSET;
  fprintf(stdout, "   - Header\n");
  output_offset = make_mcfg_header(output_offset);
  fprintf(stdout, "   - NV Items and EFS Data: ");

  // Now we recreate the structures
  struct mcfg_item *item;
  struct mcfg_nvitem *nvitem;
  struct mcfg_nvfile_part *file_section;

  for (int i = 1; i < num_elements; i++) {
    fprintf(stdout, "%i ", mcfg_dump_list[i].id);
    switch (mcfg_dump_list[i].type) {
    case MCFG_ITEM_TYPE_NV:
      item = (struct mcfg_item *)(file_out_buff + output_offset);
      item->id = mcfg_dump_list[i].id;
      item->type = mcfg_dump_list[i].type;
      item->attrib = mcfg_dump_list[i].attrib;
      output_offset += sizeof(struct mcfg_item);
      nvitem = (struct mcfg_nvitem *)(file_out_buff + output_offset);
      nvitem->id =
          mcfg_dump_list[i].id; // TODO: Do we share IDs here? I think we don't
      nvitem->payload_size = mcfg_dump_list[i].size;
      output_offset += sizeof(struct mcfg_nvitem);
      memcpy((file_out_buff + output_offset), mcfg_dump_list[i].blob,
             mcfg_dump_list[i].size);
      nvitem = NULL;
      item = NULL;
      output_offset += mcfg_dump_list[i].size;
      break;
    case MCFG_ITEM_TYPE_NVFILE:
    case MCFG_ITEM_TYPE_FILE:
      item = (struct mcfg_item *)(file_out_buff + output_offset);
      item->id = mcfg_dump_list[i].id;
      item->type = mcfg_dump_list[i].type;
      item->attrib = mcfg_dump_list[i].attrib;
      output_offset += sizeof(struct mcfg_item);

      file_section = (struct mcfg_nvfile_part *)(file_out_buff + output_offset);
      file_section->file_section = 1; // Store the file name
      file_section->section_len = strlen(mcfg_dump_list[i].diskpath);
      memcpy(file_section->payload, mcfg_dump_list[i].diskpath,
             file_section->section_len);
             
      output_offset +=
          sizeof(struct mcfg_nvfile_part) + strlen(mcfg_dump_list[i].diskpath);
      file_section = (struct mcfg_nvfile_part *)(file_out_buff + output_offset);
      file_section->file_section = 2; // File data
      file_section->section_len = mcfg_dump_list[i].size;
      memcpy(file_section->payload, mcfg_dump_list[i].blob,
             mcfg_dump_list[i].size);
      output_offset += sizeof(struct mcfg_nvfile_part) + mcfg_dump_list[i].size;
      break;
    case MCFG_ITEM_TYPE_FOOT:
      fprintf(stdout, "(Footer)\n");
      memcpy((file_out_buff + output_offset), mcfg_dump_list[i].blob,
             mcfg_dump_list[i].size);
      output_offset += mcfg_dump_list[i].size;
      break;
    default:
      fprintf(stderr, "Unhandled file type %i\n", mcfg_dump_list[i].type);
      break;
    }
  }
  fprintf(stdout, "\n");
  
  // Calculate filesizes for the different program headers
  ph0->p_filesz = sizeof(struct Elf32_Ehdr) + (3 * sizeof(struct elf32_phdr));
  ph1->p_filesz = sizeof(struct hash_segment_header);
  ph2->p_filesz = sizeof(uint32_t) + output_offset -
                  MCFG_DATA_OFFSET; // the last byte where we tell the padded
                                    // bytes is the uint32_t
  ph2->p_memsz = sizeof(uint32_t) + output_offset -
                 MCFG_DATA_OFFSET; // the last byte where we tell the padded
                                   // bytes is the uint32_t
  /* Hashes */
  fprintf(stdout, " - Regenerating file hashes... \n");
  recreate_output_file_hash();

  if (debug) {
    fprintf(stdout, "ELF-------------------\n");
    print_elf_data("Input", elf_hdr_in);
    print_elf_data("Output", elfbuf);
    fprintf(stdout, "PH0-------------------\n");
    print_ph_data("Input", 0, ph0_in);
    print_ph_data("Output", 0, ph0);
    fprintf(stdout, "PH1-------------------\n");
    print_ph_data("Input", 1, ph1_in);
    print_ph_data("Output", 1, ph1);
    fprintf(stdout, "PH2-------------------\n");
    print_ph_data("Input", 2, ph2_in);
    print_ph_data("Output", 2, ph2);
    fprintf(stdout, "HASH------------------\n");
    print_hash_data("Input", hash_in);
    print_hash_data("Output", hash);
  }
  return 0;
}

int get_dump_list(char *input_file) {
  file_in = fopen(input_file, "rb");
  num_elements = 0;
  char basefile[MAX_PATH_SIZE];
  FILE *tmpfile;
  if (file_in == NULL) {
    fprintf(stderr, "Error opening input file %s\n", input_file);
    return -EINVAL;
  }

  while (fgets(mcfg_dump_list[num_elements].filename, MAX_PATH_SIZE, file_in)) {
    char *ptr = mcfg_dump_list[num_elements].filename;
    int nums_parsed = 0;
    memset(basefile, 0, MAX_PATH_SIZE);
    mcfg_dump_list[num_elements]
        .filename[strlen(mcfg_dump_list[num_elements].filename) - 1] = '\0';
    printf("File #%i: %s\n", num_elements,
           mcfg_dump_list[num_elements].filename);
    strncpy(basefile, basename(mcfg_dump_list[num_elements].filename),
            MAX_PATH_SIZE);
    printf(" - File name: %s\n", basefile);
    while (*ptr) {
      if (isdigit(*ptr)) {
        if (nums_parsed == 0) {
          mcfg_dump_list[num_elements].id = strtoul(ptr, &ptr, 10);
          printf(" - ID: %i \n", mcfg_dump_list[num_elements].id);
          nums_parsed++;
        } else if (nums_parsed == 1) {
          mcfg_dump_list[num_elements].type = strtoul(ptr, &ptr, 10);
          printf(" - Type: %i \n", mcfg_dump_list[num_elements].type);
          nums_parsed++;
        } else if (nums_parsed == 2) {
          mcfg_dump_list[num_elements].attrib = strtoul(ptr, &ptr, 10);
          printf(" - Attributes: %.2x\n", mcfg_dump_list[num_elements].attrib);
          break;
        }
      } else {
        ptr++;
      }
    }
    ptr++;
    printf("Path to file %s\n", ptr);
    tmpfile = fopen(ptr, "rb");
    if (tmpfile == NULL) {
      fprintf(stderr, "Error opening blob!\n");
      return -EINVAL;
    }
    fseek(tmpfile, 0L, SEEK_END);
    mcfg_dump_list[num_elements].size = ftell(tmpfile);
    fseek(tmpfile, 0L, SEEK_SET);
    fread(mcfg_dump_list[num_elements].blob, MAX_OBJ_SIZE, 1, tmpfile);
    printf(" - File size: %i\n", mcfg_dump_list[num_elements].size);
    fclose(tmpfile);
    num_elements++;
  }
  fclose(file_in);

  return 0;
}
int main(int argc, char *argv[]) {
  char *input_file;
  char *output_file;
  int c;
  INPUT_ELF_OFFSET = 0;
  fprintf(stdout, "Qualcomm MCFG binary file converter \n");
  if (argc < 4) {
    print_help();
    return 0;
  }

  while ((c = getopt(argc, argv, "i:o:hd")) != -1)
    switch (c) {
    case 'i':
      if (optarg == NULL) {
        fprintf(stderr, "You need to give me something to work with\n");
        return 0;
      }
      input_file = optarg;
      break;
    case 'o':
      if (optarg == NULL) {
        fprintf(stderr, "You need to give me some place to output to\n");
        return 0;
      }
      output_file = optarg;
      break;
    case 'd':
      debug = 1;
      break;
    case 'h':
    default:
      print_help();
      return 0;
    }

  if (get_dump_list(input_file) < 0) {
    fprintf(stderr, "Error opening dump list %s!\n", input_file);
    return -EINVAL;
  }

  if (prepare_output_file(output_file) < 0) {
    fprintf(stderr, "FATAL: Cannot create output file %s\n", output_file);
    return -EINVAL;
  }

  if (repack_mcfg_data() < 0) {
    fprintf(stderr,
            "FATAL: Error processing configuration data from the input file\n");
    return -EINVAL;
  }

  fprintf(stdout, "Writing to disk... ");
  fwrite(file_out_buff, 1, file_out_sz, file_out);
  fprintf(stdout, "Done!\n");
  free(file_out_buff);
  fclose(file_out);
  return 0;
}
