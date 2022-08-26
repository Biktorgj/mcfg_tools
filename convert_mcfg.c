#include "mcfg.h"
#include "nvitems.h"
#include "sha256.h"
#include <asm-generic/errno-base.h>
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// Settings
uint8_t debug;

// Input file
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
  fprintf(stdout, "  convert_mcfg -i INPUT_FILE -o OUTPUT_FILE\n");
  fprintf(stdout, "Arguments: \n"
                  "\t-i: Input file to read\n"
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
  mcfg_head_out->no_of_items = mcfg_head_in->no_of_items;
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

/* Makes MCFG_TRL
 *
 * Depending on the things we need to include,
 * it might need quite a bunch of params
 * Not used for now. There's some sections
 * I can't identify
 */
int make_mcfg_footer_proto(uint8_t *buffer, uint8_t do_footer_section_magic1,
                           uint8_t do_footer_section_magic2,
                           uint8_t do_use_specific_mcc_mnc,
                           uint8_t do_use_specific_carrier_name,
                           uint8_t do_whitelist_specific_iccids,
                           uint16_t specific_mcc, uint16_t specific_mnc,
                           uint16_t carrier_string_len, uint8_t *carrier_name,
                           uint32_t specific_iccids[MAX_NUM_ICCIDS],
                           uint8_t used_iccids) {
  int allocsize = 0;
  if (do_footer_section_magic1)
    allocsize += sizeof(struct mcfg_footer_section_version1);

  if (do_footer_section_magic2)
    allocsize += sizeof(struct mcfg_footer_section_version2);

  if (do_use_specific_mcc_mnc)
    allocsize += sizeof(struct mcfg_footer_section_2);

  if (do_use_specific_carrier_name)
    allocsize += sizeof(struct mcfg_footer_section_carrier_name);

  if (do_whitelist_specific_iccids)
    allocsize += sizeof(struct mcfg_footer_section_allowed_iccids) +
                 (used_iccids * sizeof(uint32_t));

  buffer = malloc(allocsize);

  return allocsize;
}

int get_input_file(char *input_file) {
  file_in = fopen(input_file, "rb");
  if (file_in == NULL) {
    fprintf(stderr, "Error opening input file %s\n", input_file);
    return -EINVAL;
  }
  fseek(file_in, 0L, SEEK_END);
  file_in_sz = ftell(file_in);
  file_in_buff = malloc(file_in_sz);
  fseek(file_in, 0L, SEEK_SET);
  fread(file_in_buff, file_in_sz, 1, file_in);

  fclose(file_in);
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

char *get_section_name(uint8_t section_id) {
  switch (section_id) {
  case MCFG_FOOTER_SECTION_VERSION_1:
    return "Version field";
  case MCFG_FOOTER_SECTION_VERSION_2:
    return "Second version field";
  case MCFG_FOOTER_SECTION_APPLICABLE_MCC_MNC:
    return "Carrier Network code";
  case MCFG_FOOTER_SECTION_PROFILE_NAME:
    return "Carrier Profile name";
  case MCFG_FOOTER_SECTION_ALLOWED_ICCIDS:
    return "Allowed SIM ICC IDs for this profile";
  case MCFG_FOOTER_SECTION_CARRIER_VERSION_ID:
    return "Carrier version ID";
  }

  return "Unknown section";
}

char *get_nvitem_name(uint32_t id) {
  for (int i = 0; i < (sizeof(nvitem_names) / sizeof(nvitem_names[0])); i++) {
    if (id == nvitem_names[i].id) {
      return (char *)nvitem_names[i].name;
    }
  }

  return "Unknwon";
}

int analyze_footer(uint8_t *footer, uint16_t sz) {
  int sections_parsed = 0;
  int done = 0;
  uint32_t padded_bytes = 0;
  memset(footer_items, 0,
         sizeof(struct mcfg_footer_section) * MAX_FOOTER_SECTIONS);
  if (!debug)
    fprintf(stdout, "\nAnalyzing footer with size of %i bytes\n", sz);
  if (sz <
      (sizeof(struct mcfg_item) + sizeof(struct mcfg_footer_section_version1) +
       sizeof(struct mcfg_footer_section_version2))) {
    fprintf(stderr, "Error: Footer is too short?\n");
    return -EINVAL;
  }
  /* Dump the footer */
  if (debug) {
    fprintf(stdout, "Footer: hex dump\n");
    int cnt = 0;
    for (int i = 0; i < sz; i++) {
      fprintf(stdout, "%.2x ", footer[i]);
      cnt++;
      if (cnt > 16) {
        fprintf(stdout, "\n");
        cnt = 0;
      }
    }
    fprintf(stdout, "\n");
  }

  struct mcfg_footer *footer_in = (struct mcfg_footer *)footer;
  if (memcmp(footer_in->magic, MCFG_FILE_FOOTER_MAGIC, 8) != 0) {
    fprintf(stderr, "Error: Footer Magic string not found\n");
    return -EINVAL;
  }
  if (footer_in->footer_magic1 != MCFG_ITEM_TYPE_FOOT ||
      footer_in->footer_magic2 != 0xa1) {
    fprintf(stderr, "Error: One of the magic numbers doesn't match\n");
    return -EINVAL;
  }
  fprintf(stdout,
          "Size:\n - %i bytes\n - Reported: %i bytes\n - Trimmed: %ibytes\n",
          sz, footer_in->len, footer_in->size_trimmed);
  uint32_t *end_marker = (uint32_t *)(footer + sz - 4);
  padded_bytes = *end_marker - footer_in->len;
  fprintf(stdout, " - Padding at the end: %i bytes \n", padded_bytes);

  uint32_t curr_obj_offset = sizeof(struct mcfg_footer);
  uint32_t max_obj_size = footer_in->len - padded_bytes - sizeof(uint32_t);
  // Pointers to reuse later
  struct mcfg_footer_section_version1 *sec0;
  struct mcfg_footer_section_version2 *sec1;
  struct mcfg_footer_section_2 *sec2;
  struct mcfg_footer_section_carrier_name *sec3;
  struct mcfg_footer_section_allowed_iccids *sec4;
  struct mcfg_footer_section_carrier_id *sec5;
  /* Now find each section */
  fprintf(stdout, "Footer sections:\n");
  int prev_offset = curr_obj_offset;
  do {
    if (sections_parsed > 15) {
      fprintf(stderr,
              "Error: Exceeded maximum number of sections for the footer\n");
      return -ENOSPC;
    }

    struct mcfg_footer_proto *proto =
        (struct mcfg_footer_proto *)(footer + curr_obj_offset);

    fprintf(stdout, " - %s (#%i): %i bytes\n", get_section_name(proto->id),
            proto->id, proto->len);

    switch (proto->id) {
    case MCFG_FOOTER_SECTION_VERSION_1: // Fixed size, 2 bytes, CONSTANT
      sec0 = (struct mcfg_footer_section_version1 *)(footer + curr_obj_offset);
      fprintf(stdout, "   - Version: %i\n", sec0->data);
      break;
    case MCFG_FOOTER_SECTION_VERSION_2: // Fixed size, 4 bytes
      sec1 = (struct mcfg_footer_section_version2 *)(footer + curr_obj_offset);
      fprintf(stdout, "   - Initial version: 0x%.8x", sec1->data);
      while(sec1->data > 0x06000000) {
        sec1->data-=0x01000000;
      }
      fprintf(stdout, " --> new: 0x%.8x\n", sec1->data);
      break;
    case MCFG_FOOTER_SECTION_APPLICABLE_MCC_MNC: // MCC+MNC
      sec2 = (struct mcfg_footer_section_2 *)(footer + curr_obj_offset);
      fprintf(stdout, "   - MCC-MNC %i-%i\n", sec2->mcc, sec2->mnc);
      break;
    case MCFG_FOOTER_SECTION_PROFILE_NAME: // Carrier name
      sec3 =
          (struct mcfg_footer_section_carrier_name *)(footer + curr_obj_offset);
      fprintf(stdout, "   - Profile name: %s\n",
              (char *)sec3->carrier_config_name);
      break;

    case MCFG_FOOTER_SECTION_ALLOWED_ICCIDS: // ICCIDs
      sec4 = (struct mcfg_footer_section_allowed_iccids *)(footer +
                                                           curr_obj_offset);
      for (int tmp = 0; tmp < sec4->num_iccids; tmp++) {
        fprintf(stdout, "   - Allowed ICC ID #%i: %i...\n", tmp,
                sec4->iccids[tmp]);
      }
      break;
    case MCFG_FOOTER_SECTION_CARRIER_VERSION_ID:
      sec5 = (struct mcfg_footer_section_carrier_id *)(footer +
                                                           curr_obj_offset);
      fprintf(stdout, "   - Carrier version ID: %.4x\n", sec5->carrier_version);
      break;
    default:
      fprintf(
          stdout,
          "   - WARNING: %s: Unknown section %i of size %i in the footer at "
          "offset %i\n",
          (char *)sec3->carrier_config_name, proto->id, proto->len,
          curr_obj_offset);
      if (debug) {
        fprintf(stdout, "Section dump:\n");
        for (int p = 0; p < proto->len; p++) {
          fprintf(stdout, "%.2x ", proto->data[p]);
        }
        fprintf(stdout, "\nEnd dump\n");
      }
      break;
    }

    curr_obj_offset += sizeof(struct mcfg_footer_proto) + proto->len;
    if (proto->len == 0) {
      curr_obj_offset++;
    }
    if (curr_obj_offset >= max_obj_size) {
      done = 1;
    }

    footer_items[sections_parsed].id = proto->id;
    footer_items[sections_parsed].size = curr_obj_offset - prev_offset;
    memcpy(footer_items[sections_parsed].blob, (footer + prev_offset),
           curr_obj_offset - prev_offset);

    prev_offset = curr_obj_offset;
    proto = NULL;
    sections_parsed++;
  } while (!done);

  return 0;
}

int process_nv_configuration_data() {
  fprintf(stdout, "%s: start\n", __func__);
  int num_items = mcfg_head_in->no_of_items;
  struct item_blob nv_items[num_items];

  uint16_t current_offset = ph2_in->p_offset + sizeof(struct mcfg_file_header) +
                            sizeof(struct mcfg_sub_version_data);
  if (!debug) {
    fprintf(stdout, "Processing items...\n");
  }
  uint8_t *tmpoffset;
  input_nvitems_size = 0;
  for (int i = 0; i < num_items; i++) {
    struct mcfg_item *item =
        (struct mcfg_item *)(file_in_buff + current_offset);
    struct mcfg_nvitem *nvitem;
    struct mcfg_nvfile_part *file_section;
    if (!debug) {
      fprintf(stdout, " - %i: #%i (%s)\n", i, item->id,
              get_nvitem_name(item->id));
    }
    nv_items[i].offset = current_offset;
    nv_items[i].type = item->type;
    nv_items[i].id = item->id;
    current_offset += sizeof(struct mcfg_item);
    switch (item->type) {
    case MCFG_ITEM_TYPE_NV:
    case MCFG_ITEM_TYPE_UNKNOWN:
      nvitem = (struct mcfg_nvitem *)(file_in_buff + current_offset);
      if (debug)
        fprintf(stdout, "Item %i (ID %i) at offset %i: NV data\n", i, nvitem->id, current_offset);
      current_offset += sizeof(struct mcfg_nvitem) + nvitem->payload_size;
      nv_items[i].size = current_offset - nv_items[i].offset;
      memcpy(nv_items[i].blob, (file_in_buff + nv_items[i].offset),
             nv_items[i].size);
      nvitem = NULL;
      input_nvitems_size += nv_items[i].size;
      if (debug) {
        int cnt = 0;
        for (int k = 0; k < nv_items[i].size; k++) {
          fprintf(stdout, "%.2x ", nv_items[i].blob[k]);
          cnt++;
          if (cnt > 32) {
            fprintf(stdout, "\n");
            cnt = 0;
          }
        }
        fprintf(stdout, "\n");
      }
      break;
    case MCFG_ITEM_TYPE_NVFILE:
    case MCFG_ITEM_TYPE_FILE:
      if (debug)
        fprintf(stdout, "#%i (@%ib): EFS file: ", i, current_offset);
      for (int k = 0; k < 2; k++) {
        file_section =
            (struct mcfg_nvfile_part *)(file_in_buff + current_offset);
        switch (file_section->file_section) {
        case EFS_FILENAME:
          if (debug)
            fprintf(stdout, " Name: %s\n", (char *)file_section->payload);
          current_offset +=
              sizeof(struct mcfg_nvfile_part) + file_section->section_len;
          break;
        case EFS_FILECONTENTS:
          if (debug)
            fprintf(stdout, "--DATA--\n%s\n--EOF--\n",
                    (char *)file_section->payload);
          file_section =
              (struct mcfg_nvfile_part *)(file_in_buff + current_offset);
          current_offset +=
              sizeof(struct mcfg_nvfile_part) + file_section->section_len;
          break;
        }
        file_section = NULL;
      }
      nv_items[i].size = current_offset - nv_items[i].offset;
      input_nvitems_size += nv_items[i].size;
      memcpy(nv_items[i].blob, (file_in_buff + nv_items[i].offset),
             nv_items[i].size);

      if (debug) {
        int cnt = 0;
        for (int k = 0; k < nv_items[i].size; k++) {
          fprintf(stdout, "%.2x ", nv_items[i].blob[k]);
          cnt++;
          if (cnt > 32) {
            fprintf(stdout, "\n");
            cnt = 0;
          }
        }
        fprintf(stdout, "\nAs str: %s\n", nv_items[i].blob);
      }
      break;
    case MCFG_ITEM_TYPE_FOOT:
      if (debug)
        fprintf(stdout, "Footer at %i bytes, size of %i bytes\n",
                current_offset, file_in_sz - current_offset);
      // REWIND!
      input_footer_size =
          (file_in_sz - (current_offset - sizeof(struct mcfg_item)));
      analyze_footer((file_in_buff + current_offset - sizeof(struct mcfg_item)),
                     input_footer_size);

      if (i < (num_items - 1))
        fprintf(stderr,
                "WARNING: There's more stuff beyond the footer. Something is "
                "wrong... %i/%i\n",
                i, num_items);

      break;
    default:
      /* We need to break here. There are some types of items who don't follow
       * the same pattern. They sometimes include complete files, secret keys,
       * conditional rules for roaming etc.
       * Instead of holding them in EFS files (or either I'm missing a typedef
       * for some other filetype), they appear as a different item type for some
       * reason
       * Will try to figure it out in the future, but for now, I'll just
       * break here since I don't know how to find the correct offsets for
       * these item types
       */
      fprintf(stderr,
              "Don't know how to handle NV data type %i (0x%.2x) at 0x%.8x, bailing out, "
              "sorry\n",
              item->type, item->type, current_offset);
      for (uint32_t dbf = current_offset-128; dbf < file_in_sz; dbf++) {
        if (dbf == current_offset) {
          fprintf(stderr, "\n ... \n");
        }
        tmpoffset = (file_in_buff + dbf);
        fprintf(stderr, "%.2x ", *tmpoffset);
      }
      fprintf(stderr, "\n");
      fprintf(stderr, "String::: \n%s\nEOF\n",
              (file_in_buff + nv_items[i].offset));
      /*      fprintf(stdout, "Item %i at offset %i: \n", i, current_offset);
          nvitem = (struct mcfg_nvitem *)(file_in_buff + current_offset);
          fprintf(stdout, "Payload size: %i byte\n", nvitem->payload_size);
          current_offset += sizeof(struct mcfg_nvitem) + nvitem->payload_size;
          nv_items[i].size = current_offset - nv_items[i].offset;
          memcpy(nv_items[i].blob, (file_in_buff + nv_items[i].offset),
                 nv_items[i].size);
          nvitem = NULL;
            int cnt = 0;
            for (int k = 0; k < nv_items[i].size; k++) {
              fprintf(stdout, "%.2x ", nv_items[i].blob[k]);
              cnt++;
              if (cnt > 32) {
                fprintf(stdout, "\n");
                cnt = 0;
              }
          }
            fprintf(stdout, "\nAs str: %s\n", nv_items[i].blob);*/
      return -EINVAL;
      break;
    }

    item = NULL;
  }
  if (!debug) {
    fprintf(stdout, "\n");
  }

  /* NOW WE WRITE */
  file_out_sz =
      (MCFG_DATA_OFFSET + input_nvitems_size + input_footer_size + sizeof(struct mcfg_file_header) + sizeof(struct mcfg_sub_version_data));
  fprintf(stdout, "Target file will be %i bytes (%i %i %i) (%i)\n", file_out_sz,
          MCFG_DATA_OFFSET, input_nvitems_size, input_footer_size, file_in_sz);
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
  for (int i = 0; i < mcfg_head_out->no_of_items; i++) {
    fprintf(stdout, "%i ", nv_items[i].id);
    memcpy((file_out_buff + output_offset), nv_items[i].blob, nv_items[i].size);
    output_offset += nv_items[i].size;
  }
  fprintf(stdout, "\n");
  fprintf(stdout, "   - Footer\n");
  uint32_t initial_footer_offset = output_offset;

  fprintf(stdout, "     - Header\n");

  footer_out = (struct mcfg_footer *)(file_out_buff + output_offset);
  footer_out->footer_magic1 = 0x0a;
  footer_out->footer_magic2 = 0xa1;
  memcpy(footer_out->magic, MCFG_FILE_FOOTER_MAGIC, 8);
  output_offset += sizeof(struct mcfg_footer);
  fprintf(stdout, "     - Sections: ");
  for (int i = 0; i < MAX_FOOTER_SECTIONS; i++) {
    if (footer_items[i].size > 0) {
      fprintf(stdout, "#%i %ib ", footer_items[i].id, footer_items[i].size);
      memcpy((file_out_buff + output_offset), footer_items[i].blob,
             footer_items[i].size);
      output_offset += footer_items[i].size;
    }
  }
  fprintf(stdout, "\n");

  /* Footer padding */
  uint32_t footer_full_sz = output_offset - initial_footer_offset;
  footer_out->len = footer_full_sz + sizeof(uint32_t);
  footer_out->size_trimmed = footer_out->len - 0x10;
  uint8_t padding_bytes_required = 4 - (output_offset % 4);
  fprintf(stdout, "     - Padding needed: %i byte\n", padding_bytes_required);
  for (uint32_t i = 0; i < padding_bytes_required; i++) {
    file_out_buff[output_offset] = 0x00;
    output_offset++;
  }
  file_out_buff[output_offset] = padding_bytes_required + footer_out->len;
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
  fprintf(stdout, "Input file: %s\n", input_file);
  if (get_input_file(input_file) < 0) {
    fprintf(stderr, "Error opening input file %s!\n", input_file);
    return -EINVAL;
  }

  if (prepare_output_file(output_file) < 0) {
    fprintf(stderr, "FATAL: Cannot create output file %s\n", output_file);
    return -EINVAL;
  }

  if (check_input_file() < 0) {
    fprintf(stderr,
            "FATAL: Input file %s is not compatible with this tool :(\n",
            input_file);
    return -EINVAL;
  }

  if (process_nv_configuration_data() < 0) {
    fprintf(stderr,
            "FATAL: Error processing configuration data from the input file\n");
    return -EINVAL;
  }

  fprintf(stdout, "Writing to disk... ");
  fwrite(file_out_buff, 1, file_out_sz, file_out);
  fprintf(stdout, "Done!\n");
  fclose(file_out);
  free(file_out_buff);
  free(file_in_buff);
  return 0;
}
