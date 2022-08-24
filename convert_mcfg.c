#include "mcfg.h"
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
  fprintf(stdout, "  make_mcfg -i INPUT_FILE -o OUTPUT_FILE\n");
  fprintf(stdout, "Arguments: \n"
                  "\t-i: Input file to read\n"
                  "\t-o: Output file\n"
                  "\t-d: Print hex dumps\n");
}

int make_elf_header(uint32_t offset) {
  elfbuf = (struct Elf32_Ehdr *)file_out_buff+offset;
  memcpy(elfbuf->e_ident, ELFMAG, 4);
  elfbuf->e_type = 2;
  elfbuf->e_machine = 0;
  elfbuf->e_version = 1;
  elfbuf->e_entry = 0;
  elfbuf->e_phoff = 34;
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
  ph0 = (struct elf32_phdr *)file_out_buff+offset;
  ph0->p_filesz = 148;      // REDO THIS
  ph0->p_flags = 0x7000000; // This one stays

  // This header indicates where the SHA256 signatures are stored
  ph1 = (struct elf32_phdr *)(file_out_buff+offset + sizeof(struct elf32_phdr));
  ph1->p_offset = 0x1000; // Offset 1 at 4096 bytes
  ph1->p_vaddr = 0x5000;
  ph1->p_paddr = 0x5000;
  ph1->p_filesz = 0x136; // REDO THIS
  ph1->p_align = 4096;   // 4096

  // This header indicates where does the actual MCFG data start
  ph2 = (struct elf32_phdr *)(file_out_buff+offset + (2 * sizeof(struct elf32_phdr)));
  ph2->p_type = 1;
  ph2->p_offset = 0x2000; // Our entry point is at 8192 bytes
  ph2->p_vaddr = 0;
  ph2->p_paddr = 0;
  ph2->p_filesz = 18936; // REDO THIS
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
  hash = (struct hash_segment_header *)(file_out_buff+offset);

  hash->version = 0x00;
  hash->type = 0x03;
  hash->flash_addr = 0x00;
  hash->dest_addr = 0x5028;
  hash->total_size = 60;
  hash->signature_addr = 0x5088;
  hash->signature_size = 0x00;
  hash->cert_chain_addr = 0x5088;
  hash->cert_chain_size = 0x00;
  // We can't yet calculate the hash here
  return size;
}

int make_mcfg_header(uint32_t offset) {
  int size = offset+sizeof(struct mcfg_file_header) + sizeof(struct mcfg_sub_version_data);
  mcfg_head_out = (struct mcfg_file_header *)(file_out_buff+offset);
  mcfg_sub_out = (struct mcfg_sub_version_data *)(file_out_buff+(offset+sizeof(struct mcfg_file_header)));
  /* HEADER */
  memcpy(mcfg_head_out->magic, MCFG_FILE_HEADER_MAGIC, 4);
  mcfg_head_out->config_type = 1;
  mcfg_head_out->no_of_items = mcfg_head_in->no_of_items;
  mcfg_head_out->carrier_id = mcfg_head_in->carrier_id;
  mcfg_head_out->padding = 0x00;

  /* Whatever this is */
  mcfg_sub_out->magic = SUB_MAGIC_NUM;
  mcfg_sub_out->len = 4;
  mcfg_sub_out->data = mcfg_sub_in->data;

  return size;
}

/* Makes MCFG_TRL
 *
 * Depending on the things we need to include,
 * it might need quite a bunch of params
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
   * We know MCFG must start at least at 0x2000 bytes without signature, or 0x3000
   * with it So for now it's enough to check for the minimum size and do more
   * checks later on 
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
  fprintf(stdout, "ELF PH0 Offset: 0x%.4x %i\n", elf_hdr_in->e_phoff, elf_hdr_in->e_phoff);
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

  fprintf(stdout, " - Checking MCFG header and data... ");
  /* And finally we check if we have the magic string in its expected position
   */
  mcfg_head_in = (struct mcfg_file_header *)(file_in_buff + ph2_in->p_offset);
  if (memcmp(mcfg_head_in->magic, MCFG_FILE_HEADER_MAGIC, 4) != 0) {
    fprintf(stderr, "Error: Invalid  MCFG file MAGIC!\n");
    return -EINVAL;
  }
  mcfg_sub_in = (struct mcfg_sub_version_data*) (file_in_buff + ph2_in->p_offset + sizeof(struct mcfg_file_header));

  fprintf(stdout, "Found it!\n");
  fprintf(stdout, "   - Format version: %i\n", mcfg_head_in->format_version);
  fprintf(stdout, "   - Configuration type: %s\n", mcfg_head_in->config_type < 1 ? "HW Config" : "SW Config");
  fprintf(stdout, "   - Number of items in config: %i\n", mcfg_head_in->no_of_items);
  fprintf(stdout, "   - Carrier ID %i \n", mcfg_head_in->carrier_id);
  fprintf(stdout, "   - Sub-header data:\n");
  fprintf(stdout, "     - Magic: %x\n", mcfg_sub_in->magic);
  fprintf(stdout, "     - Size: %i\n", mcfg_sub_in->len);
  fprintf(stdout, "     - Data: %.8x\n", mcfg_sub_in->data);

  if (mcfg_head_in->config_type != MCFG_FILETYPE_SW) {
    fprintf(stderr,
            "Error: Sorry, this program does not support HW filetypes\n");
    return -EINVAL;
  }

  fprintf(stdout, "File is OK!\n");
  return 0;
}
/* Samples:
....sz..... ....fot.... ....  ..... ....magic....
4f 00 00 00 0a 00 00 00 a1 00 3f 00 4d 43 46 47 5f
........ ..sec0........ ....sec1........... ..sec3.
54 52 4c 00 02 00 00 01 01 04 00 20 08 01 05 03 10
.......sec3-cont..................................
00 52 4f 57 5f 47 65 6e 65 72 69 63 5f 33 47 50 50
..sec4.......  .....sec5........... ...sec6.......
04 02 00 01 00 05 04 00 20 08 01 05 06 02 00 01 00
...sec7............. ....UNKN.........
07 04 00 04 00 00 00 00 00 51 00 00 00

...sz...... ...foot... .....  .... .....magic.....
4e 00 00 00 0a 00 00 00 a1 00 3e 00 4d 43 46 47 5f
.......  ...sec0....... ...sec1............. .....
54 52 4c 00 02 00 00 01 01 04 00 3d 15 01 02 02 04
..sec2.......  ...sec3............................
00 cc 01 01 00 03 13 00 43 6f 6d 6d 65 72 63 69 61
.....sec3-cont............... ....sec4............
6c 2d 43 55 2d 43 53 2d 53 53 04 0a 00 00 02 29 b6
................. ....UNKN.........
0d 00 29 b6 0d 00 00 00 50 00 00 00

This has some other unknown sections:
....sz..... ...footer.. .... .-x10. ....magic....
4d 00 00 00 0a 00 00 00 a1 00 3d 00 4d 43 46 47 5f
........ ..sec0........ ...sec1............. ..sec3
54 52 4c 00 02 00 00 01 01 04 00 14 f3 01 06 03 0a
.....sec3-cont.................. ....sec4.........
00 43 54 41 2d 4c 61 62 2d 43 54 04 06 00 00 01 00
........ ....sec5...........  ..sec6........ ..sec7
00 00 00 05 04 00 14 f3 01 06 06 02 00 00 00 07 04
.............. ..........UNKNWN.......
00 08 00 00 00 00 00 00 00 51 00 00 00

A larger one
...sz...... ..footer... ....  ....  ....magic....
91 00 00 00 0a 00 00 00 a1 00 81 00 4d 43 46 47 5f
.......  ...sec0...... ...sec1.............. .....
54 52 4c 00 02 00 00 01 01 04 00 b1 18 01 06 02 04
sec2.......... ....sec3...........................
00 cc 01 01 00 03 1b 00 4e 6f 56 5f 4f 70 65 6e 4d
...................sec3-cont......................
6b 74 2d 43 6f 6d 6d 65 72 63 69 61 6c 2d 43 4d 43
.. ...sec4........................................
43 04 16 00 00 05 28 b6 0d 00 2e b6 0d 00 2a b6 0d
.......................... ...sec5............. ..
00 2f b6 0d 00 d9 b5 0d 00 05 04 00 b0 18 01 06 06
..sec6............................................
1e 00 00 07 cc 01 00 00 cc 01 02 00 cc 01 07 00 cc
............................................ .....
01 08 00 c6 01 0c 00 c6 01 0d 00 cc 01 04 00 07 04
...sec7....... ....UNKN.........
00 00 00 00 00 00 00 93 00 00 00

UNKNWN == Padding bytes + sz?
So we can pick the last one as a uint32, and the sz from the header and find out
the amount of padding? or as a checksum of sorts?

*/

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
  }

  return "Unknown section";
}

char *get_nvitem_name(uint32_t id) {
  for (int i = 0; i < (sizeof(nvitem_names) / sizeof(nvitem_names[0])); i++) {
    if (id == nvitem_names[i].id) {
      return (char*)nvitem_names[i].name;
    }
  }

  return "Unknwon";
}
int analyze_footer(uint8_t *footer, uint16_t sz) {
  int sections_parsed = 0;
  int done = 0;
  uint32_t padded_bytes = 0;
  memset(footer_items, 0, sizeof(struct mcfg_footer_section)* MAX_FOOTER_SECTIONS);
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
  fprintf(stdout, "Size:\n - %i bytes\n - Reported: %i bytes\n - Trimmed: %ibytes\n", sz, footer_in->len,
          footer_in->size_trimmed);
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
  /* Now find each section */
  fprintf(stdout, "Footer sections:\n");
  int prev_offset = curr_obj_offset;
  do {
    if (sections_parsed > 15) {
      fprintf(stderr, "Error: Exceeded maximum number of sections for the footer\n");
      return -ENOSPC;
    }

    struct mcfg_footer_proto *proto =
        (struct mcfg_footer_proto *)(footer + curr_obj_offset);

    fprintf(stdout, " - %s (#%i): %i bytes\n", get_section_name(proto->id), proto->id,
            proto->len);

    switch (proto->id) {
    case MCFG_FOOTER_SECTION_VERSION_1: // Fixed size, 2 bytes, CONSTANT
      sec0 = (struct mcfg_footer_section_version1 *)(footer + curr_obj_offset);
      fprintf(stdout, "   - Version: %i\n", sec0->data);
      break;
    case MCFG_FOOTER_SECTION_VERSION_2: // Fixed size, 4 bytes
      sec1 = (struct mcfg_footer_section_version2 *)(footer + curr_obj_offset);
      fprintf(stdout, "   - Version: %i\n", sec1->data);
      break;
    case MCFG_FOOTER_SECTION_APPLICABLE_MCC_MNC: // MCC+MNC
      sec2 = (struct mcfg_footer_section_2 *)(footer + curr_obj_offset);
      fprintf(stdout, "   - MCC-MNC %i-%i\n", sec2->mcc, sec2->mnc);
      break;
    case MCFG_FOOTER_SECTION_PROFILE_NAME: // Carrier name
      sec3 =
          (struct mcfg_footer_section_carrier_name *)(footer + curr_obj_offset);
      fprintf(stdout, "   - Profile name: %s\n", (char *)sec3->carrier_config_name);
      break;
    case MCFG_FOOTER_SECTION_ALLOWED_ICCIDS: // ICCIDs
      sec4 = (struct mcfg_footer_section_allowed_iccids *)(footer +
                                                           curr_obj_offset);
      for (int tmp = 0; tmp < sec4->num_iccids; tmp++) {
        fprintf(stdout, "   - Allowed ICC ID #%i: %i...\n", tmp,
                sec4->iccids[tmp]);
      }
      break;

    default:
      fprintf(stdout,
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
    footer_items[sections_parsed].size = curr_obj_offset-prev_offset;
    memcpy(footer_items[sections_parsed].blob, (footer+prev_offset), curr_obj_offset-prev_offset);
    fprintf(stdout, "Object %i -> %i\n", proto->id, footer_items[sections_parsed].id);
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
  for (int i = 0; i < num_items; i++) {
    struct mcfg_item *item =
        (struct mcfg_item *)(file_in_buff + current_offset);
    struct mcfg_nvitem *nvitem;
    struct mcfg_nvfile_part *file_section;
    if (!debug) {
      fprintf(stdout, " - %i: #%i (%s)\n", i, item->id, get_nvitem_name(item->id));
    }
    nv_items[i].offset = current_offset;
    nv_items[i].type = item->type;
    nv_items[i].id = item->id;
    current_offset += sizeof(struct mcfg_item);
    switch (item->type) {
    case MCFG_ITEM_TYPE_NV:
    case MCFG_ITEM_TYPE_UNKNOWN:
      if (debug)
        fprintf(stdout, "Item %i at offset %i: NV data\n", i, current_offset);
      nvitem = (struct mcfg_nvitem *)(file_in_buff + current_offset);
      current_offset += sizeof(struct mcfg_nvitem) + nvitem->payload_size;
      nv_items[i].size = current_offset - nv_items[i].offset;
      memcpy(nv_items[i].blob, (file_in_buff + nv_items[i].offset),
             nv_items[i].size);
      nvitem = NULL;
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
      analyze_footer(
          (file_in_buff + current_offset - sizeof(struct mcfg_item)),
          (file_in_sz - (current_offset - sizeof(struct mcfg_item))));
        
        if (i < (num_items-1))
          fprintf(stderr, "WARNING: There's more stuff beyond the footer. Something is wrong... %i/%i\n", i, num_items);

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
              "Don't know how to handle NV data type %i (0x%.2x), bailing out, "
              "sorry\n",
              item->type, item->type);
      for (int dbf = -8; dbf < 8; dbf++) {
        if (dbf == 0) {
          fprintf(stderr, " ... ");
        }
        tmpoffset = (file_in_buff + nv_items[i].offset + dbf);
        fprintf(stderr, "%.2x ", *tmpoffset);
      }
      fprintf(stderr, "\n");
      fprintf(stderr, "String::: \n%s\nEOF\n", (file_in_buff+nv_items[i].offset));
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
  file_out_sz = file_in_sz *2 ; // dont do this
  int output_offset = 0;
  fprintf(stdout, "Recreating file...\n");
  fprintf(stdout, " - Allocating %i bytes for the output file\n", file_out_sz);
  file_out_buff = calloc(file_out_sz, sizeof(uint8_t));
  memset(file_out_buff, 0x00, file_out_sz);

  fprintf(stdout, " - ELF header...\n");
  output_offset = make_elf_header(output_offset);

  fprintf(stdout, " - Program headers\n");
  output_offset+= make_default_program_headers(output_offset);

  fprintf(stdout, " - Building the hash section\n");
  output_offset+= make_default_hash_headers(HASH_SECTION_OFFSET);

  fprintf(stdout, " - Modem Config Write begin\n");
  output_offset = MCFG_DATA_OFFSET;
  fprintf(stdout, "   - Header\n");
  output_offset = make_mcfg_header(output_offset);
  fprintf(stdout, "Current offset: %.4x\n", output_offset);
  fprintf(stdout, "   - NV Items and EFS Data: ");
  for (int i = 0; i < mcfg_head_out->no_of_items; i++) {
    fprintf (stdout, "%i ", nv_items[i].id);
    memcpy((file_out_buff+output_offset), nv_items[i].blob, nv_items[i].size);
    output_offset+=nv_items[i].size;
  }
  fprintf(stdout, "\n");
  fprintf(stdout, "   - Footer\n");
  fprintf(stdout, "     - Header\n");
  
  fprintf(stdout, "Current offset: %.4x\n", output_offset);
  footer_out = (struct mcfg_footer *)(file_out_buff+output_offset);
  footer_out->len = 0xff;
  footer_out->footer_magic1 = 0x0a;
  footer_out->footer_magic2 = 0xa1;
  memcpy(footer_out->magic, MCFG_FILE_FOOTER_MAGIC, 8);
  output_offset+= sizeof(struct mcfg_footer);
  fprintf(stdout, "     - Sections: ");
   for (int i = 0; i < MAX_FOOTER_SECTIONS; i++) {
    if (footer_items[i].size > 0) {
      fprintf(stdout, "#%i %ib ", footer_items[i].id, footer_items[i].size);
      memcpy((file_out_buff+output_offset), footer_items[i].blob, footer_items[i].size);
      output_offset+=footer_items[i].size;
    }
  }
  fprintf(stdout, "\n");
  /* Add padding, recalculate hashes */
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

  fprintf(stdout, "Writing to disk\n");
  fwrite(file_out_buff, 1, file_out_sz, file_out);
  free(file_in_buff);
  fclose(file_out);
  return 0;
}
