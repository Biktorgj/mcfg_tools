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
#include <sys/stat.h>
#include <sys/types.h>
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
char output_dir_nv[255];
char output_dir_efs[255];
char output_dir_footer[255];

void print_help() {
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, "  extract_mcfg -i INPUT_FILE -o OUTPUT_FILE\n");
  fprintf(stdout, "Arguments: \n"
                  "\t-i: Input file to read\n"
                  "\t-o: Output file\n"
                  "\t-d: Print hex dumps\n");
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

int prepare_output_dirs(char *output_dir) {
  struct stat st = {0};
  memset(output_dir_nv, 0, 255);
  memset(output_dir_efs, 0, 255);
  memset(output_dir_footer, 0, 255);

  fprintf(stdout, "Base dir at %s\n", output_dir);
  if (stat(output_dir, &st) == -1) {
    if (mkdir(output_dir, 0700) < 0) {
      fprintf(stderr, "Error creating output dir!\n");
      return -EINVAL;
    }
  } else {
    fprintf(stderr, "ERROR: Output directory already exists!\n");
    return -EINVAL;
  }
  snprintf(output_dir_nv, 255, "%s/nvitems", output_dir);
  fprintf(stdout, " - NV Items at %s\n", output_dir_nv);
  if (mkdir(output_dir_nv, 0700) < 0) {
    fprintf(stderr, "Error creating output nvitems dir!\n");
    return -EINVAL;
  }
  snprintf(output_dir_efs, 255, "%s/efsitems", output_dir);
  fprintf(stdout, " - EFS Items at %s\n", output_dir_efs);
  if (mkdir(output_dir_efs, 0700) < 0) {
    fprintf(stderr, "Error creating output efsitems dir!\n");
    return -EINVAL;
  }

  snprintf(output_dir_footer, 255, "%s/footer", output_dir);
  fprintf(stdout, " - Footer at %s\n", output_dir_footer);
  if (mkdir(output_dir_footer, 0700) < 0) {
    fprintf(stderr, "Error creating output footer dir!\n");
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
char *get_nvitem_as_filename(uint32_t id, uint8_t position) {
  char *filename = malloc(512);
  memset(filename, 0, 512);
  for (int i = 0; i < (sizeof(nvitem_names) / sizeof(nvitem_names[0])); i++) {
    if (id == nvitem_names[i].id) {
      snprintf(filename, 512, "%s/%i__%u_%s.bin", output_dir_nv, position, id,
               nvitem_names[i].name);
    }
  }
  for (int i = 0; i < strlen(filename); i++) {
    if ((filename[i] < 'A' && filename[i] > 'Z') &&
        (filename[i] < 'a' && filename[i] > 'z') &&
        (filename[i] < '0' && filename[i] > '9')) {
      filename[i] = '-';
    }
  }
  return filename;
}

char *get_efsitem_as_filename(char *name, uint8_t position) {
  char *filename = malloc(512);
  char *tmpdir = malloc(512);
  memset(filename, 0, 512);
  int last_folder_mark = 0;
  struct stat st = {0};

  for (int i = 0; i < strlen(name); i++) {
    if (name[i] == '/') {
      last_folder_mark = i;
    }
    if (last_folder_mark > 0) {
      snprintf(tmpdir, strlen(output_dir_efs) + last_folder_mark + 1, "%s%s",
               output_dir_efs, name);
      if (stat(tmpdir, &st) == -1) {
        if (mkdir(tmpdir, 0700) < 0) {
          fprintf(stderr, "Error creating output dir %s!\n", tmpdir);
        }
      }
    }
  }

  snprintf(filename, 512, "%s%s.bin", output_dir_efs, name);

  free(tmpdir);
  return filename;
}

int save_file(char *filename, uint8_t *data, uint32_t sz) {
  FILE *fp;
  fp = fopen(filename, "wb");
  if (fp == NULL) {
    return -EINVAL;
  }
  fwrite(data, 1, sz, fp);
  fclose(fp);
  free(filename);
  return -0;
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
      sec5 =
          (struct mcfg_footer_section_carrier_id *)(footer + curr_obj_offset);
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
    char efsfilenametmp[256];
    switch (item->type) {
    case MCFG_ITEM_TYPE_NV:
    case MCFG_ITEM_TYPE_UNKNOWN:
      nvitem = (struct mcfg_nvitem *)(file_in_buff + current_offset);
      if (debug)
        fprintf(stdout, "Item %i (ID %i) at offset %i: NV data\n", i,
                nvitem->id, current_offset);

      current_offset += sizeof(struct mcfg_nvitem) + nvitem->payload_size;
      nv_items[i].size = current_offset - nv_items[i].offset;
      memcpy(nv_items[i].blob, (file_in_buff + nv_items[i].offset),
             nv_items[i].size);
      if (save_file(get_nvitem_as_filename(nvitem->id, i), nv_items[i].blob,
                    nv_items[i].size) < 0) {
        fprintf(stderr, "Error saving NV item %i\n", i);
      }
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
      memset(efsfilenametmp, 0, 256);
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
          memcpy(efsfilenametmp, (char *)file_section->payload,
                 file_section->section_len);
          break;
        case EFS_FILECONTENTS:
          file_section =
              (struct mcfg_nvfile_part *)(file_in_buff + current_offset);
          current_offset +=
              sizeof(struct mcfg_nvfile_part) + file_section->section_len;
          if (efsfilenametmp[0] != 0x00) {
            if (save_file(get_efsitem_as_filename(efsfilenametmp, i),
                          (uint8_t *)file_section->payload,
                          file_section->section_len) < 0) {
              fprintf(stderr, "Error saving EFS item %i\n", i);
            }
          } else {
            fprintf(stderr, "EFS File dump: Filename is empty!\n");
          }
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
              "Don't know how to handle NV data type %i (0x%.2x) at 0x%.8x, "
              "bailing out, "
              "sorry\n",
              item->type, item->type, current_offset);
      for (uint32_t dbf = current_offset - 128; dbf < file_in_sz; dbf++) {
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

  return 0;
}

int main(int argc, char *argv[]) {
  char *input_file;
  char *output_dir;
  int c;
  INPUT_ELF_OFFSET = 0;
  fprintf(stdout, "Qualcomm MCFG binary file extractor \n");
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
      output_dir = optarg;
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

  if (prepare_output_dirs(output_dir) < 0) {
    fprintf(stderr, "FATAL: Cannot create output directory %s\n", output_dir);
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

  free(file_in_buff);
  return 0;
}
