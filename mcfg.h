#include <argp.h>
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __MCFG_H__
#define __MCFG_H__

#define MCFG_FILE_HEADER_MAGIC "MCFG"
#define MCFG_FILE_FOOTER_MAGIC "MCFG_TRL"

#define VERSION_NUM 4995
#define MAX_NUM_ICCIDS 32
#define MAX_OBJ_SIZE 16384
#define SHA256_HASH_SIZE 32

/* ELF Headers */
#define EI_NIDENT 16
#define ELFMAG "\177ELF"

/* Hardcoded stuff for outpur files */
#define PH_OFFSET 0x0034
#define HASH_SECTION_OFFSET 0x1000
#define MCFG_DATA_OFFSET 0x2000

struct item_blob {
  uint32_t id;
  uint8_t type;
  uint16_t offset;
  uint16_t size;
  uint8_t blob[MAX_OBJ_SIZE];
};

struct Elf32_Ehdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint32_t e_entry;
  uint32_t e_phoff;
  uint32_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct elf32_phdr {
  uint32_t p_type;
  uint32_t p_offset;
  uint32_t p_vaddr;
  uint32_t p_paddr;
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint32_t p_flags;
  uint32_t p_align;
};

struct hash_segment_header {
  uint32_t version;         // 0x00
  uint32_t type;            // 0x03
  uint32_t flash_addr;      // 0x00
  uint32_t dest_addr;       // 0x28 0x10 0x00 0x00
  uint32_t total_size;      // 60 00 00 00
  uint32_t hash_size;       // 60 00 00 00
  uint32_t signature_addr;  // 88 10 00 00
  uint32_t signature_size;  // 00 00 00 00
  uint32_t cert_chain_addr; // 88 10 00 00
  uint32_t cert_chain_size; // 00 00 00 00
  uint8_t hash1[32];
  uint8_t padding[32];
  uint8_t hash2[32];
  /*
  uint8_t hash1[32]; //b5 10 06 96 85 4e b8 1e f2 12 bb d4 92 99 de fe 1f 5b 53
  26 8e 04 98 d8 a0 e0 45 e8 d9 48 a4 45
  uint8_t padding[32]; // 0x00
  uint8_t hash2[32]; //45 81 10 ce 40 ba ea fa e0 a8 06 12 8e cc 37 91 d6 9c c8
  fd eb 24 4d 76 04 8d eb da 76 20 b3 ca uint8_t padding[32]; // 0x00 all the
  rest of the file (hash1 + padding + hash2 == 0x60 (96byte)

  */
};

struct mcfg_file_header {
  unsigned char magic[4];  // MCFG
  uint16_t format_version; // 0x02 0x00
  uint16_t config_type;    // MCFG_HW is 0, MCFG_SW is 1
  uint32_t no_of_items;    // Number of items in the file
  uint16_t carrier_id;      // Each carrier seems to have a unique ID? either uin16_t + 2xbyte padding or a uint32_t and havent found a really big num
  uint16_t padding;      // 0x00 0x00
} __attribute__((packed));

/*
 * Is this another TLV?
 *   Len is always 4...
 */
struct mcfg_sub_version_data { // unsure
  uint16_t magic;            // 0x83 0x13, another magic number
  uint16_t len;           // 0x04 0x00
  uint32_t data;           // 0x01 0x00 || 0x03 0x00
} __attribute__((packed));

struct mcfg_nvitem {
  uint16_t id;           // EFS NV element?
  uint16_t payload_size; // Size of the rest of the item
  uint8_t *payload[0];
} __attribute__((packed));

struct mcfg_nvfile_part {
  uint16_t file_section; // 0x01 for filename, 0x02 for file contents
  uint16_t section_len;  // size of this piece
  uint8_t *payload[0];
} __attribute__((packed));

struct mcfg_item {
  uint32_t id;      // EFS NV element?
  uint8_t type;     // 0x01 || <-- ITEM TYPE?
  uint8_t attrib;   // 0x09 0x29? <-- Attributes?
  uint16_t padding; // 0x00 0x00
} __attribute__((packed));

struct mcfg_footer_header {
  uint16_t id; // 0xa1 0x00
  uint16_t len;

} __attribute__((packed));

struct mcfg_footer_proto {
  uint8_t id;
  uint16_t len;
  uint8_t data[0];
} __attribute__((packed));

// *ALMOST* constant, some magic identifier or version?
struct mcfg_footer_section_version1 {
  uint8_t id;    // 0x00
  uint16_t len;  // 2 bytes
  uint16_t data; // 256
} __attribute__((packed));

// This changes in different files, although structure stays and numbers match
// inside firmwares Seems like some version number too?
struct mcfg_footer_section_version2 {
  uint8_t id;    // 0x01
  uint16_t len;  // 4 bytes
  uint32_t data; // 33625405
} __attribute__((packed));

// Network
struct mcfg_footer_section_2 {
  uint8_t id;   // 0x01
  uint16_t len; // 4 bytes
  uint16_t mcc; // 460
  uint16_t mnc; // 01
} __attribute__((packed));

// Carrier name, as shown in QMBNCFG?
struct mcfg_footer_section_carrier_name {
  uint8_t id;   // 3
  uint16_t len; // 19 <-- len?
  uint8_t *carrier_config_name[];
} __attribute__((packed));

/*
Apparently it's a list of partial ICCIDs to match the SIMs
https://forums.quectel.com/t/document-sharing-sim-card/16046
https://blog.karthisoftek.com/a?ID=00900-29badf5d-bd0a-47f7-b3fc-eb900c57e003
*/
struct mcfg_footer_section_allowed_iccids {
  uint8_t id;         // 4
  uint16_t len;       // 10
  uint8_t foot14;     // 0
  uint8_t num_iccids; // 2?
  uint32_t iccids[0]; // 898601 898601
} __attribute__((packed));

struct mcfg_footer {
  uint32_t len;
  uint32_t footer_magic1; // 0x0a 00 00 00
  uint16_t footer_magic2; // 0xa1 00
  uint16_t size_trimmed;  // No confindence on this, its always len -0x10
  unsigned char magic[8]; // MCFG_TRL
} __attribute__((packed));

enum {
  MCFG_FILETYPE_HW = 0,
  MCFG_FILETYPE_SW = 1,
};
// Base item IDs
enum {
  MCFG_CARRIER_NAME = 0x00000019,
};

/* Item types, borrowed from
 * https://github.com/JohnBel/EfsTools/blob/master/EfsTools/Mbn/ItemType.cs */
enum {
  MCFG_ITEM_TYPE_NV = 0x01,
  MCFG_ITEM_TYPE_NVFILE = 0x02,
  MCFG_ITEM_TYPE_FILE = 0x04,
  MCFG_ITEM_TYPE_UNKNOWN = 0x05,
  MCFG_ITEM_TYPE_FOOT = 0x0A,
};

/* Attributes */
enum {
  ATTRIB_MODE_FOOTER = 0x00, // Only shows in footer?
  ATTRIB_MODE_09 = 0x09,
  ATTRIB_MODE_0D = 0x0D,
  ATTRIB_MODE_19 = 0x19,
  ATTRIB_MODE_29 = 0x29,
  ATTRIB_MODE_2D = 0x2D,
  ATTRIB_MODE_39 = 0x39,
  ATTRIB_MODE_2A = 0x2A,
};

/* EFS file sections */
enum {
  EFS_FILENAME = 0x01,
  EFS_FILECONTENTS = 0x02,
};

/* Known and unknown footer sections */
enum {
  MCFG_FOOTER_SECTION_VERSION_1 = 0x00,
  MCFG_FOOTER_SECTION_VERSION_2 = 0x01,
  MCFG_FOOTER_SECTION_APPLICABLE_MCC_MNC = 0x02,
  MCFG_FOOTER_SECTION_PROFILE_NAME = 0x03,
  MCFG_FOOTER_SECTION_ALLOWED_ICCIDS = 0x04,
};

/* This list is absolutely incomplete.
 *  In fact it's probably worthless, names
 *  are taken from an excel found in some
 *  obscure chinese site, leaving them here
 *  just in case it might help someone
 *
 */

static const struct {
  uint32_t id;
  const char *name;
} nvitem_names[] = {
    {5, "Slot Cycle Index"},
    {6, "Mobile CAI Revision Number"},
    {10, "Digital/Analog Mode Preference"},
    {25, "Authentication Key"},
    {26, "Authentication Key Checksum"},
    {27, "SSD A"},
    {28, "SSD A  Checksum"},
    {29, "SSD B"},
    {30, "SSD B Checksum"},
    {31, "Count"},
    {32, "MIN 1"},
    {33, "MIN 2"},
    {34, "CDMA Mobile Term SID Reg Flag"},
    {35, "CDMA Mobile Term Foreign SID Reg Flag"},
    {36, "CDMA Mobile Term Foreign NID Reg Flag"},
    {37, "ACCOLC"},
    {69, "Service Area Alert"},
    {70, "Call Fade Alert"},
    {71, "Banner"},
    {74, "Auto Answer Setting "},
    {75, "Auto Redial Setting"},
    {81, "Phone Lock"},
    {176, "IMSI MCC"},
    {177, "IMSI 11 12"},
    {178, "Directory Number"},
    {179, "Voice Privacy"},
    {209, "IMSI Length"},
    {215, "Directory Number PCS Format"},
    {240, "QNC Enabled Flag"},
    {241, "Data Service Option Set"},
    {255, "CDMA Negative SID"},
    {256, "Roaming List Enabled"},
    {259, "Home SID/NID List"},
    {260, "OTAPA Enabled"},
    {262, "True IMSI - MIN1"},
    {263, "True IMSI - MIN2"},
    {264, "True IMSI - MCC"},
    {265, "True IMSI-11 12 Digits"},
    {266, "True IMSI - Address Number"},
    {291, "Silent Redial Enabled"},
    {296, "OTASP SPC Change"},
    {297, "Data MDR Mode"},
    {298, "Packet Data Calls Originate String"},
    {304, "OTKSL flag"},
    {374, "Broadcast SMS Configuration"},
    {375, "Broadcast SMS User Preferences"},
    {405, "IS2000 CAI Radio Configuration RC Preference"},
    {409, "TTY mode"},
    {423, "Primary DNS Server"},
    {424, "Secondary DNS Server"},
    {429, "Data SCRM Enabled"},
    {441, "Band Class Preference (NV_BAND_PREF_I)"},
    {441, "NV_BAND_PREF_I"},
    {442, "Roam Preference"},
    {450, "Data Throttle Enabled"},
    {453, "Factory Testmode Phone Mode"},
    {459, "Data Services QC Mobile IP"},
    {459, "Data Service QC Mobile IP"},
    {460, "DS Mobile IP Registration Retries"},
    {461, "DS Mobile IP Registration Retries Intitial Interval"},
    {462, "DS Mobile IP registration Expiration Attempt Reg"},
    {463, "DS Mobile IP Number Profiles"},
    {464, "DS Mobile IP Currently Active Profiles"},
    {465, "DS MIP General User Profile"},
    {466, "DS MIP Shared Secret User  Profile"},
    {475, "HDRSCP session status"},
    {494, "DS Mobile IP MN Home Agent Timebase Diff"},
    {495, "MIP Handoff Optimization Enabled"},
    {495, "DS MIP QC PREV 6 MIP Handoff Optim Enabled"},
    {546, "DS Mobile IP RFC2002bis MN HA Auth Calc"},
    {553, "GSM A5 Algorithms supported"},
    {562, "Preferred Hybrid Mode"},
    {707, "DS Mobile IP RRQ If Traffic"},
    {714, "DS Mobile IP Enable Profile"},
    {818, "HDR Receive diversity"},
    {830, "SMS Config Routing"},
    {848, "Acquisition order preference"},
    {849, "Network Selection Mode Preference"},
    {850, "Service Domain Preference"},
    {854, "DS Mobile IP DMU PKOID"},
    {855, "RTRE Configuration"},
    {855, "RTRE Config"},
    {880, "RRC Integrity Enabled"},
    {881, "RRC Ciphering Enabled"},
    {882, "RRC Fake Security Enabled"},
    {889, "DS Mobile IP DMU MN Authentication"},
    {896, "UIM First Instruction Class"},
    {899, "JCDMA M512 Mode Setting"},
    {905, "Fatal Error Option"},
    {906, "IP PPP Password"},
    {909, "GSM/UMTS SMS Bearer Preference"},
    {910, "PPP User ID"},
    {911, "GPRS Multislot Class"},
    {928, "PZID Hysterisis activation timer"},
    {929, "PZID Hysterisis timer"},
    {930, "Packet Call Dial String Lookup Table"},
    {932, "Process Incoming CS Data Call As Internal"},
    {941, "PRL Protocol Revision Number"},
    {945, "MRU Data Type"},
    {946, "NV_BAND_PREF_I6_32_I"},
    {947, "GPRS Enable Anite GCF 51.010"},
    {1014, "GSM/UMTS Cell Broadcast SMS Service Table"},
    {1015, "GSM/UMTS Cell Broadcast SMS Service Table Size"},
    {1016, "GSM UMTS Cell Broadcast SMS Carrier Configuration"},
    {1017, "GSM UMTS Cell Broadcast SMS User Preference"},
    {1018, "CDMA Receive diversity"},
    {1030, "Force EU SGSNR GSM R99 Version"},
    {1031, "Force EU MSCR GSM R99 Version"},
    {1192, "HDR AN CHAP Authentication Password"},
    {1193, "Data Svcs MIP QC Handdown"},
    {1194, "HDR AN CHAP Authentication User ID"},
    {1302, "GSM AMR Call Configuration"},
    {1877, "RF Band Configuration"},
    {1883, "VCTCXO Slope"},
    {1892, "Diag Debug Control"},
    {1895, "Diag Debug Detail"},
    {1896, "Ipv6 Enabled"},
    {1897, "IPV6 State Machine Configuration"},
    {1907, "Authentication Require Password Encryption"},
    {1918, "AAGPS Default QoS Time"},
    {1920, "AAGPS Positioning Modes Supported"},
    {1962, "Trace Files Saved EFS"},
    {2508, "EDGE Feature Support"},
    {2509, "Edge Multislot class"},
    {2512, "GERAN Feature Pack1"},
    {2825, "DS Mip RM NAI"},
    {2826, "SMS BMC Reading Pref"},
    {2954, "NV_BAND_PREF_32_63_I"},
    {3006, "MS Max Number of SMS"},
    {3446, "TRM Configuration"},
    {3458, "HDR SCP Subtype Custom Config"},
    {3461, "ENS Enabled"},
    {3515, "CDMA Rx chain select threshold"},
    {3532, "SMS MO Retry Period"},
    {3533, "SMS MO Retry Interval"},
    {3628, "DTM Feature Support"},
    {3629, "DTM Multislot class"},
    {3630, "EDA Feature Support"},
    {3635, "SD Configurable Items"},
    {3649, "WCDMA RRC Version"},
    {3851, "WCDMA RX Diversity Control"},
    {3852, "WCDMA equalizer Control"},
    {4102, "CDMA SO68 enabled"},
    {4102, "Enable SO68 Capability"},
    {4117, "DARP Feature support"},
    {4118, "HSDPA Category"},
    {4173, "WCDMA RRC PDCP Disabled"},
    {4192, "CDMA S070 enabled"},
    {4192, "CDMA SO70 Enable"},
    {4204, "HDR SCP Force Release 0 Session Configuration"},
    {4209, "EDTM Feature Support"},
    {4210, "HSUPA Category"},
    {4228, "SMS MO on Access Channel"},
    {4229, "SMS MO on Traffic Channel"},
    {4230, "VOIP Preferred URI"},
    {4257, "RF PMIC Configuration"},
    {4261, "CPU Based Flow Control"},
    {4265, "VOIP Registration Mode"},
    {4366, "SMS Service option"},
    {4396, "DS Mobile IP Deregistration Retries"},
    {4398, "UIM Select Default SIM Application"},
    {4399, "Detect HW Reset"},
    {4432, "GPRS GEA Algorithms Supported"},
    {4528, "HDR EMPA Supported"},
    {4676, "DS707 Go NULL Timer 1X"},
    {4677, "DS707 Go NULL Timer DO"},
    {4722, "NAS Release Compliance"},
    {4964, "HDR SCP force AT configuration"},
    {5080, "NV_RR_ACQ_DB_CHUNK_00_I"},
    {5090, "WCDMA HSUPA CM Controller"},
    {5107, "Repeated ACCH"},
    {5280, "Disable CM Call Type"},
    {5770, "Toolkit CS PS Parallel"},
    {5773, "DSAT707 CTA Timer"},
    {5895, "MGRF Supported"},
    {6247, "RFNV LTE B4 TX Gain Index For APT 3"},
    {6248, "EHRPD Enabled"},
    {6253, "CSIM Support"},
    {6828, "LTE BC Config"},
    {6830, "CS TO VOIP Fallback Timer"},
    {6831, "VOIP Cancel Retry Timer"},
    {6832, "HDRSCP Force Restricted CF"},
    {6844, "ENHANCED HPLMN SRCH TBL"},
    {6850, "UMTS amr code preference config"},
    {6862, "UICC Mode"},
    {6907, "UIM HW SIM Config"},
    {7147, "RFNV LTE B24 TX Limit VS Freq"},
    {7166, "Enable SO73 Capability"},
};
/* NOTE:

Missing Sections:
NV ITEMS:
  Type 00
  Type 05


FOOTER:
  At least up to section 8, there are shared things among some of the sample
files It looks like sections >10 are custom fields of some sorts that only
certain carriers have. We'll store them just in case Section #5: When it
appears, it's always 4xuint8_t Section #6: Variable size, but shared accross
some of the profiles with different names in same country. Could be related to
MVNOs? Section #7: 4 Bytes Section 8: 32 Bytes Section #9: Typically 0 bytes
long when it shows up? Section #10 Section #37: Only SMARTFREN has it Section
#78 : Only Telefonica Spain has it.
*/
#endif
