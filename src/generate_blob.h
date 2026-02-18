/*
 * generate_blob.h - Blob generation from .fcmps schema files
 *
 * Generates binary completion data blob from indentation-based tab-indented command schema.
 */

#ifndef GENERATE_BLOB_H
#define GENERATE_BLOB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Blob format constants - shared between generator and reader.
 * Keep these in sync with scripts/dump_blob.py.
 */
#define BLOB_MAGIC   "FCMP"
#define BLOB_VERSION 14

#define HEADER_SIZE         64
#define SECTION_ENTRY_SIZE  20
#define PARAM_SIZE          20
#define COMMAND_SIZE        20

/* Section ids */
#define SECTION_STRINGS_HOT     1
#define SECTION_STRINGS_COLD    2
#define SECTION_COMMANDS        3
#define SECTION_PARAMS          4
#define SECTION_CHOICES         5
#define SECTION_MEMBERS         6
#define SECTION_ROOT            7
#define SECTION_OPTION_LONG     8
#define SECTION_OPTION_SHORT    9

/* Section flags */
#define SECTION_FLAG_OPTIONAL   0x01

/* Param flags */
#define FLAG_TAKES_VALUE  0x01

/* Param value kinds */
#define VALUE_KIND_NONE       0
#define VALUE_KIND_CHOICES    1
#define VALUE_KIND_MEMBERS    2
#define VALUE_KIND_COMPLETER  3

/* Header flags */
#define HEADER_FLAG_NO_DESCRIPTIONS 0x01

/* Shared structs used by both generator and runtime */
typedef struct {
    uint32_t start;
    uint32_t count;
} Slice32;

typedef struct {
    uint32_t param_idx;
} LongIndexEntry;

typedef struct {
    uint8_t short_ch;
    uint8_t _pad[3];
    uint32_t param_idx;
} ShortIndexEntry;

/* Description mode for blob generation */
typedef enum {
    DESC_NONE = 0,   /* Omit descriptions entirely (smallest blob) */
    DESC_SHORT = 1,  /* First sentence only (default) */
    DESC_LONG = 2    /* Full descriptions */
} DescriptionMode;

/*
 * Generate a binary blob from a schema file.
 *
 * schema_path: Path to .fcmps schema file
 * output_path: Path to output blob file
 * desc_mode: How to handle descriptions (DESC_NONE, DESC_SHORT, DESC_LONG)
 * desc_max_len: Maximum description length in UTF-8 characters (0 = unlimited).
 *               If exceeded, truncate to (desc_max_len - 1) chars + "…" (Unicode ellipsis).
 *
 * Returns true on success, false on error (errors printed to stderr).
 */
bool generate_blob(const char *schema_path, const char *output_path, DescriptionMode desc_mode, size_t desc_max_len);

/*
 * Extract the CLI name from a schema file.
 *
 * Reads the first depth-0 command (the root/CLI name). If not present, returns NULL.
 * Caller must free the returned string.
 */
char *get_schema_name(const char *schema_path);

/*
 * Lint a schema file (syntax + structural validation).
 *
 * Returns true if schema is valid, false otherwise.
 */
bool lint_schema(const char *schema_path);

#endif /* GENERATE_BLOB_H */
