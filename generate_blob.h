/*
 * generate_blob.h - Blob generation from TSV schema files
 *
 * Generates binary completion data blob from tab-separated command schema.
 */

#ifndef GENERATE_BLOB_H
#define GENERATE_BLOB_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Blob format constants - shared between generator and reader.
 * Keep these in sync with dump_blob.py.
 */
#define BLOB_MAGIC   "FCMP"
#define BLOB_VERSION 9

#define HEADER_SIZE  56
#define PARAM_SIZE   17
#define COMMAND_SIZE 18

/* Param flags */
#define FLAG_TAKES_VALUE  0x01
#define FLAG_IS_MEMBERS   0x02
#define FLAG_IS_COMPLETER 0x04

/* Header flags */
#define HEADER_FLAG_BIG_ENDIAN      0x01
#define HEADER_FLAG_NO_DESCRIPTIONS 0x02

/* Description mode for blob generation */
typedef enum {
    DESC_NONE = 0,   /* Omit descriptions entirely (smallest blob) */
    DESC_SHORT = 1,  /* First sentence only (default) */
    DESC_LONG = 2    /* Full descriptions */
} DescriptionMode;

/*
 * Generate a binary blob from a schema file.
 *
 * schema_path: Path to TSV schema file
 * output_path: Path to output blob file
 * big_endian: If true, generate big-endian blob
 * desc_mode: How to handle descriptions (DESC_NONE, DESC_SHORT, DESC_LONG)
 * desc_max_len: Maximum description length (0 = unlimited). If exceeded,
 *               truncate to (desc_max_len - 3) chars + "...".
 *
 * Returns true on success, false on error (errors printed to stderr).
 */
bool generate_blob(const char *schema_path, const char *output_path, bool big_endian, DescriptionMode desc_mode, size_t desc_max_len);

/*
 * Extract the CLI name from a schema file.
 *
 * Reads the "#name" directive from the TSV schema. If not present, returns NULL.
 * Caller must free the returned string.
 */
char *get_schema_name(const char *schema_path);

#endif /* GENERATE_BLOB_H */
