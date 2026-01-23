/*
 * generate_blob.h - Blob generation from JSON schema files
 *
 * Generates binary completion data blob from JSON command schema.
 */

#ifndef GENERATE_BLOB_H
#define GENERATE_BLOB_H

#include <stdbool.h>

/*
 * Blob format constants - shared between generator and reader.
 * Keep these in sync with dump_blob.py.
 */
#define BLOB_MAGIC   "FCMP"
#define BLOB_VERSION 7

#define HEADER_SIZE  64
#define PARAM_SIZE   17
#define COMMAND_SIZE 18

/* Param flags */
#define FLAG_TAKES_VALUE  0x01
#define FLAG_IS_MEMBERS   0x02
#define FLAG_IS_COMPLETER 0x04

/* Header flags */
#define HEADER_FLAG_BIG_ENDIAN      0x01
#define HEADER_FLAG_NO_DESCRIPTIONS 0x02

/*
 * Generate a binary blob from a schema file.
 *
 * schema_path: Path to JSON schema file
 * output_path: Path to output blob file
 * big_endian: If true, generate big-endian blob
 * no_descriptions: If true, omit descriptions from blob (smaller size)
 * long_descriptions: If true, include full descriptions (default is first sentence only)
 *
 * Returns true on success, false on error (errors printed to stderr).
 */
bool generate_blob(const char *schema_path, const char *output_path, bool big_endian, bool no_descriptions, bool long_descriptions);

/*
 * Extract the CLI name from a schema file.
 *
 * Reads the "name" property from the schema. If not present, returns NULL.
 * Caller must free the returned string.
 */
char *get_schema_name(const char *schema_path);

#endif /* GENERATE_BLOB_H */
