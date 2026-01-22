/*
 * generate_blob.h - Blob generation from JSON/YAML schema files
 *
 * Generates binary completion data blob from JSON or YAML command schema.
 */

#ifndef GENERATE_BLOB_H
#define GENERATE_BLOB_H

#include <stdbool.h>

/*
 * Generate a binary blob from a schema file.
 *
 * schema_path: Path to JSON or YAML schema file
 * output_path: Path to output blob file
 * big_endian: If true, generate big-endian blob
 *
 * Returns true on success, false on error (errors printed to stderr).
 */
bool generate_blob(const char *schema_path, const char *output_path, bool big_endian);

/*
 * Extract the CLI name from a schema file.
 *
 * Reads the "name" property from the schema. If not present, returns NULL.
 * Caller must free the returned string.
 */
char *get_schema_name(const char *schema_path);

#endif /* GENERATE_BLOB_H */
