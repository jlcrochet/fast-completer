/*
 * generate_blob.c - Blob generation from JSON/YAML schema files
 *
 * Generates binary completion data blob from JSON or YAML command schema.
 */

#include "generate_blob.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "vendor/cjson/cJSON.h"
#include "vendor/libyaml/include/yaml.h"

// Binary format constants (must match fast-completer.c)
#define BLOB_MAGIC "FCMP"
#define BLOB_VERSION 3
#define HEADER_SIZE 68
#define PARAM_SIZE 17
#define COMMAND_SIZE 20

// Param flags
#define FLAG_TAKES_VALUE 0x01
#define FLAG_IS_MEMBERS  0x02

// Header flags
#define HEADER_FLAG_BIG_ENDIAN      0x01
#define HEADER_FLAG_NO_DESCRIPTIONS 0x02

// Limits
#define VLQ_MAX_LENGTH 32767
#define SHORT_DESC_MAX_LEN 200

// Msgpack overhead constants
#define KEY_VALUE_LEN 5
#define KEY_DESC_LEN 11
#define OVERHEAD_PER_ITEM 25

// --------------------------------------------------------------------------
// Description truncation helpers
// --------------------------------------------------------------------------

// Check if position is inside a URL (has :// before without intervening space)
static bool in_url(const char *s, size_t pos) {
    // Look backwards for :// without hitting a space
    if (pos < 3) return false;
    for (size_t i = pos; i >= 3; i--) {
        if (s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == '\n') return false;
        if (s[i-1] == '/' && s[i-2] == '/' && s[i-3] == ':') return true;
        if (i == 3) break;
    }
    return false;
}

// Check if period is part of an abbreviation (e.g., i.e., etc., vs.)
static bool is_abbreviation(const char *s, size_t pos) {
    // Common abbreviations - check if period is preceded by these
    static const char *abbrevs[] = {
        "e.g", "i.e", "etc", "vs", "approx", "incl", "excl",
        "min", "max", "avg", "num", "vol", "ch", "sec", "fig",
        NULL
    };

    if (pos < 2) return false;

    for (const char **abbr = abbrevs; *abbr; abbr++) {
        size_t len = strlen(*abbr);
        if (pos >= len) {
            bool match = true;
            for (size_t i = 0; i < len && match; i++) {
                char c1 = s[pos - len + i];
                char c2 = (*abbr)[i];
                // Case-insensitive comparison
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) match = false;
            }
            if (match) {
                // Make sure it's a word boundary before the abbreviation
                if (pos == len || s[pos - len - 1] == ' ' || s[pos - len - 1] == '(') {
                    return true;
                }
            }
        }
    }
    return false;
}

// Check if period is between digits (version number like 1.0.0)
static bool is_version_number(const char *s, size_t pos, size_t len) {
    if (pos == 0 || pos + 1 >= len) return false;
    return (s[pos - 1] >= '0' && s[pos - 1] <= '9') &&
           (s[pos + 1] >= '0' && s[pos + 1] <= '9');
}

// Truncate description to first sentence
// Returns a newly allocated string (caller must free)
static char *truncate_to_first_sentence(const char *desc) {
    if (!desc || !*desc) return strdup("");

    size_t len = strlen(desc);
    size_t end = len;

    for (size_t i = 0; i < len && i < SHORT_DESC_MAX_LEN; i++) {
        char c = desc[i];
        char next = (i + 1 < len) ? desc[i + 1] : '\0';

        // Stop at newlines
        if (c == '\n') {
            end = i;
            break;
        }

        // Check for sentence-ending punctuation followed by space/end
        if ((c == '.' || c == ';' || c == ':') &&
            (next == ' ' || next == '\n' || next == '\0' || next == '\t')) {

            // Skip if it's a special case
            if (c == '.') {
                if (in_url(desc, i)) continue;
                if (is_abbreviation(desc, i)) continue;
                if (is_version_number(desc, i, len)) continue;
            }

            end = i;  // Stop before the punctuation
            break;
        }
    }

    // If we hit max length without finding sentence end, truncate with ...
    if (end == len && len > SHORT_DESC_MAX_LEN) {
        // Find last space before max length to avoid cutting words
        end = SHORT_DESC_MAX_LEN;
        while (end > SHORT_DESC_MAX_LEN - 30 && desc[end] != ' ') {
            end--;
        }
        if (desc[end] == ' ') {
            char *result = malloc(end + 4);
            memcpy(result, desc, end);
            memcpy(result + end, "...", 4);
            return result;
        }
        end = SHORT_DESC_MAX_LEN;
    }

    char *result = malloc(end + 1);
    memcpy(result, desc, end);
    result[end] = '\0';
    return result;
}

// --------------------------------------------------------------------------
// String Table (with hash table for O(1) deduplication)
// --------------------------------------------------------------------------

// Hash table entry: stores hash and index into strings array
typedef struct {
    uint32_t hash;      // 0 = empty slot
    uint32_t idx;       // Index into strings/offsets arrays
} HashEntry;

typedef struct {
    char **strings;         // Array of string pointers
    uint32_t *offsets;      // Offset of each string in data
    size_t count;           // Number of strings
    size_t capacity;        // Allocated capacity
    uint8_t *data;          // Packed string data
    size_t data_len;        // Length of data
    size_t data_cap;        // Capacity of data
    size_t max_str_len;     // Maximum string length seen
    HashEntry *hash_table;  // Hash table for deduplication
    size_t hash_cap;        // Hash table capacity (power of 2)
} StringTable;

// DJB2 hash function
static uint32_t hash_string(const char *s) {
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) ^ (uint8_t)*s++;
    return h ? h : 1;  // Ensure non-zero (0 = empty slot)
}

static void strtab_init(StringTable *st) {
    st->capacity = 1024;
    st->strings = calloc(st->capacity, sizeof(char *));
    st->offsets = calloc(st->capacity, sizeof(uint32_t));
    st->count = 0;
    st->data_cap = 65536;
    st->data = malloc(st->data_cap);
    st->data_len = 0;
    st->max_str_len = 0;

    // Initialize hash table
    st->hash_cap = 4096;  // Start with reasonable size
    st->hash_table = calloc(st->hash_cap, sizeof(HashEntry));

    // Add empty string at offset 0
    st->strings[0] = strdup("");
    st->offsets[0] = 0;
    st->data[0] = 0;  // Empty string: length 0
    st->data_len = 1;
    st->count = 1;

    // Add empty string to hash table
    uint32_t h = hash_string("");
    size_t idx = h & (st->hash_cap - 1);
    st->hash_table[idx].hash = h;
    st->hash_table[idx].idx = 0;
}

static void strtab_free(StringTable *st) {
    for (size_t i = 0; i < st->count; i++) {
        free(st->strings[i]);
    }
    free(st->strings);
    free(st->offsets);
    free(st->data);
    free(st->hash_table);
}

// Grow hash table when load factor exceeds 50%
static void strtab_grow_hash(StringTable *st) {
    size_t old_cap = st->hash_cap;
    HashEntry *old_table = st->hash_table;

    st->hash_cap *= 2;
    st->hash_table = calloc(st->hash_cap, sizeof(HashEntry));

    // Rehash all entries
    for (size_t i = 0; i < old_cap; i++) {
        if (old_table[i].hash) {
            size_t idx = old_table[i].hash & (st->hash_cap - 1);
            while (st->hash_table[idx].hash) {
                idx = (idx + 1) & (st->hash_cap - 1);
            }
            st->hash_table[idx] = old_table[i];
        }
    }
    free(old_table);
}

static uint32_t strtab_add(StringTable *st, const char *s) {
    if (!s) s = "";

    // Hash lookup
    uint32_t h = hash_string(s);
    size_t idx = h & (st->hash_cap - 1);

    while (st->hash_table[idx].hash) {
        if (st->hash_table[idx].hash == h) {
            // Potential match - verify string
            uint32_t str_idx = st->hash_table[idx].idx;
            if (strcmp(st->strings[str_idx], s) == 0) {
                return st->offsets[str_idx];
            }
        }
        idx = (idx + 1) & (st->hash_cap - 1);
    }

    // Not found - add new string
    if (st->count >= st->capacity) {
        st->capacity *= 2;
        st->strings = realloc(st->strings, st->capacity * sizeof(char *));
        st->offsets = realloc(st->offsets, st->capacity * sizeof(uint32_t));
    }

    // Grow hash table if needed (keep load factor < 50%)
    if (st->count * 2 >= st->hash_cap) {
        strtab_grow_hash(st);
        // Recalculate insertion index after rehash
        idx = h & (st->hash_cap - 1);
        while (st->hash_table[idx].hash) {
            idx = (idx + 1) & (st->hash_cap - 1);
        }
    }

    size_t len = strlen(s);
    if (len > st->max_str_len) st->max_str_len = len;

    // Calculate space needed
    size_t vlq_len = (len < 128) ? 1 : 2;
    size_t total = vlq_len + len;

    // Ensure capacity
    while (st->data_len + total > st->data_cap) {
        st->data_cap *= 2;
        st->data = realloc(st->data, st->data_cap);
    }

    uint32_t offset = (uint32_t)st->data_len;

    // Write VLQ length
    if (len < 128) {
        st->data[st->data_len++] = (uint8_t)len;
    } else if (len <= VLQ_MAX_LENGTH) {
        st->data[st->data_len++] = 0x80 | (uint8_t)(len >> 8);
        st->data[st->data_len++] = (uint8_t)(len & 0xff);
    } else {
        fprintf(stderr, "String too long: %zu bytes\n", len);
        return 0;
    }

    // Write string data
    memcpy(st->data + st->data_len, s, len);
    st->data_len += len;

    // Store in lookup table
    uint32_t str_idx = (uint32_t)st->count;
    st->strings[st->count] = strdup(s);
    st->offsets[st->count] = offset;
    st->count++;

    // Add to hash table
    st->hash_table[idx].hash = h;
    st->hash_table[idx].idx = str_idx;

    return offset;
}

// --------------------------------------------------------------------------
// Parameter and Command Structures
// --------------------------------------------------------------------------

typedef struct {
    uint32_t name_off;
    uint32_t short_off;
    uint32_t desc_off;
    uint32_t choices_idx;   // Index into choices/members list (converted to offset later)
    uint8_t flags;
} ParamEntry;

typedef struct {
    uint32_t name_off;
    uint32_t desc_off;
    uint32_t params_idx;
    uint32_t subcommands_idx;
    uint16_t params_count;
    uint16_t subcommands_count;
} CommandEntry;

typedef struct {
    uint32_t *offsets;      // Array of string offsets
    size_t count;           // Number of strings
} StringList;

// --------------------------------------------------------------------------
// Blob Generator State
// --------------------------------------------------------------------------

typedef struct {
    StringTable strtab;

    // Params array (index 0 is sentinel)
    ParamEntry *params;
    size_t params_count;
    size_t params_cap;

    // Commands array (index 0 is sentinel)
    CommandEntry *commands;
    size_t commands_count;
    size_t commands_cap;

    // Choices and members lists
    StringList *choices_lists;
    size_t choices_count;
    size_t choices_cap;

    StringList *members_lists;
    size_t members_count;
    size_t members_cap;

    // Global params
    ParamEntry *global_params;
    size_t global_params_count;
    size_t global_params_cap;

    // Tracking for buffer size calculation
    size_t total_leaf_commands;
    size_t total_leaf_bytes;
    size_t max_param_count;
    size_t max_param_bytes;
    size_t max_choices_count;
    size_t max_choices_bytes;
    size_t max_members_count;
    size_t max_members_bytes;
    size_t max_command_path_len;
    size_t global_param_count;
    size_t global_param_bytes;

    // Current command tracking
    size_t current_param_bytes;
    size_t current_param_count;

    // Byte order
    bool big_endian;

    // Description options
    bool no_descriptions;
    bool long_descriptions;  // Default is short (first sentence)

    // Track if any descriptions were actually added
    bool has_any_descriptions;
} BlobGen;

static void blobgen_init(BlobGen *bg, bool big_endian, bool no_descriptions, bool long_descriptions) {
    memset(bg, 0, sizeof(*bg));
    strtab_init(&bg->strtab);

    bg->params_cap = 1024;
    bg->params = calloc(bg->params_cap, sizeof(ParamEntry));
    bg->params_count = 0;

    bg->commands_cap = 1024;
    bg->commands = calloc(bg->commands_cap, sizeof(CommandEntry));
    bg->commands_count = 0;

    bg->choices_cap = 256;
    bg->choices_lists = calloc(bg->choices_cap, sizeof(StringList));
    bg->choices_count = 0;

    bg->members_cap = 256;
    bg->members_lists = calloc(bg->members_cap, sizeof(StringList));
    bg->members_count = 0;

    bg->global_params_cap = 64;
    bg->global_params = calloc(bg->global_params_cap, sizeof(ParamEntry));
    bg->global_params_count = 0;

    bg->big_endian = big_endian;
    bg->no_descriptions = no_descriptions;
    bg->long_descriptions = long_descriptions;
}

// Add a description to the string table, applying truncation if needed
// If track is true, sets has_any_descriptions flag
static uint32_t strtab_add_desc_ex(BlobGen *bg, const char *desc, bool track) {
    if (bg->no_descriptions || !desc || !*desc) {
        return 0;
    }

    char *processed = NULL;
    if (!bg->long_descriptions) {
        // Default: truncate to first sentence
        processed = truncate_to_first_sentence(desc);
        desc = processed;
    }

    uint32_t offset = 0;
    if (desc && *desc) {
        offset = strtab_add(&bg->strtab, desc);
        if (track) bg->has_any_descriptions = true;
    }

    free(processed);
    return offset;
}

// Add a description and track it
static uint32_t strtab_add_desc(BlobGen *bg, const char *desc) {
    return strtab_add_desc_ex(bg, desc, true);
}

static void blobgen_free(BlobGen *bg) {
    strtab_free(&bg->strtab);
    free(bg->params);
    free(bg->commands);
    for (size_t i = 0; i < bg->choices_count; i++) {
        free(bg->choices_lists[i].offsets);
    }
    free(bg->choices_lists);
    for (size_t i = 0; i < bg->members_count; i++) {
        free(bg->members_lists[i].offsets);
    }
    free(bg->members_lists);
    free(bg->global_params);
}

// --------------------------------------------------------------------------
// Tracking functions
// --------------------------------------------------------------------------

static void track_leaf_command(BlobGen *bg, size_t value_len, size_t desc_len) {
    bg->total_leaf_commands++;
    bg->total_leaf_bytes += value_len + desc_len;
    if (value_len > bg->max_command_path_len) {
        bg->max_command_path_len = value_len;
    }
}

static void track_param(BlobGen *bg, size_t value_len, size_t desc_len) {
    bg->current_param_bytes += value_len + desc_len;
    bg->current_param_count++;
}

static void finish_command_params(BlobGen *bg) {
    if (bg->current_param_bytes > bg->max_param_bytes) {
        bg->max_param_bytes = bg->current_param_bytes;
        bg->max_param_count = bg->current_param_count;
    }
    bg->current_param_bytes = 0;
    bg->current_param_count = 0;
}

static void track_choices(BlobGen *bg, size_t total_bytes, size_t count) {
    if (total_bytes > bg->max_choices_bytes) {
        bg->max_choices_bytes = total_bytes;
        bg->max_choices_count = count;
    }
}

static void track_members(BlobGen *bg, size_t total_bytes, size_t count) {
    if (total_bytes > bg->max_members_bytes) {
        bg->max_members_bytes = total_bytes;
        bg->max_members_count = count;
    }
}

static size_t calc_msgpack_buffer_size(BlobGen *bg) {
    // Scenario 1: Root level
    size_t root_count = bg->total_leaf_commands + 1 + bg->global_param_count;
    size_t root_bytes = 5 + root_count * OVERHEAD_PER_ITEM +
                        bg->total_leaf_bytes + 50 + bg->global_param_bytes;

    // Scenario 2: Deep command with many params
    size_t deep_count = bg->max_param_count + bg->global_param_count;
    size_t deep_bytes = 5 + deep_count * OVERHEAD_PER_ITEM +
                        bg->max_param_bytes + bg->global_param_bytes;

    // Scenario 3: Choice completion
    size_t choices_bytes = 5 + bg->max_choices_count * OVERHEAD_PER_ITEM +
                           bg->max_choices_bytes;

    // Scenario 4: Member completion
    size_t members_bytes = 5 + bg->max_members_count * OVERHEAD_PER_ITEM +
                           bg->max_members_bytes;

    size_t buffer_size = root_bytes;
    if (deep_bytes > buffer_size) buffer_size = deep_bytes;
    if (choices_bytes > buffer_size) buffer_size = choices_bytes;
    if (members_bytes > buffer_size) buffer_size = members_bytes;

    return buffer_size;
}

// --------------------------------------------------------------------------
// Choices/Members list management
// --------------------------------------------------------------------------

static size_t get_choices_index(BlobGen *bg, cJSON *choices_arr) {
    if (!choices_arr || !cJSON_IsArray(choices_arr)) return (size_t)-1;

    int count = cJSON_GetArraySize(choices_arr);
    if (count == 0) return (size_t)-1;

    // Allocate and fill string list
    if (bg->choices_count >= bg->choices_cap) {
        bg->choices_cap *= 2;
        bg->choices_lists = realloc(bg->choices_lists, bg->choices_cap * sizeof(StringList));
    }

    StringList *sl = &bg->choices_lists[bg->choices_count];
    sl->offsets = malloc(count * sizeof(uint32_t));
    sl->count = count;

    size_t total_bytes = 0;
    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(choices_arr, i);
        const char *s = cJSON_IsString(item) ? item->valuestring : "";
        sl->offsets[i] = strtab_add(&bg->strtab, s);
        total_bytes += strlen(s);
    }

    track_choices(bg, total_bytes, count);
    return bg->choices_count++;
}

static size_t get_members_index(BlobGen *bg, cJSON *members_arr) {
    if (!members_arr || !cJSON_IsArray(members_arr)) return (size_t)-1;

    int count = cJSON_GetArraySize(members_arr);
    if (count == 0) return (size_t)-1;

    if (bg->members_count >= bg->members_cap) {
        bg->members_cap *= 2;
        bg->members_lists = realloc(bg->members_lists, bg->members_cap * sizeof(StringList));
    }

    StringList *sl = &bg->members_lists[bg->members_count];
    sl->offsets = malloc(count * sizeof(uint32_t));
    sl->count = count;

    size_t total_bytes = 0;
    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(members_arr, i);
        cJSON *key = cJSON_GetObjectItem(item, "key");
        if (key && cJSON_IsString(key)) {
            // Flatten: add "key=" suffix
            char buf[1024];
            snprintf(buf, sizeof(buf), "%s=", key->valuestring);
            sl->offsets[i] = strtab_add(&bg->strtab, buf);
            total_bytes += strlen(buf);
        } else {
            sl->offsets[i] = 0;
        }
    }

    track_members(bg, total_bytes, count);
    return bg->members_count++;
}

// --------------------------------------------------------------------------
// Parameter extraction
// --------------------------------------------------------------------------

typedef struct {
    char *name;         // Long option (e.g., "--name")
    char *short_opt;    // Short option (e.g., "-n"), or NULL
    char *description;
    bool takes_value;
    cJSON *choices;     // Array of choices, or NULL
    cJSON *members;     // Array of members, or NULL
} ParamInfo;

static bool get_param_info(cJSON *param, ParamInfo *info) {
    memset(info, 0, sizeof(*info));

    cJSON *options = cJSON_GetObjectItem(param, "options");
    if (!options || !cJSON_IsArray(options) || cJSON_GetArraySize(options) == 0) {
        // Try 'name' field directly
        cJSON *name = cJSON_GetObjectItem(param, "name");
        if (!name || !cJSON_IsString(name)) return false;

        const char *name_str = name->valuestring;
        // Handle space-separated options
        if (strchr(name_str, ' ')) {
            // Parse space-separated options
            char *copy = strdup(name_str);
            char *token = strtok(copy, " ");
            while (token) {
                if (strncmp(token, "--", 2) == 0) {
                    if (!info->name || strlen(token) > strlen(info->name)) {
                        free(info->name);
                        info->name = strdup(token);
                    }
                } else if (token[0] == '-' && strlen(token) == 2) {
                    free(info->short_opt);
                    info->short_opt = strdup(token);
                }
                token = strtok(NULL, " ");
            }
            free(copy);
        } else if (strncmp(name_str, "--", 2) == 0) {
            info->name = strdup(name_str);
        } else {
            return false;
        }
    } else {
        // Parse options array
        int opt_count = cJSON_GetArraySize(options);
        for (int i = 0; i < opt_count; i++) {
            cJSON *opt = cJSON_GetArrayItem(options, i);
            if (!cJSON_IsString(opt)) continue;
            const char *opt_str = opt->valuestring;
            if (strncmp(opt_str, "--", 2) == 0) {
                if (!info->name || strlen(opt_str) > strlen(info->name)) {
                    free(info->name);
                    info->name = strdup(opt_str);
                }
            } else if (opt_str[0] == '-' && strlen(opt_str) == 2) {
                free(info->short_opt);
                info->short_opt = strdup(opt_str);
            }
        }
    }

    if (!info->name) return false;

    // Determine if it takes a value
    cJSON *choices = cJSON_GetObjectItem(param, "choices");
    bool is_bool = false;
    if (choices && cJSON_IsArray(choices) && cJSON_GetArraySize(choices) == 2) {
        // Check if choices are just true/false
        cJSON *c0 = cJSON_GetArrayItem(choices, 0);
        cJSON *c1 = cJSON_GetArrayItem(choices, 1);
        const char *s0 = cJSON_IsString(c0) ? c0->valuestring : "";
        const char *s1 = cJSON_IsString(c1) ? c1->valuestring : "";
        if ((strcasecmp(s0, "true") == 0 || strcasecmp(s0, "false") == 0) &&
            (strcasecmp(s1, "true") == 0 || strcasecmp(s1, "false") == 0)) {
            is_bool = true;
        }
    }

    info->takes_value = true;
    if (is_bool) {
        info->takes_value = false;
    } else {
        cJSON *type = cJSON_GetObjectItem(param, "type");
        if (type && cJSON_IsString(type)) {
            if (strcmp(type->valuestring, "bool") == 0 ||
                strcmp(type->valuestring, "boolean") == 0) {
                info->takes_value = false;
            }
        }

        cJSON *def = cJSON_GetObjectItem(param, "default");
        if (def && cJSON_IsBool(def)) {
            info->takes_value = false;
        }
    }

    // Override with explicit takes_value
    cJSON *tv = cJSON_GetObjectItem(param, "takes_value");
    if (tv) {
        info->takes_value = cJSON_IsTrue(tv);
    }

    // Get description
    cJSON *summary = cJSON_GetObjectItem(param, "summary");
    cJSON *desc = cJSON_GetObjectItem(param, "description");
    if (summary && cJSON_IsString(summary)) {
        info->description = strdup(summary->valuestring);
    } else if (desc && cJSON_IsString(desc)) {
        info->description = strdup(desc->valuestring);
    } else {
        info->description = strdup("");
    }

    // Get choices (non-bool)
    if (choices && cJSON_IsArray(choices) && !is_bool) {
        info->choices = choices;
    }

    // Get members
    cJSON *members = cJSON_GetObjectItem(param, "members");
    if (!info->choices && members && cJSON_IsArray(members)) {
        info->members = members;
    }

    return true;
}

static void free_param_info(ParamInfo *info) {
    free(info->name);
    free(info->short_opt);
    free(info->description);
}

// --------------------------------------------------------------------------
// Command Tree Building
// --------------------------------------------------------------------------

typedef struct CommandNode {
    char *name;
    cJSON *cmd;
    struct CommandNode **children;
    size_t children_count;
    size_t children_cap;
} CommandNode;

static CommandNode *node_create(const char *name) {
    CommandNode *node = calloc(1, sizeof(CommandNode));
    node->name = strdup(name ? name : "");
    node->children_cap = 8;
    node->children = calloc(node->children_cap, sizeof(CommandNode *));
    return node;
}

static void node_free(CommandNode *node) {
    if (!node) return;
    free(node->name);
    for (size_t i = 0; i < node->children_count; i++) {
        node_free(node->children[i]);
    }
    free(node->children);
    free(node);
}

static CommandNode *node_get_child(CommandNode *node, const char *name) {
    for (size_t i = 0; i < node->children_count; i++) {
        if (strcmp(node->children[i]->name, name) == 0) {
            return node->children[i];
        }
    }
    return NULL;
}

static CommandNode *node_add_child(CommandNode *node, const char *name) {
    if (node->children_count >= node->children_cap) {
        node->children_cap *= 2;
        node->children = realloc(node->children, node->children_cap * sizeof(CommandNode *));
    }
    CommandNode *child = node_create(name);
    node->children[node->children_count++] = child;
    return child;
}

static CommandNode *build_command_tree(cJSON *commands) {
    CommandNode *root = node_create("");

    int cmd_count = cJSON_GetArraySize(commands);
    for (int i = 0; i < cmd_count; i++) {
        cJSON *cmd = cJSON_GetArrayItem(commands, i);
        cJSON *name_obj = cJSON_GetObjectItem(cmd, "name");
        if (!name_obj || !cJSON_IsString(name_obj)) continue;

        const char *name = name_obj->valuestring;
        char *copy = strdup(name);
        char *token = strtok(copy, " ");
        CommandNode *node = root;

        while (token) {
            CommandNode *child = node_get_child(node, token);
            if (!child) {
                child = node_add_child(node, token);
            }
            node = child;
            token = strtok(NULL, " ");
        }

        node->cmd = cmd;
        free(copy);
    }

    return root;
}

// Sort children alphabetically
static int cmp_nodes(const void *a, const void *b) {
    const CommandNode *na = *(const CommandNode **)a;
    const CommandNode *nb = *(const CommandNode **)b;
    return strcmp(na->name, nb->name);
}

static void sort_children(CommandNode *node) {
    if (node->children_count > 1) {
        qsort(node->children, node->children_count, sizeof(CommandNode *), cmp_nodes);
    }
    for (size_t i = 0; i < node->children_count; i++) {
        sort_children(node->children[i]);
    }
}

// --------------------------------------------------------------------------
// Collect params and commands
// --------------------------------------------------------------------------

typedef struct {
    uint32_t idx;
    uint16_t count;
} IdxCount;

static IdxCount collect_params(BlobGen *bg, cJSON *params_arr) {
    IdxCount result = {0, 0};
    if (!params_arr || !cJSON_IsArray(params_arr)) return result;

    int count = cJSON_GetArraySize(params_arr);
    if (count == 0) return result;

    uint32_t start_idx = (uint32_t)bg->params_count;
    uint16_t valid_count = 0;

    for (int i = 0; i < count; i++) {
        cJSON *p = cJSON_GetArrayItem(params_arr, i);
        ParamInfo info;
        if (!get_param_info(p, &info)) continue;

        // Ensure capacity
        if (bg->params_count >= bg->params_cap) {
            bg->params_cap *= 2;
            bg->params = realloc(bg->params, bg->params_cap * sizeof(ParamEntry));
        }

        ParamEntry *pe = &bg->params[bg->params_count++];
        pe->name_off = strtab_add(&bg->strtab, info.name);
        pe->short_off = info.short_opt ? strtab_add(&bg->strtab, info.short_opt) : 0;
        pe->desc_off = strtab_add_desc(bg, info.description);
        pe->flags = 0;
        pe->choices_idx = (uint32_t)-1;

        if (info.takes_value) pe->flags |= FLAG_TAKES_VALUE;

        if (info.choices) {
            pe->choices_idx = (uint32_t)get_choices_index(bg, info.choices);
        } else if (info.members) {
            pe->choices_idx = (uint32_t)get_members_index(bg, info.members);
            pe->flags |= FLAG_IS_MEMBERS;
        }

        track_param(bg, strlen(info.name), bg->no_descriptions ? 0 : strlen(info.description));
        free_param_info(&info);
        valid_count++;
    }

    if (valid_count == 0) return result;

    finish_command_params(bg);

    result.idx = start_idx;
    result.count = valid_count;
    return result;
}

static IdxCount collect_commands(BlobGen *bg, CommandNode *node);

static IdxCount collect_commands(BlobGen *bg, CommandNode *node) {
    IdxCount result = {0, 0};
    if (node->children_count == 0) return result;

    // First, recursively collect all children
    typedef struct {
        uint32_t name_off;
        uint32_t desc_off;
        uint32_t params_idx;
        uint16_t params_count;
        uint32_t subcommands_idx;
        uint16_t subcommands_count;
        const char *path;
        size_t desc_len;
    } ChildData;

    ChildData *child_data = malloc(node->children_count * sizeof(ChildData));

    for (size_t i = 0; i < node->children_count; i++) {
        CommandNode *child = node->children[i];

        IdxCount sub_result = collect_commands(bg, child);
        child_data[i].subcommands_idx = sub_result.idx;
        child_data[i].subcommands_count = sub_result.count;

        cJSON *params_arr = NULL;
        const char *desc = "";
        if (child->cmd) {
            params_arr = cJSON_GetObjectItem(child->cmd, "parameters");
            cJSON *summary = cJSON_GetObjectItem(child->cmd, "summary");
            cJSON *desc_obj = cJSON_GetObjectItem(child->cmd, "description");
            if (summary && cJSON_IsString(summary)) desc = summary->valuestring;
            else if (desc_obj && cJSON_IsString(desc_obj)) desc = desc_obj->valuestring;
        }

        IdxCount params_result = collect_params(bg, params_arr);
        child_data[i].params_idx = params_result.idx;
        child_data[i].params_count = params_result.count;
        child_data[i].name_off = strtab_add(&bg->strtab, child->name);
        child_data[i].desc_off = strtab_add_desc(bg, desc);
        child_data[i].desc_len = bg->no_descriptions ? 0 : strlen(desc);

        // Track leaf command
        if (child_data[i].subcommands_count == 0 && child->cmd) {
            cJSON *name_obj = cJSON_GetObjectItem(child->cmd, "name");
            const char *path = name_obj ? name_obj->valuestring : child->name;
            child_data[i].path = path;
            track_leaf_command(bg, strlen(path), child_data[i].desc_len);
        } else {
            child_data[i].path = NULL;
        }
    }

    // Now add commands to array
    uint32_t start_idx = (uint32_t)bg->commands_count;

    for (size_t i = 0; i < node->children_count; i++) {
        if (bg->commands_count >= bg->commands_cap) {
            bg->commands_cap *= 2;
            bg->commands = realloc(bg->commands, bg->commands_cap * sizeof(CommandEntry));
        }

        CommandEntry *ce = &bg->commands[bg->commands_count++];
        ce->name_off = child_data[i].name_off;
        ce->desc_off = child_data[i].desc_off;
        ce->params_idx = child_data[i].params_idx;
        ce->subcommands_idx = child_data[i].subcommands_idx;
        ce->params_count = child_data[i].params_count;
        ce->subcommands_count = child_data[i].subcommands_count;
    }

    free(child_data);
    result.idx = start_idx;
    result.count = (uint16_t)node->children_count;
    return result;
}

// --------------------------------------------------------------------------
// Byte order helpers
// --------------------------------------------------------------------------

static void write_u16(uint8_t *buf, uint16_t val, bool big_endian) {
    if (big_endian) {
        buf[0] = (uint8_t)(val >> 8);
        buf[1] = (uint8_t)val;
    } else {
        buf[0] = (uint8_t)val;
        buf[1] = (uint8_t)(val >> 8);
    }
}

static void write_u32(uint8_t *buf, uint32_t val, bool big_endian) {
    if (big_endian) {
        buf[0] = (uint8_t)(val >> 24);
        buf[1] = (uint8_t)(val >> 16);
        buf[2] = (uint8_t)(val >> 8);
        buf[3] = (uint8_t)val;
    } else {
        buf[0] = (uint8_t)val;
        buf[1] = (uint8_t)(val >> 8);
        buf[2] = (uint8_t)(val >> 16);
        buf[3] = (uint8_t)(val >> 24);
    }
}

// --------------------------------------------------------------------------
// YAML to JSON conversion
// --------------------------------------------------------------------------

static cJSON *yaml_to_json(yaml_document_t *doc, yaml_node_t *node);

static cJSON *yaml_scalar_to_json(yaml_node_t *node) {
    const char *val = (const char *)node->data.scalar.value;

    // Try to detect type
    if (strcmp(val, "true") == 0 || strcmp(val, "True") == 0 ||
        strcmp(val, "TRUE") == 0 || strcmp(val, "yes") == 0) {
        return cJSON_CreateBool(true);
    }
    if (strcmp(val, "false") == 0 || strcmp(val, "False") == 0 ||
        strcmp(val, "FALSE") == 0 || strcmp(val, "no") == 0) {
        return cJSON_CreateBool(false);
    }
    if (strcmp(val, "null") == 0 || strcmp(val, "~") == 0 || val[0] == '\0') {
        return cJSON_CreateNull();
    }

    // Try number
    char *endptr;
    double d = strtod(val, &endptr);
    if (*endptr == '\0' && endptr != val) {
        return cJSON_CreateNumber(d);
    }

    return cJSON_CreateString(val);
}

static cJSON *yaml_sequence_to_json(yaml_document_t *doc, yaml_node_t *node) {
    cJSON *arr = cJSON_CreateArray();
    for (yaml_node_item_t *item = node->data.sequence.items.start;
         item < node->data.sequence.items.top; item++) {
        yaml_node_t *child = yaml_document_get_node(doc, *item);
        cJSON_AddItemToArray(arr, yaml_to_json(doc, child));
    }
    return arr;
}

static cJSON *yaml_mapping_to_json(yaml_document_t *doc, yaml_node_t *node) {
    cJSON *obj = cJSON_CreateObject();
    for (yaml_node_pair_t *pair = node->data.mapping.pairs.start;
         pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *key_node = yaml_document_get_node(doc, pair->key);
        yaml_node_t *val_node = yaml_document_get_node(doc, pair->value);
        if (key_node && key_node->type == YAML_SCALAR_NODE) {
            const char *key = (const char *)key_node->data.scalar.value;
            cJSON_AddItemToObject(obj, key, yaml_to_json(doc, val_node));
        }
    }
    return obj;
}

static cJSON *yaml_to_json(yaml_document_t *doc, yaml_node_t *node) {
    if (!node) return cJSON_CreateNull();
    switch (node->type) {
        case YAML_SCALAR_NODE:
            return yaml_scalar_to_json(node);
        case YAML_SEQUENCE_NODE:
            return yaml_sequence_to_json(doc, node);
        case YAML_MAPPING_NODE:
            return yaml_mapping_to_json(doc, node);
        default:
            return cJSON_CreateNull();
    }
}

static cJSON *load_yaml_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return NULL;
    }

    yaml_parser_t parser;
    yaml_document_t document;

    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize YAML parser\n");
        fclose(f);
        return NULL;
    }

    yaml_parser_set_input_file(&parser, f);

    if (!yaml_parser_load(&parser, &document)) {
        fprintf(stderr, "YAML parse error: %s at line %zu\n",
                parser.problem, parser.problem_mark.line + 1);
        yaml_parser_delete(&parser);
        fclose(f);
        return NULL;
    }

    yaml_node_t *root = yaml_document_get_root_node(&document);
    cJSON *json = yaml_to_json(&document, root);

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    fclose(f);

    return json;
}

// --------------------------------------------------------------------------
// Load input file (JSON or YAML)
// --------------------------------------------------------------------------

static cJSON *load_input_file(const char *path) {
    // Check extension
    const char *ext = strrchr(path, '.');
    bool is_yaml = ext && (strcmp(ext, ".yaml") == 0 || strcmp(ext, ".yml") == 0);

    if (is_yaml) {
        return load_yaml_file(path);
    }

    // Load as JSON
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(size + 1);
    size_t nread = fread(buf, 1, size, f);
    buf[nread] = '\0';
    fclose(f);

    cJSON *json = cJSON_Parse(buf);
    if (!json) {
        fprintf(stderr, "JSON parse error: %s\n", cJSON_GetErrorPtr());
    }
    free(buf);

    return json;
}

// --------------------------------------------------------------------------
// Schema name extraction
// --------------------------------------------------------------------------

char *get_schema_name(const char *schema_path) {
    cJSON *data = load_input_file(schema_path);
    if (!data) return NULL;

    // Try "name" first, then "cli"
    cJSON *name = cJSON_GetObjectItem(data, "name");
    if (!name || !cJSON_IsString(name)) {
        name = cJSON_GetObjectItem(data, "cli");
    }

    char *result = NULL;
    if (name && cJSON_IsString(name)) {
        result = strdup(name->valuestring);
    }

    cJSON_Delete(data);
    return result;
}

// --------------------------------------------------------------------------
// Main blob generation
// --------------------------------------------------------------------------

bool generate_blob(const char *schema_path, const char *output_path, bool big_endian, bool no_descriptions, bool long_descriptions) {
    cJSON *data = load_input_file(schema_path);
    if (!data) return false;

    BlobGen bg;
    blobgen_init(&bg, big_endian, no_descriptions, long_descriptions);

    cJSON *commands = cJSON_GetObjectItem(data, "commands");
    if (!commands || !cJSON_IsArray(commands)) {
        fprintf(stderr, "Schema must have 'commands' array\n");
        cJSON_Delete(data);
        blobgen_free(&bg);
        return false;
    }

    // Build command tree
    CommandNode *tree = build_command_tree(commands);
    sort_children(tree);

    // Collect all commands
    IdxCount top_level = collect_commands(&bg, tree);

    // Add root command params (version)
    cJSON *version_name_obj = cJSON_GetObjectItem(data, "version_param_name");
    cJSON *version_desc_obj = cJSON_GetObjectItem(data, "version_param_desc");
    cJSON *root_desc_obj = cJSON_GetObjectItem(data, "root_desc");

    const char *version_name = version_name_obj && cJSON_IsString(version_name_obj)
                               ? version_name_obj->valuestring : "version";
    const char *version_desc = version_desc_obj && cJSON_IsString(version_desc_obj)
                               ? version_desc_obj->valuestring : "Show version";
    const char *root_desc = root_desc_obj && cJSON_IsString(root_desc_obj)
                            ? root_desc_obj->valuestring : "CLI";

    uint32_t version_name_off = strtab_add(&bg.strtab, version_name);
    // Add version/root descriptions but don't count them for has_any_descriptions
    // (these are defaults, not from the schema)
    uint32_t version_desc_off = strtab_add_desc_ex(&bg, version_desc, false);
    uint32_t root_desc_off = strtab_add_desc_ex(&bg, root_desc, false);

    uint32_t root_params_idx = (uint32_t)bg.params_count;
    uint16_t root_params_count = 1;  // Just the version param

    // Ensure capacity
    if (bg.params_count + 1 > bg.params_cap) {
        bg.params_cap *= 2;
        bg.params = realloc(bg.params, bg.params_cap * sizeof(ParamEntry));
    }

    ParamEntry *ver_param = &bg.params[bg.params_count++];
    ver_param->name_off = version_name_off;
    ver_param->short_off = 0;
    ver_param->desc_off = version_desc_off;
    ver_param->choices_idx = (uint32_t)-1;
    ver_param->flags = 0;

    // Build global params
    cJSON *global_params = cJSON_GetObjectItem(data, "global_params");
    if (global_params && cJSON_IsArray(global_params)) {
        int gp_count = cJSON_GetArraySize(global_params);
        for (int i = 0; i < gp_count; i++) {
            cJSON *gp = cJSON_GetArrayItem(global_params, i);
            cJSON *gp_name = cJSON_GetObjectItem(gp, "name");
            cJSON *gp_desc = cJSON_GetObjectItem(gp, "description");
            cJSON *gp_tv = cJSON_GetObjectItem(gp, "takes_value");
            cJSON *gp_choices = cJSON_GetObjectItem(gp, "choices");

            if (!gp_name || !cJSON_IsString(gp_name)) continue;

            const char *name = gp_name->valuestring;
            const char *desc = (gp_desc && cJSON_IsString(gp_desc)) ? gp_desc->valuestring : "";
            bool takes_value = gp_tv && cJSON_IsTrue(gp_tv);

            // Extract short option if present
            char *long_opt = NULL;
            char *short_opt = NULL;

            if (strchr(name, ' ')) {
                char *copy = strdup(name);
                char *token = strtok(copy, " ");
                while (token) {
                    if (strncmp(token, "--", 2) == 0) {
                        free(long_opt);
                        long_opt = strdup(token);
                    } else if (token[0] == '-' && strlen(token) == 2) {
                        free(short_opt);
                        short_opt = strdup(token);
                    }
                    token = strtok(NULL, " ");
                }
                free(copy);
            } else {
                long_opt = strdup(name);
            }

            if (bg.global_params_count >= bg.global_params_cap) {
                bg.global_params_cap *= 2;
                bg.global_params = realloc(bg.global_params, bg.global_params_cap * sizeof(ParamEntry));
            }

            ParamEntry *pe = &bg.global_params[bg.global_params_count++];
            pe->name_off = strtab_add(&bg.strtab, long_opt ? long_opt : name);
            pe->short_off = short_opt ? strtab_add(&bg.strtab, short_opt) : 0;
            pe->desc_off = strtab_add_desc(&bg, desc);
            pe->flags = takes_value ? FLAG_TAKES_VALUE : 0;
            pe->choices_idx = (uint32_t)-1;

            if (gp_choices && cJSON_IsArray(gp_choices)) {
                pe->choices_idx = (uint32_t)get_choices_index(&bg, gp_choices);
            }

            bg.global_param_count++;
            bg.global_param_bytes += strlen(long_opt ? long_opt : name) + (bg.no_descriptions ? 0 : strlen(desc));

            free(long_opt);
            free(short_opt);
        }
    }

    // Calculate buffer size
    size_t msgpack_buffer_size = calc_msgpack_buffer_size(&bg);

    // Calculate section sizes
    size_t commands_size = bg.commands_count * COMMAND_SIZE;
    size_t params_size = bg.params_count * PARAM_SIZE;
    size_t global_params_size = bg.global_params_count * PARAM_SIZE;

    size_t choices_size = 0;
    for (size_t i = 0; i < bg.choices_count; i++) {
        choices_size += (bg.choices_lists[i].count + 1) * 4;
    }

    size_t members_size = 0;
    for (size_t i = 0; i < bg.members_count; i++) {
        members_size += (bg.members_lists[i].count + 1) * 4;
    }

    // Calculate offsets
    uint32_t string_table_off = HEADER_SIZE;
    uint32_t commands_off = string_table_off + (uint32_t)bg.strtab.data_len;
    uint32_t params_off = commands_off + (uint32_t)commands_size;
    uint32_t choices_off = params_off + (uint32_t)params_size;
    uint32_t members_off = choices_off + (uint32_t)choices_size;
    uint32_t global_params_off = members_off + (uint32_t)members_size;
    uint32_t root_command_off = global_params_off + (uint32_t)global_params_size;

    size_t total_size = root_command_off + COMMAND_SIZE;

    // Build choices/members offset maps
    uint32_t *choices_offsets = malloc(bg.choices_count * sizeof(uint32_t));
    uint32_t offset = choices_off;
    for (size_t i = 0; i < bg.choices_count; i++) {
        choices_offsets[i] = offset;
        offset += (uint32_t)(bg.choices_lists[i].count + 1) * 4;
    }

    uint32_t *members_offsets = malloc(bg.members_count * sizeof(uint32_t));
    offset = members_off;
    for (size_t i = 0; i < bg.members_count; i++) {
        members_offsets[i] = offset;
        offset += (uint32_t)(bg.members_lists[i].count + 1) * 4;
    }

    // Allocate blob
    uint8_t *blob = calloc(1, total_size);

    // Write header
    memcpy(blob, BLOB_MAGIC, 4);
    write_u16(blob + 4, BLOB_VERSION, big_endian);
    uint16_t flags = 0;
    if (big_endian) flags |= HEADER_FLAG_BIG_ENDIAN;
    if (no_descriptions || !bg.has_any_descriptions) flags |= HEADER_FLAG_NO_DESCRIPTIONS;
    write_u16(blob + 6, flags, big_endian);
    write_u32(blob + 8, (uint32_t)bg.max_command_path_len + 1, big_endian);
    write_u32(blob + 12, (uint32_t)msgpack_buffer_size, big_endian);
    write_u32(blob + 16, (uint32_t)bg.commands_count, big_endian);
    write_u32(blob + 20, (uint32_t)bg.params_count, big_endian);
    write_u32(blob + 24, (uint32_t)bg.global_params_count, big_endian);
    write_u32(blob + 28, (uint32_t)bg.strtab.data_len, big_endian);
    write_u32(blob + 32, (uint32_t)bg.choices_count, big_endian);
    write_u32(blob + 36, (uint32_t)bg.members_count, big_endian);
    write_u32(blob + 40, string_table_off, big_endian);
    write_u32(blob + 44, commands_off, big_endian);
    write_u32(blob + 48, params_off, big_endian);
    write_u32(blob + 52, choices_off, big_endian);
    write_u32(blob + 56, members_off, big_endian);
    write_u32(blob + 60, global_params_off, big_endian);
    write_u32(blob + 64, root_command_off, big_endian);

    // Write string table
    memcpy(blob + string_table_off, bg.strtab.data, bg.strtab.data_len);

    // Write commands
    offset = commands_off;
    for (size_t i = 0; i < bg.commands_count; i++) {
        CommandEntry *ce = &bg.commands[i];
        write_u32(blob + offset, ce->name_off, big_endian);
        write_u32(blob + offset + 4, ce->desc_off, big_endian);
        write_u32(blob + offset + 8, ce->params_idx, big_endian);
        write_u32(blob + offset + 12, ce->subcommands_idx, big_endian);
        write_u16(blob + offset + 16, ce->params_count, big_endian);
        write_u16(blob + offset + 18, ce->subcommands_count, big_endian);
        offset += COMMAND_SIZE;
    }

    // Write params
    offset = params_off;
    for (size_t i = 0; i < bg.params_count; i++) {
        ParamEntry *pe = &bg.params[i];
        uint32_t choices_off_val = 0;
        if (pe->choices_idx != (uint32_t)-1) {
            if (pe->flags & FLAG_IS_MEMBERS) {
                choices_off_val = members_offsets[pe->choices_idx];
            } else {
                choices_off_val = choices_offsets[pe->choices_idx];
            }
        }
        write_u32(blob + offset, pe->name_off, big_endian);
        write_u32(blob + offset + 4, pe->short_off, big_endian);
        write_u32(blob + offset + 8, pe->desc_off, big_endian);
        write_u32(blob + offset + 12, choices_off_val, big_endian);
        blob[offset + 16] = pe->flags;
        offset += PARAM_SIZE;
    }

    // Write choices
    offset = choices_off;
    for (size_t i = 0; i < bg.choices_count; i++) {
        StringList *sl = &bg.choices_lists[i];
        for (size_t j = 0; j < sl->count; j++) {
            write_u32(blob + offset, sl->offsets[j], big_endian);
            offset += 4;
        }
        write_u32(blob + offset, 0, big_endian);  // Null terminator
        offset += 4;
    }

    // Write members
    offset = members_off;
    for (size_t i = 0; i < bg.members_count; i++) {
        StringList *sl = &bg.members_lists[i];
        for (size_t j = 0; j < sl->count; j++) {
            write_u32(blob + offset, sl->offsets[j], big_endian);
            offset += 4;
        }
        write_u32(blob + offset, 0, big_endian);  // Null terminator
        offset += 4;
    }

    // Write global params
    offset = global_params_off;
    for (size_t i = 0; i < bg.global_params_count; i++) {
        ParamEntry *pe = &bg.global_params[i];
        uint32_t choices_off_val = 0;
        if (pe->choices_idx != (uint32_t)-1) {
            choices_off_val = choices_offsets[pe->choices_idx];
        }
        write_u32(blob + offset, pe->name_off, big_endian);
        write_u32(blob + offset + 4, pe->short_off, big_endian);
        write_u32(blob + offset + 8, pe->desc_off, big_endian);
        write_u32(blob + offset + 12, choices_off_val, big_endian);
        blob[offset + 16] = pe->flags;
        offset += PARAM_SIZE;
    }

    // Write root command
    write_u32(blob + root_command_off, 0, big_endian);  // name_off (root has no name)
    write_u32(blob + root_command_off + 4, root_desc_off, big_endian);
    write_u32(blob + root_command_off + 8, root_params_idx, big_endian);
    write_u32(blob + root_command_off + 12, top_level.idx, big_endian);
    write_u16(blob + root_command_off + 16, root_params_count, big_endian);
    write_u16(blob + root_command_off + 18, top_level.count, big_endian);

    // Write to file
    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror(output_path);
        free(blob);
        free(choices_offsets);
        free(members_offsets);
        node_free(tree);
        cJSON_Delete(data);
        blobgen_free(&bg);
        return false;
    }

    fwrite(blob, 1, total_size, out);
    fclose(out);

    // Print stats
    fprintf(stderr, "Generated %s (%zu bytes)\n", output_path, total_size);
    fprintf(stderr, "  Commands: %zu\n", bg.commands_count);
    fprintf(stderr, "  Params: %zu\n", bg.params_count);
    fprintf(stderr, "  Global params: %zu\n", bg.global_params_count);
    fprintf(stderr, "  Choices lists: %zu\n", bg.choices_count);
    fprintf(stderr, "  Members lists: %zu\n", bg.members_count);
    fprintf(stderr, "  String table: %zu bytes\n", bg.strtab.data_len);

    // Cleanup
    free(blob);
    free(choices_offsets);
    free(members_offsets);
    node_free(tree);
    cJSON_Delete(data);
    blobgen_free(&bg);

    return true;
}
