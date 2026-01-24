/*
 * generate_blob.c - Blob generation from JSON schema files
 *
 * Generates binary completion data blob from JSON command schema.
 * Uses jsmn for minimal JSON parsing.
 */

#include "generate_blob.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define JSMN_PARENT_LINKS
#define JSMN_STATIC
#include "vendor/jsmn/jsmn.h"

// Limits
#define VLQ_MAX_LENGTH 32767
#define SHORT_DESC_MAX_LEN 200

// --------------------------------------------------------------------------
// JSMN helpers
// --------------------------------------------------------------------------

typedef struct {
    const char *js;      // JSON string
    jsmntok_t *tokens;   // Token array
    int num_tokens;      // Number of tokens
} JsonDoc;

// Compare token string with a C string
static bool tok_eq(const char *js, jsmntok_t *tok, const char *s) {
    if (tok->type != JSMN_STRING) return false;
    size_t len = tok->end - tok->start;
    return strlen(s) == len && strncmp(js + tok->start, s, len) == 0;
}

// Get string value from token (caller must free)
static char *tok_strdup(const char *js, jsmntok_t *tok) {
    if (tok->type != JSMN_STRING && tok->type != JSMN_PRIMITIVE) {
        return strdup("");
    }
    size_t len = tok->end - tok->start;
    char *s = malloc(len + 1);
    memcpy(s, js + tok->start, len);
    s[len] = '\0';
    return s;
}

// Check if token is true
static bool tok_is_true(const char *js, jsmntok_t *tok) {
    if (tok->type != JSMN_PRIMITIVE) return false;
    return tok->end - tok->start == 4 && strncmp(js + tok->start, "true", 4) == 0;
}

// Check if token is a boolean
static bool tok_is_bool(const char *js, jsmntok_t *tok) {
    if (tok->type != JSMN_PRIMITIVE) return false;
    size_t len = tok->end - tok->start;
    if (len == 4 && strncmp(js + tok->start, "true", 4) == 0) return true;
    if (len == 5 && strncmp(js + tok->start, "false", 5) == 0) return true;
    return false;
}

// Skip a token and all its children, return index of next sibling
static int tok_skip(jsmntok_t *tokens, int idx) {
    int end = idx + 1;
    for (int i = 0; i < tokens[idx].size; i++) {
        if (tokens[idx].type == JSMN_OBJECT) {
            end++;  // skip key
        }
        end = tok_skip(tokens, end);
    }
    return end;
}

// Find key in object, return token index of value or -1
static int obj_get(const char *js, jsmntok_t *tokens, int obj_idx, const char *key) {
    if (tokens[obj_idx].type != JSMN_OBJECT) return -1;
    int idx = obj_idx + 1;
    for (int i = 0; i < tokens[obj_idx].size; i++) {
        if (tok_eq(js, &tokens[idx], key)) {
            return idx + 1;  // Return value token
        }
        idx++;  // Skip key
        idx = tok_skip(tokens, idx);  // Skip value
    }
    return -1;
}

// Get string property from object (caller must free), returns empty string if not found
static char *obj_get_str(const char *js, jsmntok_t *tokens, int obj_idx, const char *key) {
    int idx = obj_get(js, tokens, obj_idx, key);
    if (idx < 0) return strdup("");
    return tok_strdup(js, &tokens[idx]);
}

// Get array size
static int arr_size(jsmntok_t *tokens, int arr_idx) {
    if (tokens[arr_idx].type != JSMN_ARRAY) return 0;
    return tokens[arr_idx].size;
}

// Get first item in array (use with tok_skip for iteration)
static inline int arr_first(jsmntok_t *tokens, int arr_idx) {
    if (tokens[arr_idx].type != JSMN_ARRAY || tokens[arr_idx].size == 0) return -1;
    return arr_idx + 1;
}

// --------------------------------------------------------------------------
// Description truncation helpers
// --------------------------------------------------------------------------

static bool in_url(const char *s, size_t pos) {
    if (pos < 3) return false;
    for (size_t i = pos; i >= 3; i--) {
        if (s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == '\n') return false;
        if (s[i-1] == '/' && s[i-2] == '/' && s[i-3] == ':') return true;
        if (i == 3) break;
    }
    return false;
}

static bool is_abbreviation(const char *s, size_t pos) {
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
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) match = false;
            }
            if (match && (pos == len || s[pos - len - 1] == ' ' || s[pos - len - 1] == '(')) {
                return true;
            }
        }
    }
    return false;
}

static bool is_version_number(const char *s, size_t pos, size_t len) {
    if (pos == 0 || pos + 1 >= len) return false;
    return (s[pos - 1] >= '0' && s[pos - 1] <= '9') &&
           (s[pos + 1] >= '0' && s[pos + 1] <= '9');
}

static char *truncate_to_first_sentence(const char *desc) {
    if (!desc || !*desc) return strdup("");
    size_t len = strlen(desc);
    size_t end = len;
    for (size_t i = 0; i < len && i < SHORT_DESC_MAX_LEN; i++) {
        char c = desc[i];
        char next = (i + 1 < len) ? desc[i + 1] : '\0';
        if (c == '\n') { end = i; break; }
        if ((c == '.' || c == ';' || c == ':') &&
            (next == ' ' || next == '\n' || next == '\0' || next == '\t')) {
            if (c == '.') {
                if (in_url(desc, i)) continue;
                if (is_abbreviation(desc, i)) continue;
                if (is_version_number(desc, i, len)) continue;
            }
            end = i;
            break;
        }
    }
    if (end == len && len > SHORT_DESC_MAX_LEN) {
        end = SHORT_DESC_MAX_LEN;
        while (end > SHORT_DESC_MAX_LEN - 30 && desc[end] != ' ') end--;
        if (desc[end] == ' ') {
            char *result = malloc(end + 4);
            if (!result) return strdup("");
            memcpy(result, desc, end);
            memcpy(result + end, "...", 4);
            return result;
        }
        end = SHORT_DESC_MAX_LEN;
    }
    char *result = malloc(end + 1);
    if (!result) return strdup("");
    memcpy(result, desc, end);
    result[end] = '\0';
    return result;
}

// --------------------------------------------------------------------------
// String Table
// --------------------------------------------------------------------------

typedef struct {
    uint32_t hash;
    uint32_t idx;
} HashEntry;

typedef struct {
    char **strings;
    uint32_t *offsets;
    size_t count;
    size_t capacity;
    uint8_t *data;
    size_t data_len;
    size_t data_cap;
    size_t max_str_len;
    HashEntry *hash_table;
    size_t hash_cap;
} StringTable;

static uint32_t hash_string(const char *s) {
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) ^ (uint8_t)*s++;
    return h ? h : 1;
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
    st->hash_cap = 65536;  // Start large to reduce resizing for big schemas
    st->hash_table = calloc(st->hash_cap, sizeof(HashEntry));
    st->strings[0] = strdup("");
    st->offsets[0] = 0;
    st->data[0] = 0;
    st->data_len = 1;
    st->count = 1;
    uint32_t h = hash_string("");
    size_t idx = h & (st->hash_cap - 1);
    st->hash_table[idx].hash = h;
    st->hash_table[idx].idx = 0;
}

static void strtab_free(StringTable *st) {
    for (size_t i = 0; i < st->count; i++) free(st->strings[i]);
    free(st->strings);
    free(st->offsets);
    free(st->data);
    free(st->hash_table);
}

static void strtab_grow_hash(StringTable *st) {
    size_t old_cap = st->hash_cap;
    HashEntry *old_table = st->hash_table;
    st->hash_cap *= 2;
    st->hash_table = calloc(st->hash_cap, sizeof(HashEntry));
    for (size_t i = 0; i < old_cap; i++) {
        if (old_table[i].hash) {
            size_t idx = old_table[i].hash & (st->hash_cap - 1);
            while (st->hash_table[idx].hash) idx = (idx + 1) & (st->hash_cap - 1);
            st->hash_table[idx] = old_table[i];
        }
    }
    free(old_table);
}

static uint32_t strtab_add(StringTable *st, const char *s) {
    if (!s) s = "";
    uint32_t h = hash_string(s);
    size_t idx = h & (st->hash_cap - 1);
    while (st->hash_table[idx].hash) {
        if (st->hash_table[idx].hash == h) {
            uint32_t str_idx = st->hash_table[idx].idx;
            if (strcmp(st->strings[str_idx], s) == 0) return st->offsets[str_idx];
        }
        idx = (idx + 1) & (st->hash_cap - 1);
    }
    if (st->count >= st->capacity) {
        st->capacity *= 2;
        st->strings = realloc(st->strings, st->capacity * sizeof(char *));
        st->offsets = realloc(st->offsets, st->capacity * sizeof(uint32_t));
    }
    if (st->count * 2 >= st->hash_cap) {
        strtab_grow_hash(st);
        idx = h & (st->hash_cap - 1);
        while (st->hash_table[idx].hash) idx = (idx + 1) & (st->hash_cap - 1);
    }
    size_t len = strlen(s);
    if (len > st->max_str_len) st->max_str_len = len;
    size_t vlq_len = (len < 128) ? 1 : 2;
    size_t total = vlq_len + len;
    while (st->data_len + total > st->data_cap) {
        st->data_cap *= 2;
        st->data = realloc(st->data, st->data_cap);
    }
    uint32_t offset = (uint32_t)st->data_len;
    if (len < 128) {
        st->data[st->data_len++] = (uint8_t)len;
    } else if (len <= VLQ_MAX_LENGTH) {
        st->data[st->data_len++] = 0x80 | (uint8_t)(len >> 8);
        st->data[st->data_len++] = (uint8_t)(len & 0xff);
    } else {
        fprintf(stderr, "String too long: %zu bytes\n", len);
        return 0;
    }
    memcpy(st->data + st->data_len, s, len);
    st->data_len += len;
    uint32_t str_idx = (uint32_t)st->count;
    st->strings[st->count] = strdup(s);
    st->offsets[st->count] = offset;
    st->count++;
    st->hash_table[idx].hash = h;
    st->hash_table[idx].idx = str_idx;
    return offset;
}

// Add string without deduplication (for subtree clustering of command names)
static uint32_t strtab_add_nodupe(StringTable *st, const char *s) {
    if (!s) s = "";
    if (st->count >= st->capacity) {
        st->capacity *= 2;
        st->strings = realloc(st->strings, st->capacity * sizeof(char *));
        st->offsets = realloc(st->offsets, st->capacity * sizeof(uint32_t));
    }
    size_t len = strlen(s);
    if (len > st->max_str_len) st->max_str_len = len;
    size_t vlq_len = (len < 128) ? 1 : 2;
    size_t total = vlq_len + len;
    while (st->data_len + total > st->data_cap) {
        st->data_cap *= 2;
        st->data = realloc(st->data, st->data_cap);
    }
    uint32_t offset = (uint32_t)st->data_len;
    if (len < 128) {
        st->data[st->data_len++] = (uint8_t)len;
    } else if (len <= VLQ_MAX_LENGTH) {
        st->data[st->data_len++] = 0x80 | (uint8_t)(len >> 8);
        st->data[st->data_len++] = (uint8_t)(len & 0xff);
    } else {
        fprintf(stderr, "String too long: %zu bytes\n", len);
        return 0;
    }
    memcpy(st->data + st->data_len, s, len);
    st->data_len += len;
    st->strings[st->count] = strdup(s);
    st->offsets[st->count] = offset;
    st->count++;
    return offset;
}

// --------------------------------------------------------------------------
// Structures
// --------------------------------------------------------------------------

typedef struct {
    uint32_t name_off;
    uint32_t short_off;
    uint32_t desc_off;
    uint32_t choices_idx;
    uint8_t flags;
} ParamEntry;

typedef struct {
    uint32_t name_off;
    uint32_t desc_off;
    uint32_t params_idx;
    uint16_t subcommands_idx;
    uint16_t params_count;
    uint16_t subcommands_count;
} CommandEntry;

typedef struct {
    uint32_t *offsets;
    size_t count;
    uint32_t hash;       // For deduplication
    uint32_t blob_off;   // Offset in blob once written (0 = not yet written)
} StringList;

typedef struct {
    StringTable strtab;       // Hot strings (names, choices, etc.)
    StringTable desc_strtab;  // Cold strings (descriptions) - written after hot for locality
    ParamEntry *params;
    size_t params_count;
    size_t params_cap;
    CommandEntry *commands;
    size_t commands_count;
    size_t commands_cap;
    StringList *choices_lists;
    size_t choices_count;
    size_t choices_cap;
    StringList *members_lists;
    size_t members_count;
    size_t members_cap;
    ParamEntry *global_params;
    size_t global_params_count;
    size_t global_params_cap;
    size_t max_command_path_len;
    bool big_endian;
    bool no_descriptions;
    bool long_descriptions;
    bool has_any_descriptions;
} BlobGen;

static void blobgen_init(BlobGen *bg, bool big_endian, bool no_descriptions, bool long_descriptions) {
    memset(bg, 0, sizeof(*bg));
    strtab_init(&bg->strtab);
    strtab_init(&bg->desc_strtab);  // Separate table for descriptions (cold data)
    bg->params_cap = 1024;
    bg->params = calloc(bg->params_cap, sizeof(ParamEntry));
    bg->commands_cap = 1024;
    bg->commands = calloc(bg->commands_cap, sizeof(CommandEntry));
    bg->choices_cap = 256;
    bg->choices_lists = calloc(bg->choices_cap, sizeof(StringList));
    bg->members_cap = 256;
    bg->members_lists = calloc(bg->members_cap, sizeof(StringList));
    bg->global_params_cap = 64;
    bg->global_params = calloc(bg->global_params_cap, sizeof(ParamEntry));
    bg->big_endian = big_endian;
    bg->no_descriptions = no_descriptions;
    bg->long_descriptions = long_descriptions;
}

static uint32_t strtab_add_desc_ex(BlobGen *bg, const char *desc, bool track) {
    if (bg->no_descriptions || !desc || !*desc) return 0;
    char *processed = NULL;
    if (!bg->long_descriptions) {
        processed = truncate_to_first_sentence(desc);
        desc = processed;
    }
    uint32_t offset = 0;
    if (desc && *desc) {
        // Add to cold (description) string table - offset will be adjusted at write time
        offset = strtab_add(&bg->desc_strtab, desc);
        if (track) bg->has_any_descriptions = true;
    }
    free(processed);
    return offset;
}

static uint32_t strtab_add_desc(BlobGen *bg, const char *desc) {
    return strtab_add_desc_ex(bg, desc, true);
}

static void blobgen_free(BlobGen *bg) {
    strtab_free(&bg->strtab);
    strtab_free(&bg->desc_strtab);
    free(bg->params);
    free(bg->commands);
    for (size_t i = 0; i < bg->choices_count; i++) free(bg->choices_lists[i].offsets);
    free(bg->choices_lists);
    for (size_t i = 0; i < bg->members_count; i++) free(bg->members_lists[i].offsets);
    free(bg->members_lists);
    free(bg->global_params);
}

// --------------------------------------------------------------------------
// Tracking
// --------------------------------------------------------------------------

static void track_command_path_len(BlobGen *bg, size_t path_len) {
    if (path_len > bg->max_command_path_len) bg->max_command_path_len = path_len;
}

// --------------------------------------------------------------------------
// Choices/Members
// --------------------------------------------------------------------------

// Hash a string list for deduplication
static uint32_t hash_string_list(const uint32_t *offsets, size_t count) {
    uint32_t h = 5381;
    for (size_t i = 0; i < count; i++) {
        h = ((h << 5) + h) ^ offsets[i];
    }
    return h ? h : 1;
}

// Find existing choice list with same contents
static size_t find_existing_choices(BlobGen *bg, const uint32_t *offsets, size_t count, uint32_t hash) {
    for (size_t i = 0; i < bg->choices_count; i++) {
        StringList *sl = &bg->choices_lists[i];
        if (sl->hash == hash && sl->count == count) {
            if (memcmp(sl->offsets, offsets, count * sizeof(uint32_t)) == 0) {
                return i;
            }
        }
    }
    return (size_t)-1;
}

// Find existing member list with same contents
static size_t find_existing_members(BlobGen *bg, const uint32_t *offsets, size_t count, uint32_t hash) {
    for (size_t i = 0; i < bg->members_count; i++) {
        StringList *sl = &bg->members_lists[i];
        if (sl->hash == hash && sl->count == count) {
            if (memcmp(sl->offsets, offsets, count * sizeof(uint32_t)) == 0) {
                return i;
            }
        }
    }
    return (size_t)-1;
}

static size_t get_choices_index(BlobGen *bg, const char *js, jsmntok_t *tokens, int arr_idx) {
    if (tokens[arr_idx].type != JSMN_ARRAY) return (size_t)-1;
    int count = arr_size(tokens, arr_idx);
    if (count == 0) return (size_t)-1;

    // Build temporary offset array
    uint32_t *offsets = malloc(count * sizeof(uint32_t));
    int item_idx = arr_first(tokens, arr_idx);
    for (int i = 0; i < count; i++) {
        char *s = tok_strdup(js, &tokens[item_idx]);
        offsets[i] = strtab_add(&bg->strtab, s);
        free(s);
        item_idx = tok_skip(tokens, item_idx);
    }

    // Check for existing identical list
    uint32_t hash = hash_string_list(offsets, count);
    size_t existing = find_existing_choices(bg, offsets, count, hash);
    if (existing != (size_t)-1) {
        free(offsets);
        return existing;
    }

    // Add new list
    if (bg->choices_count >= bg->choices_cap) {
        bg->choices_cap *= 2;
        bg->choices_lists = realloc(bg->choices_lists, bg->choices_cap * sizeof(StringList));
    }
    StringList *sl = &bg->choices_lists[bg->choices_count];
    sl->offsets = offsets;
    sl->count = count;
    sl->hash = hash;
    sl->blob_off = 0;
    return bg->choices_count++;
}

static size_t get_members_index(BlobGen *bg, const char *js, jsmntok_t *tokens, int arr_idx) {
    if (tokens[arr_idx].type != JSMN_ARRAY) return (size_t)-1;
    int count = arr_size(tokens, arr_idx);
    if (count == 0) return (size_t)-1;

    // Build temporary offset array
    uint32_t *offsets = malloc(count * sizeof(uint32_t));
    int item_idx = arr_first(tokens, arr_idx);
    for (int i = 0; i < count; i++) {
        int key_idx = obj_get(js, tokens, item_idx, "key");
        if (key_idx >= 0) {
            char *key = tok_strdup(js, &tokens[key_idx]);
            char buf[1024];
            snprintf(buf, sizeof(buf), "%s=", key);
            offsets[i] = strtab_add(&bg->strtab, buf);
            free(key);
        } else {
            offsets[i] = 0;
        }
        item_idx = tok_skip(tokens, item_idx);
    }

    // Check for existing identical list
    uint32_t hash = hash_string_list(offsets, count);
    size_t existing = find_existing_members(bg, offsets, count, hash);
    if (existing != (size_t)-1) {
        free(offsets);
        return existing;
    }

    // Add new list
    if (bg->members_count >= bg->members_cap) {
        bg->members_cap *= 2;
        bg->members_lists = realloc(bg->members_lists, bg->members_cap * sizeof(StringList));
    }
    StringList *sl = &bg->members_lists[bg->members_count];
    sl->offsets = offsets;
    sl->count = count;
    sl->hash = hash;
    sl->blob_off = 0;
    return bg->members_count++;
}

// --------------------------------------------------------------------------
// Parameter extraction
// --------------------------------------------------------------------------

typedef struct {
    char *name;
    char *short_opt;
    char *description;
    char *completer;
    bool takes_value;
    int choices_idx;
    int members_idx;
} ParamInfo;

static bool get_param_info(const char *js, jsmntok_t *tokens, int param_idx, ParamInfo *info) {
    memset(info, 0, sizeof(*info));
    info->choices_idx = -1;
    info->members_idx = -1;

    int options_idx = obj_get(js, tokens, param_idx, "options");
    if (options_idx >= 0 && tokens[options_idx].type == JSMN_ARRAY && arr_size(tokens, options_idx) > 0) {
        int opt_count = arr_size(tokens, options_idx);
        int opt_idx = arr_first(tokens, options_idx);
        for (int i = 0; i < opt_count; i++) {
            char *opt = tok_strdup(js, &tokens[opt_idx]);
            if (strncmp(opt, "--", 2) == 0) {
                if (!info->name || strlen(opt) > strlen(info->name)) {
                    free(info->name);
                    info->name = opt;
                    opt = NULL;
                }
            } else if (opt[0] == '-' && strlen(opt) == 2) {
                free(info->short_opt);
                info->short_opt = opt;
                opt = NULL;
            }
            free(opt);
            opt_idx = tok_skip(tokens, opt_idx);
        }
    } else {
        char *name_str = obj_get_str(js, tokens, param_idx, "name");
        if (!name_str[0]) { free(name_str); return false; }
        if (strchr(name_str, ' ')) {
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
        }
        free(name_str);
    }

    if (!info->name) return false;

    // Check for bool choices
    int choices_idx = obj_get(js, tokens, param_idx, "choices");
    bool is_bool_choices = false;
    if (choices_idx >= 0 && tokens[choices_idx].type == JSMN_ARRAY && arr_size(tokens, choices_idx) == 2) {
        int c0 = arr_first(tokens, choices_idx);
        int c1 = tok_skip(tokens, c0);
        char *s0 = tok_strdup(js, &tokens[c0]);
        char *s1 = tok_strdup(js, &tokens[c1]);
        if ((strcasecmp(s0, "true") == 0 || strcasecmp(s0, "false") == 0) &&
            (strcasecmp(s1, "true") == 0 || strcasecmp(s1, "false") == 0)) {
            is_bool_choices = true;
        }
        free(s0);
        free(s1);
    }

    info->takes_value = true;
    if (is_bool_choices) {
        info->takes_value = false;
    } else {
        char *type = obj_get_str(js, tokens, param_idx, "type");
        if (strcmp(type, "bool") == 0 || strcmp(type, "boolean") == 0) {
            info->takes_value = false;
        }
        free(type);

        int def_idx = obj_get(js, tokens, param_idx, "default");
        if (def_idx >= 0 && tok_is_bool(js, &tokens[def_idx])) {
            info->takes_value = false;
        }
    }

    int tv_idx = obj_get(js, tokens, param_idx, "takes_value");
    if (tv_idx >= 0) {
        info->takes_value = tok_is_true(js, &tokens[tv_idx]);
    }

    // Get description
    char *summary = obj_get_str(js, tokens, param_idx, "summary");
    if (summary[0]) {
        info->description = summary;
    } else {
        free(summary);
        info->description = obj_get_str(js, tokens, param_idx, "description");
    }

    // Store choices/members indices
    if (choices_idx >= 0 && !is_bool_choices) {
        info->choices_idx = choices_idx;
    }
    int members_idx = obj_get(js, tokens, param_idx, "members");
    if (info->choices_idx < 0 && members_idx >= 0) {
        info->members_idx = members_idx;
    }

    // Extract completer (mutually exclusive with choices/members)
    if (info->choices_idx < 0 && info->members_idx < 0) {
        int completer_idx = obj_get(js, tokens, param_idx, "completer");
        if (completer_idx >= 0 && tokens[completer_idx].type == JSMN_STRING) {
            char *completer = tok_strdup(js, &tokens[completer_idx]);
            // Skip "dynamic" marker - not actionable without introspection
            if (strcmp(completer, "dynamic") != 0) {
                info->completer = completer;
            } else {
                free(completer);
            }
        }
    }

    return true;
}

static void free_param_info(ParamInfo *info) {
    free(info->name);
    free(info->short_opt);
    free(info->description);
    free(info->completer);
}

// --------------------------------------------------------------------------
// Command Tree Building
// --------------------------------------------------------------------------

typedef struct CommandNode {
    char *name;
    int cmd_idx;  // Index in tokens array, or -1
    struct CommandNode **children;
    size_t children_count;
    size_t children_cap;
} CommandNode;

static CommandNode *node_create(const char *name) {
    CommandNode *node = calloc(1, sizeof(CommandNode));
    node->name = strdup(name ? name : "");
    node->cmd_idx = -1;
    node->children_cap = 8;
    node->children = calloc(node->children_cap, sizeof(CommandNode *));
    return node;
}

static void node_free(CommandNode *node) {
    if (!node) return;
    free(node->name);
    for (size_t i = 0; i < node->children_count; i++) node_free(node->children[i]);
    free(node->children);
    free(node);
}

static CommandNode *node_get_child(CommandNode *node, const char *name) {
    for (size_t i = 0; i < node->children_count; i++) {
        if (strcmp(node->children[i]->name, name) == 0) return node->children[i];
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

static CommandNode *build_command_tree(const char *js, jsmntok_t *tokens, int commands_idx) {
    CommandNode *root = node_create("");
    int cmd_count = arr_size(tokens, commands_idx);
    int cmd_idx = arr_first(tokens, commands_idx);
    for (int i = 0; i < cmd_count; i++) {
        char *name = obj_get_str(js, tokens, cmd_idx, "name");
        if (!name[0]) { free(name); cmd_idx = tok_skip(tokens, cmd_idx); continue; }
        char *copy = strdup(name);
        char *token = strtok(copy, " ");
        CommandNode *node = root;
        while (token) {
            CommandNode *child = node_get_child(node, token);
            if (!child) child = node_add_child(node, token);
            node = child;
            token = strtok(NULL, " ");
        }
        node->cmd_idx = cmd_idx;
        free(copy);
        free(name);
        cmd_idx = tok_skip(tokens, cmd_idx);
    }
    return root;
}

static int cmp_nodes(const void *a, const void *b) {
    const CommandNode *na = *(const CommandNode **)a;
    const CommandNode *nb = *(const CommandNode **)b;
    return strcmp(na->name, nb->name);
}

static void sort_children(CommandNode *node) {
    if (node->children_count > 1) {
        qsort(node->children, node->children_count, sizeof(CommandNode *), cmp_nodes);
    }
    for (size_t i = 0; i < node->children_count; i++) sort_children(node->children[i]);
}

// --------------------------------------------------------------------------
// Param sorting (for binary search in completer)
// --------------------------------------------------------------------------

static StringTable *sort_strtab = NULL;

static const char *strtab_get_by_offset(StringTable *st, uint32_t off) {
    if (off == 0) return "";
    for (size_t i = 0; i < st->count; i++) {
        if (st->offsets[i] == off) return st->strings[i];
    }
    return "";
}

static int cmp_params(const void *a, const void *b) {
    const ParamEntry *pa = a, *pb = b;
    const char *na = strtab_get_by_offset(sort_strtab, pa->name_off);
    const char *nb = strtab_get_by_offset(sort_strtab, pb->name_off);
    return strcmp(na, nb);
}

// --------------------------------------------------------------------------
// Collect params and commands
// --------------------------------------------------------------------------

typedef struct { uint32_t idx; uint16_t count; } IdxCount;

static IdxCount collect_params(BlobGen *bg, const char *js, jsmntok_t *tokens, int params_idx) {
    IdxCount result = {0, 0};
    if (params_idx < 0 || tokens[params_idx].type != JSMN_ARRAY) return result;
    int count = arr_size(tokens, params_idx);
    if (count == 0) return result;
    uint32_t start_idx = (uint32_t)bg->params_count;
    uint32_t valid_count = 0;
    int p_idx = arr_first(tokens, params_idx);
    for (int i = 0; i < count; i++) {
        ParamInfo info;
        if (!get_param_info(js, tokens, p_idx, &info)) { p_idx = tok_skip(tokens, p_idx); continue; }
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
        if (info.choices_idx >= 0) {
            pe->choices_idx = (uint32_t)get_choices_index(bg, js, tokens, info.choices_idx);
        } else if (info.members_idx >= 0) {
            pe->choices_idx = (uint32_t)get_members_index(bg, js, tokens, info.members_idx);
            pe->flags |= FLAG_IS_MEMBERS;
        } else if (info.completer) {
            // Store completer string offset directly (reuses choices_idx field)
            pe->choices_idx = strtab_add(&bg->strtab, info.completer);
            pe->flags |= FLAG_IS_COMPLETER;
        }
        free_param_info(&info);
        valid_count++;
        p_idx = tok_skip(tokens, p_idx);
    }
    if (valid_count == 0) return result;
    if (valid_count > 65535) {
        fprintf(stderr, "Too many params in one command: %u (max 65535)\n", valid_count);
        return result;  // Return empty result to signal error
    }
    // Sort params by name for binary search in completer
    if (valid_count > 1) {
        sort_strtab = &bg->strtab;
        qsort(&bg->params[start_idx], valid_count, sizeof(ParamEntry), cmp_params);
    }
    result.idx = start_idx;
    result.count = (uint16_t)valid_count;
    return result;
}

static IdxCount collect_commands(BlobGen *bg, const char *js, jsmntok_t *tokens, CommandNode *node);

static IdxCount collect_commands(BlobGen *bg, const char *js, jsmntok_t *tokens, CommandNode *node) {
    IdxCount result = {0, 0};
    if (node->children_count == 0) return result;

    typedef struct {
        uint32_t name_off, desc_off, params_idx, subcommands_idx;
        uint16_t params_count, subcommands_count;
        const char *path;
        size_t desc_len;
    } ChildData;

    ChildData *child_data = malloc(node->children_count * sizeof(ChildData));

    for (size_t i = 0; i < node->children_count; i++) {
        CommandNode *child = node->children[i];

        // Add name BEFORE recursing (pre-order) for subtree clustering
        // This puts each subtree's names contiguous in the string table
        // Use nodupe to preserve clustering (deduplication would scatter names)
        child_data[i].name_off = strtab_add_nodupe(&bg->strtab, child->name);

        // Now recurse into children
        IdxCount sub_result = collect_commands(bg, js, tokens, child);
        child_data[i].subcommands_idx = sub_result.idx;
        child_data[i].subcommands_count = sub_result.count;

        int params_arr_idx = -1;
        const char *desc = "";
        char *desc_alloc = NULL;
        if (child->cmd_idx >= 0) {
            params_arr_idx = obj_get(js, tokens, child->cmd_idx, "parameters");
            char *summary = obj_get_str(js, tokens, child->cmd_idx, "summary");
            if (summary[0]) {
                desc_alloc = summary;
                desc = desc_alloc;
            } else {
                free(summary);
                desc_alloc = obj_get_str(js, tokens, child->cmd_idx, "description");
                desc = desc_alloc;
            }
        }

        IdxCount params_result = collect_params(bg, js, tokens, params_arr_idx);
        child_data[i].params_idx = params_result.idx;
        child_data[i].params_count = params_result.count;
        child_data[i].desc_off = strtab_add_desc(bg, desc);
        child_data[i].desc_len = bg->no_descriptions ? 0 : strlen(desc);

        if (child_data[i].subcommands_count == 0 && child->cmd_idx >= 0) {
            char *path = obj_get_str(js, tokens, child->cmd_idx, "name");
            child_data[i].path = path;
            track_command_path_len(bg, strlen(path));
        } else {
            child_data[i].path = NULL;
        }
        free(desc_alloc);
    }

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
        free((char *)child_data[i].path);
    }
    free(child_data);
    result.idx = start_idx;
    if (node->children_count > 65535) {
        fprintf(stderr, "Too many subcommands in one command: %zu (max 65535)\n", node->children_count);
        result.count = 65535;  // Will be caught by validation later
    } else {
        result.count = (uint16_t)node->children_count;
    }
    return result;
}

// --------------------------------------------------------------------------
// Byte order helpers
// --------------------------------------------------------------------------

static void write_u16(uint8_t *buf, uint16_t val, bool big_endian) {
    if (big_endian) { buf[0] = val >> 8; buf[1] = val; }
    else { buf[0] = val; buf[1] = val >> 8; }
}

static void write_u32(uint8_t *buf, uint32_t val, bool big_endian) {
    if (big_endian) { buf[0] = val >> 24; buf[1] = val >> 16; buf[2] = val >> 8; buf[3] = val; }
    else { buf[0] = val; buf[1] = val >> 8; buf[2] = val >> 16; buf[3] = val >> 24; }
}

// --------------------------------------------------------------------------
// Load JSON file
// --------------------------------------------------------------------------

static bool load_json_file(const char *path, char **out_js, jsmntok_t **out_tokens, int *out_count) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return false; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *js = malloc(size + 1);
    size_t nread = fread(js, 1, size, f);
    js[nread] = '\0';
    fclose(f);

    jsmn_parser parser;
    jsmn_init(&parser);
    int num_tokens = jsmn_parse(&parser, js, nread, NULL, 0);
    if (num_tokens < 0) {
        fprintf(stderr, "JSON parse error: %d\n", num_tokens);
        free(js);
        return false;
    }

    jsmntok_t *tokens = malloc(num_tokens * sizeof(jsmntok_t));
    jsmn_init(&parser);
    int r = jsmn_parse(&parser, js, nread, tokens, num_tokens);
    if (r < 0) {
        fprintf(stderr, "JSON parse error: %d\n", r);
        free(js);
        free(tokens);
        return false;
    }

    *out_js = js;
    *out_tokens = tokens;
    *out_count = num_tokens;
    return true;
}

// --------------------------------------------------------------------------
// Schema name extraction
// --------------------------------------------------------------------------

char *get_schema_name(const char *schema_path) {
    char *js = NULL;
    jsmntok_t *tokens = NULL;
    int num_tokens = 0;
    if (!load_json_file(schema_path, &js, &tokens, &num_tokens)) return NULL;

    char *result = NULL;
    int name_idx = obj_get(js, tokens, 0, "name");
    if (name_idx < 0) name_idx = obj_get(js, tokens, 0, "cli");
    if (name_idx >= 0) result = tok_strdup(js, &tokens[name_idx]);

    free(js);
    free(tokens);
    return result;
}

// --------------------------------------------------------------------------
// Main blob generation
// --------------------------------------------------------------------------

bool generate_blob(const char *schema_path, const char *output_path, bool big_endian, bool no_descriptions, bool long_descriptions) {
    char *js = NULL;
    jsmntok_t *tokens = NULL;
    int num_tokens = 0;
    if (!load_json_file(schema_path, &js, &tokens, &num_tokens)) return false;

    BlobGen bg;
    blobgen_init(&bg, big_endian, no_descriptions, long_descriptions);

    int commands_idx = obj_get(js, tokens, 0, "commands");
    if (commands_idx < 0 || tokens[commands_idx].type != JSMN_ARRAY) {
        fprintf(stderr, "Schema must have 'commands' array\n");
        return false;
    }

    CommandNode *tree = build_command_tree(js, tokens, commands_idx);
    sort_children(tree);
    IdxCount top_level = collect_commands(&bg, js, tokens, tree);

    // Root params
    char *version_name = obj_get_str(js, tokens, 0, "version_param_name");
    char *version_desc = obj_get_str(js, tokens, 0, "version_param_desc");
    char *root_desc = obj_get_str(js, tokens, 0, "root_desc");
    if (!version_name[0]) { free(version_name); version_name = strdup("version"); }
    if (!version_desc[0]) { free(version_desc); version_desc = strdup("Show version"); }
    if (!root_desc[0]) { free(root_desc); root_desc = strdup("CLI"); }

    uint32_t version_name_off = strtab_add(&bg.strtab, version_name);
    uint32_t version_desc_off = strtab_add_desc_ex(&bg, version_desc, false);
    uint32_t root_desc_off = strtab_add_desc_ex(&bg, root_desc, false);
    free(version_name); free(version_desc); free(root_desc);

    uint32_t root_params_idx = (uint32_t)bg.params_count;
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

    // Global params
    int global_params_idx = obj_get(js, tokens, 0, "global_params");
    if (global_params_idx >= 0 && tokens[global_params_idx].type == JSMN_ARRAY) {
        int gp_count = arr_size(tokens, global_params_idx);
        int gp_idx = arr_first(tokens, global_params_idx);
        for (int i = 0; i < gp_count; i++) {
            char *name = obj_get_str(js, tokens, gp_idx, "name");
            char *desc = obj_get_str(js, tokens, gp_idx, "description");
            int tv_idx = obj_get(js, tokens, gp_idx, "takes_value");
            bool takes_value = tv_idx >= 0 && tok_is_true(js, &tokens[tv_idx]);

            char *long_opt = NULL, *short_opt = NULL;
            if (strchr(name, ' ')) {
                char *copy = strdup(name);
                char *tok = strtok(copy, " ");
                while (tok) {
                    if (strncmp(tok, "--", 2) == 0) { free(long_opt); long_opt = strdup(tok); }
                    else if (tok[0] == '-' && strlen(tok) == 2) { free(short_opt); short_opt = strdup(tok); }
                    tok = strtok(NULL, " ");
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

            int choices_idx = obj_get(js, tokens, gp_idx, "choices");
            if (choices_idx >= 0 && tokens[choices_idx].type == JSMN_ARRAY) {
                pe->choices_idx = (uint32_t)get_choices_index(&bg, js, tokens, choices_idx);
            }

            free(long_opt); free(short_opt); free(name); free(desc);
            gp_idx = tok_skip(tokens, gp_idx);
        }
    }

    // Sort global params by name for binary search in completer
    if (bg.global_params_count > 1) {
        sort_strtab = &bg.strtab;
        qsort(bg.global_params, bg.global_params_count, sizeof(ParamEntry), cmp_params);
    }

    // Check for integer overflow in counts (process will exit on error, no need to free)
    if (bg.commands_count > 65535) {
        fprintf(stderr, "Too many commands: %zu (max 65535)\n", bg.commands_count);
        return false;
    }
    // params_idx is u32, so limit is much higher (params_count per command is still u16)
    if (bg.params_count > 16777215) {  // 2^24 - reasonable limit
        fprintf(stderr, "Too many params: %zu (max 16777215)\n", bg.params_count);
        return false;
    }
    if (bg.global_params_count > 65535) {
        fprintf(stderr, "Too many global params: %zu (max 65535)\n", bg.global_params_count);
        return false;
    }
    // Combined string table size (hot + cold for descriptions)
    size_t total_strtab_size = bg.strtab.data_len + bg.desc_strtab.data_len;
    if (total_strtab_size > UINT32_MAX) {
        fprintf(stderr, "String table too large: %zu bytes (max 4GB)\n", total_strtab_size);
        return false;
    }

    size_t commands_size = bg.commands_count * COMMAND_SIZE;
    size_t params_size = bg.params_count * PARAM_SIZE;
    size_t global_params_size = bg.global_params_count * PARAM_SIZE;
    // Variable-length count: u8 for <255, 0xFF + u16 for >=255
    size_t choices_size = 0;
    for (size_t i = 0; i < bg.choices_count; i++) {
        size_t count = bg.choices_lists[i].count;
        if (count > 65535) {
            fprintf(stderr, "Choice list %zu too large: %zu items (max 65535)\n", i, count);
            return false;
        }
        choices_size += (count < 255 ? 1 : 3) + count * 4;
    }
    size_t members_size = 0;
    for (size_t i = 0; i < bg.members_count; i++) {
        size_t count = bg.members_lists[i].count;
        if (count > 65535) {
            fprintf(stderr, "Member list %zu too large: %zu items (max 65535)\n", i, count);
            return false;
        }
        members_size += (count < 255 ? 1 : 3) + count * 4;
    }

    uint32_t string_table_off = HEADER_SIZE;
    uint32_t commands_off = string_table_off + (uint32_t)total_strtab_size;
    uint32_t params_off = commands_off + (uint32_t)commands_size;
    uint32_t choices_off = params_off + (uint32_t)params_size;
    uint32_t members_off = choices_off + (uint32_t)choices_size;
    uint32_t global_params_off = members_off + (uint32_t)members_size;
    uint32_t root_command_off = global_params_off + (uint32_t)global_params_size;
    size_t total_size = root_command_off + COMMAND_SIZE;

    // Calculate blob offsets for each choice/member list (variable-length count)
    uint32_t *choices_offsets = malloc(bg.choices_count * sizeof(uint32_t));
    uint32_t offset = choices_off;
    for (size_t i = 0; i < bg.choices_count; i++) {
        choices_offsets[i] = offset;
        size_t count = bg.choices_lists[i].count;
        offset += (count < 255 ? 1 : 3) + (uint32_t)count * 4;
    }
    uint32_t *members_offsets = malloc(bg.members_count * sizeof(uint32_t));
    offset = members_off;
    for (size_t i = 0; i < bg.members_count; i++) {
        members_offsets[i] = offset;
        size_t count = bg.members_lists[i].count;
        offset += (count < 255 ? 1 : 3) + (uint32_t)count * 4;
    }

    uint8_t *blob = calloc(1, total_size);
    memcpy(blob, BLOB_MAGIC, 4);
    write_u16(blob + 4, BLOB_VERSION, big_endian);
    uint16_t flags = 0;
    if (big_endian) flags |= HEADER_FLAG_BIG_ENDIAN;
    if (no_descriptions || !bg.has_any_descriptions) flags |= HEADER_FLAG_NO_DESCRIPTIONS;
    write_u16(blob + 6, flags, big_endian);
    write_u32(blob + 8, (uint32_t)bg.max_command_path_len + 1, big_endian);
    write_u32(blob + 12, (uint32_t)bg.commands_count, big_endian);
    write_u32(blob + 16, (uint32_t)bg.params_count, big_endian);
    write_u32(blob + 20, (uint32_t)bg.global_params_count, big_endian);
    write_u32(blob + 24, (uint32_t)total_strtab_size, big_endian);
    write_u32(blob + 28, (uint32_t)bg.choices_count, big_endian);
    write_u32(blob + 32, (uint32_t)bg.members_count, big_endian);
    write_u32(blob + 36, string_table_off, big_endian);
    write_u32(blob + 40, commands_off, big_endian);
    write_u32(blob + 44, params_off, big_endian);
    write_u32(blob + 48, choices_off, big_endian);
    write_u32(blob + 52, members_off, big_endian);
    write_u32(blob + 56, global_params_off, big_endian);
    write_u32(blob + 60, root_command_off, big_endian);

    // Write hot string table (names, choices, etc.)
    memcpy(blob + string_table_off, bg.strtab.data, bg.strtab.data_len);
    // Write cold string table (descriptions) - at the end for better page locality
    memcpy(blob + string_table_off + bg.strtab.data_len, bg.desc_strtab.data, bg.desc_strtab.data_len);

    // Description offsets need adjustment: they're offsets into the cold table,
    // but need to be relative to string_table_off (which points to hot table start)
    uint32_t desc_off_adjust = (uint32_t)bg.strtab.data_len;

    offset = commands_off;
    for (size_t i = 0; i < bg.commands_count; i++) {
        CommandEntry *ce = &bg.commands[i];
        uint32_t adj_desc_off = ce->desc_off ? ce->desc_off + desc_off_adjust : 0;
        write_u32(blob + offset, ce->name_off, big_endian);
        write_u32(blob + offset + 4, adj_desc_off, big_endian);
        write_u32(blob + offset + 8, ce->params_idx, big_endian);
        write_u16(blob + offset + 12, ce->subcommands_idx, big_endian);
        write_u16(blob + offset + 14, ce->params_count, big_endian);
        write_u16(blob + offset + 16, ce->subcommands_count, big_endian);
        offset += COMMAND_SIZE;
    }

    offset = params_off;
    for (size_t i = 0; i < bg.params_count; i++) {
        ParamEntry *pe = &bg.params[i];
        uint32_t adj_desc_off = pe->desc_off ? pe->desc_off + desc_off_adjust : 0;
        uint32_t choices_off_val = 0;
        if (pe->choices_idx != (uint32_t)-1) {
            if (pe->flags & FLAG_IS_COMPLETER) {
                // Completer: choices_idx is already a string table offset
                choices_off_val = pe->choices_idx;
            } else if (pe->flags & FLAG_IS_MEMBERS) {
                choices_off_val = members_offsets[pe->choices_idx];
            } else {
                choices_off_val = choices_offsets[pe->choices_idx];
            }
        }
        write_u32(blob + offset, pe->name_off, big_endian);
        write_u32(blob + offset + 4, pe->short_off, big_endian);
        write_u32(blob + offset + 8, adj_desc_off, big_endian);
        write_u32(blob + offset + 12, choices_off_val, big_endian);
        blob[offset + 16] = pe->flags;
        offset += PARAM_SIZE;
    }

    // Write choices lists (variable-length count: u8 if <255, else 0xFF + u16)
    offset = choices_off;
    for (size_t i = 0; i < bg.choices_count; i++) {
        StringList *sl = &bg.choices_lists[i];
        if (sl->count < 255) {
            blob[offset++] = (uint8_t)sl->count;
        } else {
            blob[offset++] = 0xFF;
            write_u16(blob + offset, (uint16_t)sl->count, big_endian); offset += 2;
        }
        for (size_t j = 0; j < sl->count; j++) { write_u32(blob + offset, sl->offsets[j], big_endian); offset += 4; }
    }

    // Write members lists (variable-length count: u8 if <255, else 0xFF + u16)
    offset = members_off;
    for (size_t i = 0; i < bg.members_count; i++) {
        StringList *sl = &bg.members_lists[i];
        if (sl->count < 255) {
            blob[offset++] = (uint8_t)sl->count;
        } else {
            blob[offset++] = 0xFF;
            write_u16(blob + offset, (uint16_t)sl->count, big_endian); offset += 2;
        }
        for (size_t j = 0; j < sl->count; j++) { write_u32(blob + offset, sl->offsets[j], big_endian); offset += 4; }
    }

    offset = global_params_off;
    for (size_t i = 0; i < bg.global_params_count; i++) {
        ParamEntry *pe = &bg.global_params[i];
        uint32_t adj_desc_off = pe->desc_off ? pe->desc_off + desc_off_adjust : 0;
        uint32_t choices_off_val = (pe->choices_idx != (uint32_t)-1) ? choices_offsets[pe->choices_idx] : 0;
        write_u32(blob + offset, pe->name_off, big_endian);
        write_u32(blob + offset + 4, pe->short_off, big_endian);
        write_u32(blob + offset + 8, adj_desc_off, big_endian);
        write_u32(blob + offset + 12, choices_off_val, big_endian);
        blob[offset + 16] = pe->flags;
        offset += PARAM_SIZE;
    }

    uint32_t adj_root_desc_off = root_desc_off ? root_desc_off + desc_off_adjust : 0;
    write_u32(blob + root_command_off, 0, big_endian);
    write_u32(blob + root_command_off + 4, adj_root_desc_off, big_endian);
    write_u32(blob + root_command_off + 8, root_params_idx, big_endian);
    write_u16(blob + root_command_off + 12, top_level.idx, big_endian);
    write_u16(blob + root_command_off + 14, 1, big_endian);
    write_u16(blob + root_command_off + 16, top_level.count, big_endian);

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror(output_path);
        return false;
    }
    if (fwrite(blob, 1, total_size, out) != total_size) {
        perror(output_path);
        return false;
    }
    fclose(out);

    fprintf(stderr, "Generated %s (%zu bytes)\n", output_path, total_size);
    fprintf(stderr, "  Commands: %zu\n", bg.commands_count);
    fprintf(stderr, "  Params: %zu\n", bg.params_count);
    fprintf(stderr, "  Global params: %zu\n", bg.global_params_count);
    fprintf(stderr, "  Choices lists: %zu\n", bg.choices_count);
    fprintf(stderr, "  Members lists: %zu\n", bg.members_count);
    fprintf(stderr, "  String table: %zu bytes (hot: %zu, cold: %zu)\n",
            total_strtab_size, bg.strtab.data_len, bg.desc_strtab.data_len);

    free(blob); free(choices_offsets); free(members_offsets);
    node_free(tree); free(js); free(tokens); blobgen_free(&bg);
    return true;
}
