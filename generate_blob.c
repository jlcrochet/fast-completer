/*
 * generate_blob.c - Blob generation from TSV schema files
 *
 * Generates binary completion data blob from tab-separated command schema.
 */

#include "generate_blob.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// Limits
#define VLQ_MAX_LENGTH 32767
#define SHORT_DESC_MAX_LEN 200
#define MAX_FIELDS 8
#define MAX_LINE_LEN 8192

static char *str_ndup(const char *s, size_t n) {
    size_t len = strlen(s);
    if (n < len) len = n;
    char *result = malloc(len + 1);
    if (result) {
        memcpy(result, s, len);
        result[len] = '\0';
    }
    return result;
}

// --------------------------------------------------------------------------
// UTF-8 helpers
// --------------------------------------------------------------------------

// Count UTF-8 characters in a string
static size_t utf8_strlen(const char *s) {
    size_t count = 0;
    while (*s) {
        // Count only lead bytes (not continuation bytes 10xxxxxx)
        if ((*s & 0xC0) != 0x80) count++;
        s++;
    }
    return count;
}

// Find byte offset for the first n UTF-8 characters
// Returns byte position after n characters (or end of string if fewer)
static size_t utf8_byte_offset(const char *s, size_t n_chars) {
    const char *p = s;
    size_t chars = 0;
    while (*p && chars < n_chars) {
        if ((*p & 0xC0) != 0x80) chars++;
        p++;
    }
    // If we stopped mid-sequence, back up to start of this character
    // (This shouldn't happen if input is valid UTF-8, but be safe)
    return (size_t)(p - s);
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
    size_t char_count = utf8_strlen(desc);
    size_t end = len;  // byte position
    size_t chars_seen = 0;

    // Iterate by bytes, but track character count for the limit
    for (size_t i = 0; i < len && chars_seen < SHORT_DESC_MAX_LEN; i++) {
        // Count UTF-8 characters (skip continuation bytes)
        if ((desc[i] & 0xC0) != 0x80) chars_seen++;

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

    // If no sentence break found and exceeds character limit, truncate at word boundary
    if (end == len && char_count > SHORT_DESC_MAX_LEN) {
        // Find byte offset for SHORT_DESC_MAX_LEN characters
        size_t max_bytes = utf8_byte_offset(desc, SHORT_DESC_MAX_LEN);
        end = max_bytes;
        // Walk back to find a space (but not more than ~30 characters back)
        size_t min_bytes = utf8_byte_offset(desc, SHORT_DESC_MAX_LEN > 30 ? SHORT_DESC_MAX_LEN - 30 : 0);
        while (end > min_bytes && desc[end] != ' ') end--;
        if (desc[end] == ' ') {
            char *result = malloc(end + 4);  // +3 for UTF-8 ellipsis, +1 for null
            if (!result) return strdup("");
            memcpy(result, desc, end);
            memcpy(result + end, "\xe2\x80\xa6", 4);  // "…" + null terminator
            return result;
        }
        end = max_bytes;
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
    st->hash_cap = 65536;
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

// Compare two strings by their offsets in the string table (for sorting)
// Decodes directly from the data buffer - O(1) instead of O(n) lookup
static int strtab_cmp(StringTable *st, uint32_t off_a, uint32_t off_b) {
    if (off_a == off_b) return 0;
    if (off_a == 0) return -1;
    if (off_b == 0) return 1;

    // Decode string A
    const uint8_t *pa = st->data + off_a;
    size_t len_a = (pa[0] < 128) ? pa[0] : (((pa[0] & 0x7f) << 8) | pa[1]);
    const char *str_a = (const char *)(pa + (pa[0] < 128 ? 1 : 2));

    // Decode string B
    const uint8_t *pb = st->data + off_b;
    size_t len_b = (pb[0] < 128) ? pb[0] : (((pb[0] & 0x7f) << 8) | pb[1]);
    const char *str_b = (const char *)(pb + (pb[0] < 128 ? 1 : 2));

    // Compare with length awareness (strings aren't null-terminated in buffer)
    size_t min_len = (len_a < len_b) ? len_a : len_b;
    int cmp = memcmp(str_a, str_b, min_len);
    if (cmp != 0) return cmp;
    return (len_a < len_b) ? -1 : (len_a > len_b) ? 1 : 0;
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
    uint32_t hash;
    uint32_t blob_off;
} StringList;

typedef struct {
    // String tables organized by type for cache locality:
    // Layout in blob: [commands][params][choices][descriptions]
    StringTable cmd_strtab;     // Command names (pre-order, no dedup for clustering)
    StringTable param_strtab;   // Param long names + short names
    StringTable choice_strtab;  // Choices, members, completer strings
    StringTable desc_strtab;    // Descriptions (cold, accessed only for output)
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
    size_t max_command_path_len;
    bool big_endian;
    DescriptionMode desc_mode;
    size_t desc_max_len;
    bool has_any_descriptions;
} BlobGen;

static void blobgen_init(BlobGen *bg, bool big_endian, DescriptionMode desc_mode, size_t desc_max_len) {
    memset(bg, 0, sizeof(*bg));
    strtab_init(&bg->cmd_strtab);
    strtab_init(&bg->param_strtab);
    strtab_init(&bg->choice_strtab);
    strtab_init(&bg->desc_strtab);
    bg->params_cap = 1024;
    bg->params = calloc(bg->params_cap, sizeof(ParamEntry));
    bg->commands_cap = 1024;
    bg->commands = calloc(bg->commands_cap, sizeof(CommandEntry));
    bg->choices_cap = 256;
    bg->choices_lists = calloc(bg->choices_cap, sizeof(StringList));
    bg->members_cap = 256;
    bg->members_lists = calloc(bg->members_cap, sizeof(StringList));
    bg->big_endian = big_endian;
    bg->desc_mode = desc_mode;
    bg->desc_max_len = desc_max_len;
}

static uint32_t strtab_add_desc_ex(BlobGen *bg, const char *desc, bool track) {
    if (bg->desc_mode == DESC_NONE || !desc || !*desc) return 0;
    char *processed = NULL;
    char *truncated = NULL;
    if (bg->desc_mode == DESC_SHORT) {
        processed = truncate_to_first_sentence(desc);
        desc = processed;
    }
    // Apply max length truncation if configured (counts UTF-8 characters, not bytes)
    // Uses Unicode ellipsis (…) to distinguish from literal "..." in text
    if (bg->desc_max_len > 0 && desc && utf8_strlen(desc) > bg->desc_max_len) {
        size_t trunc_chars = bg->desc_max_len - 1;  // Room for "…" (1 character)
        size_t trunc_bytes = utf8_byte_offset(desc, trunc_chars);
        truncated = malloc(trunc_bytes + 4);  // +3 for UTF-8 ellipsis, +1 for null
        if (truncated) {
            memcpy(truncated, desc, trunc_bytes);
            memcpy(truncated + trunc_bytes, "\xe2\x80\xa6", 4);  // "…" + null terminator
            desc = truncated;
        }
    }
    uint32_t offset = 0;
    if (desc && *desc) {
        offset = strtab_add(&bg->desc_strtab, desc);
        if (track) bg->has_any_descriptions = true;
    }
    free(processed);
    free(truncated);
    return offset;
}

static uint32_t strtab_add_desc(BlobGen *bg, const char *desc) {
    return strtab_add_desc_ex(bg, desc, true);
}

static void blobgen_free(BlobGen *bg) {
    strtab_free(&bg->cmd_strtab);
    strtab_free(&bg->param_strtab);
    strtab_free(&bg->choice_strtab);
    strtab_free(&bg->desc_strtab);
    free(bg->params);
    free(bg->commands);
    for (size_t i = 0; i < bg->choices_count; i++) free(bg->choices_lists[i].offsets);
    free(bg->choices_lists);
    for (size_t i = 0; i < bg->members_count; i++) free(bg->members_lists[i].offsets);
    free(bg->members_lists);
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

static uint32_t hash_string_list(const uint32_t *offsets, size_t count) {
    uint32_t h = 5381;
    for (size_t i = 0; i < count; i++) {
        h = ((h << 5) + h) ^ offsets[i];
    }
    return h ? h : 1;
}

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

// Add choices from pipe-separated string, return index
static size_t add_choices_from_string(BlobGen *bg, const char *choices_str) {
    if (!choices_str || !*choices_str) return (size_t)-1;

    // Count choices
    size_t count = 1;
    for (const char *p = choices_str; *p; p++) {
        if (*p == '|') count++;
    }

    uint32_t *offsets = malloc(count * sizeof(uint32_t));
    char *copy = strdup(choices_str);
    char *saveptr;
    char *token = strtok_r(copy, "|", &saveptr);
    size_t i = 0;
    while (token && i < count) {
        offsets[i++] = strtab_add(&bg->choice_strtab, token);
        token = strtok_r(NULL, "|", &saveptr);
    }
    free(copy);

    // Check for existing identical list
    uint32_t hash = hash_string_list(offsets, i);
    size_t existing = find_existing_choices(bg, offsets, i, hash);
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
    sl->count = i;
    sl->hash = hash;
    sl->blob_off = 0;
    return bg->choices_count++;
}

// Add members from {key1|key2} string, return index
// Handles nested braces: {foo{x}|bar} parses as members "foo{x}" and "bar"
static size_t add_members_from_string(BlobGen *bg, const char *members_str) {
    if (!members_str || members_str[0] != '{') return (size_t)-1;

    // Skip { and find matching } (handle nested braces)
    const char *start = members_str + 1;
    const char *end = NULL;
    int depth = 1;
    for (const char *p = start; *p; p++) {
        if (*p == '{') depth++;
        else if (*p == '}') {
            depth--;
            if (depth == 0) { end = p; break; }
        }
    }
    if (!end) return (size_t)-1;

    size_t len = end - start;
    char *inner = malloc(len + 1);
    memcpy(inner, start, len);
    inner[len] = '\0';

    // Count members (skip | inside nested braces)
    size_t count = 1;
    int brace_depth = 0;
    for (const char *p = inner; *p; p++) {
        if (*p == '{') brace_depth++;
        else if (*p == '}') brace_depth--;
        else if (*p == '|' && brace_depth == 0) count++;
    }

    // Split on | (respecting nested braces)
    uint32_t *offsets = malloc(count * sizeof(uint32_t));
    size_t i = 0;
    const char *token_start = inner;
    brace_depth = 0;
    for (const char *p = inner; ; p++) {
        if (*p == '{') brace_depth++;
        else if (*p == '}') brace_depth--;
        else if ((*p == '|' && brace_depth == 0) || *p == '\0') {
            if (p > token_start && i < count) {
                size_t token_len = p - token_start;
                char buf[256];
                size_t copy_len = token_len < sizeof(buf) - 2 ? token_len : sizeof(buf) - 2;
                memcpy(buf, token_start, copy_len);
                buf[copy_len] = '=';
                buf[copy_len + 1] = '\0';
                offsets[i++] = strtab_add(&bg->choice_strtab, buf);
            }
            if (*p == '\0') break;
            token_start = p + 1;
        }
    }
    free(inner);

    // Check for existing identical list
    uint32_t hash = hash_string_list(offsets, i);
    size_t existing = find_existing_members(bg, offsets, i, hash);
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
    sl->count = i;
    sl->hash = hash;
    sl->blob_off = 0;
    return bg->members_count++;
}

// --------------------------------------------------------------------------
// Command Tree Building
// --------------------------------------------------------------------------

typedef struct CommandNode {
    char *name;
    char *description;
    struct CommandNode **children;
    size_t children_count;
    size_t children_cap;
    ParamEntry *params;
    size_t params_count;
    size_t params_cap;
} CommandNode;

static CommandNode *node_create(const char *name) {
    CommandNode *node = calloc(1, sizeof(CommandNode));
    node->name = strdup(name ? name : "");
    node->children_cap = 8;
    node->children = calloc(node->children_cap, sizeof(CommandNode *));
    node->params_cap = 8;
    node->params = calloc(node->params_cap, sizeof(ParamEntry));
    return node;
}

static void node_free(CommandNode *node) {
    if (!node) return;
    free(node->name);
    free(node->description);
    for (size_t i = 0; i < node->children_count; i++) node_free(node->children[i]);
    free(node->children);
    free(node->params);
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

static void node_add_param(CommandNode *node, ParamEntry *pe) {
    if (node->params_count >= node->params_cap) {
        node->params_cap *= 2;
        node->params = realloc(node->params, node->params_cap * sizeof(ParamEntry));
    }
    node->params[node->params_count++] = *pe;
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

// Global pointer for param sorting (qsort doesn't support context)
static BlobGen *g_sort_bg = NULL;

// Compare params alphabetically by name (or short name for short-only params)
static int cmp_params(const void *a, const void *b) {
    const ParamEntry *pa = (const ParamEntry *)a;
    const ParamEntry *pb = (const ParamEntry *)b;
    // Use name_off if present, otherwise short_off (for short-only params)
    uint32_t off_a = pa->name_off ? pa->name_off : pa->short_off;
    uint32_t off_b = pb->name_off ? pb->name_off : pb->short_off;
    return strtab_cmp(&g_sort_bg->param_strtab, off_a, off_b);
}

// Sort params within each depth level, then recurse
static void sort_node_params(BlobGen *bg, CommandNode *node) {
    if (node->params_count > 1) {
        g_sort_bg = bg;
        qsort(node->params, node->params_count, sizeof(ParamEntry), cmp_params);
    }
    for (size_t i = 0; i < node->children_count; i++) {
        sort_node_params(bg, node->children[i]);
    }
}

// --------------------------------------------------------------------------
// Collect params and commands
// --------------------------------------------------------------------------

typedef struct { uint32_t idx; uint16_t count; } IdxCount;

static IdxCount collect_params_from_node(BlobGen *bg, CommandNode *node) {
    IdxCount result = {0, 0};
    if (node->params_count == 0) return result;

    uint32_t start_idx = (uint32_t)bg->params_count;
    for (size_t i = 0; i < node->params_count; i++) {
        if (bg->params_count >= bg->params_cap) {
            bg->params_cap *= 2;
            bg->params = realloc(bg->params, bg->params_cap * sizeof(ParamEntry));
        }
        bg->params[bg->params_count++] = node->params[i];
    }

    if (node->params_count > 65535) {
        fprintf(stderr, "Too many params in one command: %zu (max 65535)\n", node->params_count);
        return result;
    }

    // Params are sorted alphabetically within each depth level, with inheritance order preserved
    // (command's own params first, then parent's, then grandparent's, etc.)
    // Linear search is used in the completer, which is fine for typical param counts
    result.idx = start_idx;
    result.count = (uint16_t)node->params_count;
    return result;
}

static IdxCount collect_commands(BlobGen *bg, CommandNode *node);

static IdxCount collect_commands(BlobGen *bg, CommandNode *node) {
    IdxCount result = {0, 0};
    if (node->children_count == 0) return result;

    typedef struct {
        uint32_t name_off, desc_off, params_idx, subcommands_idx;
        uint16_t params_count, subcommands_count;
    } ChildData;

    ChildData *child_data = malloc(node->children_count * sizeof(ChildData));
    if (!child_data) {
        fprintf(stderr, "malloc failed in collect_commands\n");
        return result;
    }

    for (size_t i = 0; i < node->children_count; i++) {
        CommandNode *child = node->children[i];

        // Add name BEFORE recursing (pre-order) for subtree clustering
        child_data[i].name_off = strtab_add_nodupe(&bg->cmd_strtab, child->name);

        // Recurse into children
        IdxCount sub_result = collect_commands(bg, child);
        child_data[i].subcommands_idx = sub_result.idx;
        child_data[i].subcommands_count = sub_result.count;

        // Collect params
        IdxCount params_result = collect_params_from_node(bg, child);
        child_data[i].params_idx = params_result.idx;
        child_data[i].params_count = params_result.count;
        child_data[i].desc_off = strtab_add_desc(bg, child->description);
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
    }
    free(child_data);
    result.idx = start_idx;
    if (node->children_count > 65535) {
        fprintf(stderr, "Too many subcommands in one command: %zu (max 65535)\n", node->children_count);
        result.count = 65535;
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
// Schema Parsing
// --------------------------------------------------------------------------

#define MAX_DEPTH 32

// Count leading tabs in a line
static int count_leading_tabs(const char *line) {
    int tabs = 0;
    while (line[tabs] == '\t') tabs++;
    return tabs;
}

// --------------------------------------------------------------------------
// New format tokenizer
// --------------------------------------------------------------------------

typedef enum {
    TOK_WORD,       // Regular word (whitespace-separated)
    TOK_CHOICES,    // (value1|value2)
    TOK_MEMBERS,    // {key1|key2}
    TOK_COMPLETER,  // `completer`
    TOK_BOOL,       // @bool
    TOK_DESC,       // # description (rest of line)
    TOK_END         // End of tokens
} TokenType;

typedef struct {
    TokenType type;
    char *value;    // Owned copy of token content (without delimiters)
} Token;

typedef struct {
    Token *tokens;
    size_t count;
    size_t capacity;
} TokenList;

static void token_list_init(TokenList *tl) {
    tl->capacity = 8;
    tl->tokens = malloc(tl->capacity * sizeof(Token));
    tl->count = 0;
}

static void token_list_add(TokenList *tl, TokenType type, const char *start, size_t len) {
    if (tl->count >= tl->capacity) {
        tl->capacity *= 2;
        tl->tokens = realloc(tl->tokens, tl->capacity * sizeof(Token));
    }
    Token *t = &tl->tokens[tl->count++];
    t->type = type;
    t->value = malloc(len + 1);
    memcpy(t->value, start, len);
    t->value[len] = '\0';
}

static void token_list_free(TokenList *tl) {
    for (size_t i = 0; i < tl->count; i++) {
        free(tl->tokens[i].value);
    }
    free(tl->tokens);
}

// Tokenize a line in the new schema format
// Returns false on error (unmatched delimiters)
static bool tokenize_line(const char *line, TokenList *tl, const char *path, int line_num) {
    token_list_init(tl);
    const char *p = line;

    while (*p) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        // Check for description (# outside delimiters)
        if (*p == '#') {
            p++;  // Skip #
            while (*p == ' ' || *p == '\t') p++;  // Skip leading whitespace after #
            size_t len = strlen(p);
            // Trim trailing whitespace
            while (len > 0 && (p[len-1] == ' ' || p[len-1] == '\t' || p[len-1] == '\r' || p[len-1] == '\n')) len--;
            token_list_add(tl, TOK_DESC, p, len);
            break;  // Description consumes rest of line
        }

        // Check for choices: (...)
        if (*p == '(') {
            const char *start = p + 1;
            int depth = 1;
            p++;
            while (*p && depth > 0) {
                if (*p == '(') depth++;
                else if (*p == ')') depth--;
                if (depth > 0) p++;
            }
            if (depth != 0) {
                fprintf(stderr, "%s:%d: error: unmatched '(' in choices\n", path, line_num);
                token_list_free(tl);
                return false;
            }
            token_list_add(tl, TOK_CHOICES, start, p - start);
            p++;  // Skip closing )
            continue;
        }

        // Check for members: {...}
        if (*p == '{') {
            const char *start = p + 1;
            int depth = 1;
            p++;
            while (*p && depth > 0) {
                if (*p == '{') depth++;
                else if (*p == '}') depth--;
                if (depth > 0) p++;
            }
            if (depth != 0) {
                fprintf(stderr, "%s:%d: error: unmatched '{' in members\n", path, line_num);
                token_list_free(tl);
                return false;
            }
            token_list_add(tl, TOK_MEMBERS, start, p - start);
            p++;  // Skip closing }
            continue;
        }

        // Check for completer: `...`
        if (*p == '`') {
            const char *start = p + 1;
            p++;
            while (*p && *p != '`') p++;
            if (*p != '`') {
                fprintf(stderr, "%s:%d: error: unmatched '`' in completer\n", path, line_num);
                token_list_free(tl);
                return false;
            }
            token_list_add(tl, TOK_COMPLETER, start, p - start);
            p++;  // Skip closing `
            continue;
        }

        // Check for @bool keyword
        if (*p == '@') {
            const char *start = p;
            p++;
            while (*p && *p != ' ' && *p != '\t' && *p != '#') p++;
            size_t len = p - start;
            if (len == 5 && strncmp(start, "@bool", 5) == 0) {
                token_list_add(tl, TOK_BOOL, "bool", 4);
            } else {
                // Unknown @ keyword, treat as word
                token_list_add(tl, TOK_WORD, start, len);
            }
            continue;
        }

        // Regular word (until whitespace or # or special delimiter)
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '#' && *p != '(' && *p != '{' && *p != '`') p++;
        if (p > start) {
            token_list_add(tl, TOK_WORD, start, p - start);
        }
    }

    return true;
}

// Trim trailing whitespace
static void trim_trailing(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' || s[len-1] == '\r' || s[len-1] == '\n')) {
        s[--len] = '\0';
    }
}

// Parse option spec and extract long/short options
// Format: --long|-s, --long, -s, --long|--alias, etc.
// Aliases separated by |, first of each type (short=2 chars, long=other) used
static void parse_option_spec(const char *spec, char **long_opt, char **short_opt) {
    static char long_buf[256];
    static char short_buf[8];
    *long_opt = NULL;
    *short_opt = NULL;

    char *copy = strdup(spec);
    char *saveptr;
    char *token = strtok_r(copy, "|", &saveptr);
    while (token) {
        size_t len = strlen(token);
        if (len >= 2 && token[0] == '-') {
            if (len == 2) {
                // Short option: exactly 2 chars like -s
                if (!*short_opt && len < sizeof(short_buf)) {
                    strcpy(short_buf, token);
                    *short_opt = short_buf;
                }
            } else {
                // Long option: -foo, --foo, or longer
                if (!*long_opt && len < sizeof(long_buf)) {
                    strcpy(long_buf, token);
                    *long_opt = long_buf;
                }
            }
        }
        token = strtok_r(NULL, "|", &saveptr);
    }
    free(copy);
}

// Parse param line in new format:
//   --long-option|-s @bool # description
//   --long-option|-s (choice1|choice2) # description
//   --long-option {key1|key2} # description
//   --long-option `completer` # description
//
// Tokens: option_spec [@bool | (choices) | {members} | `completer`] [# description]
static bool parse_param_line(BlobGen *bg, const char *line, CommandNode *current_cmd, const char *path, int line_num) {
    TokenList tl;
    if (!tokenize_line(line, &tl, path, line_num)) {
        return false;
    }

    if (tl.count == 0) {
        token_list_free(&tl);
        return false;
    }

    // First token must be option spec
    if (tl.tokens[0].type != TOK_WORD || tl.tokens[0].value[0] != '-') {
        token_list_free(&tl);
        return false;
    }

    char *long_opt = NULL;
    char *short_opt = NULL;
    parse_option_spec(tl.tokens[0].value, &long_opt, &short_opt);

    ParamEntry pe;
    pe.name_off = long_opt ? strtab_add(&bg->param_strtab, long_opt) : 0;
    pe.short_off = short_opt ? strtab_add(&bg->param_strtab, short_opt) : 0;
    pe.desc_off = 0;
    pe.flags = 0;
    pe.choices_idx = (uint32_t)-1;

    bool is_bool = false;
    bool has_type = false;

    // Process remaining tokens
    for (size_t i = 1; i < tl.count; i++) {
        Token *t = &tl.tokens[i];
        switch (t->type) {
            case TOK_BOOL:
                is_bool = true;
                has_type = true;
                break;
            case TOK_CHOICES: {
                size_t idx = add_choices_from_string(bg, t->value);
                if (idx != (size_t)-1) {
                    pe.choices_idx = (uint32_t)idx;
                    pe.flags |= FLAG_TAKES_VALUE;
                }
                has_type = true;
                break;
            }
            case TOK_MEMBERS: {
                // Wrap in braces for add_members_from_string (stack buffer, bounded by line length)
                char wrapped[MAX_LINE_LEN + 3];
                snprintf(wrapped, sizeof(wrapped), "{%s}", t->value);
                size_t idx = add_members_from_string(bg, wrapped);
                if (idx != (size_t)-1) {
                    pe.choices_idx = (uint32_t)idx;
                    pe.flags |= FLAG_IS_MEMBERS | FLAG_TAKES_VALUE;
                }
                has_type = true;
                break;
            }
            case TOK_COMPLETER:
                pe.choices_idx = strtab_add(&bg->choice_strtab, t->value);
                pe.flags |= FLAG_IS_COMPLETER | FLAG_TAKES_VALUE;
                has_type = true;
                break;
            case TOK_DESC:
                pe.desc_off = strtab_add_desc(bg, t->value);
                break;
            case TOK_WORD:
                // Ignore unknown words
                break;
            case TOK_END:
                break;
        }
    }

    // Validation: @bool cannot combine with choices/members/completer
    if (is_bool && (pe.flags & (FLAG_TAKES_VALUE | FLAG_IS_MEMBERS | FLAG_IS_COMPLETER))) {
        fprintf(stderr, "%s:%d: warning: @bool cannot combine with choices/members/completer\n", path, line_num);
    }

    // If no type specified and not bool, default to takes value
    if (!is_bool && !has_type) {
        pe.flags |= FLAG_TAKES_VALUE;
    }

    if (current_cmd) {
        node_add_param(current_cmd, &pe);
    }

    token_list_free(&tl);
    return true;
}

// Load file contents
static char *load_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { perror(path); fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0) { perror("ftell"); fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { perror(path); fclose(f); return NULL; }
    if ((size_t)size > SIZE_MAX - 1) {
        fprintf(stderr, "%s: file too large\n", path);
        fclose(f);
        return NULL;
    }
    char *content = malloc((size_t)size + 1);
    if (!content) { perror("malloc"); fclose(f); return NULL; }
    size_t nread = fread(content, 1, (size_t)size, f);
    if (nread != (size_t)size) {
        if (ferror(f)) perror(path);
        else fprintf(stderr, "%s: short read\n", path);
        free(content);
        fclose(f);
        return NULL;
    }
    content[nread] = '\0';
    fclose(f);
    return content;
}

// Main TSV parser - indentation-based format
// First depth-0 command is the root/CLI name; its description is the root description
// All subsequent commands are children of this root
static bool parse_tsv_schema(const char *path, BlobGen *bg, CommandNode *root, char **out_root_desc) {
    char *content = load_file(path);
    if (!content) return false;

    char *line = content;
    int line_num = 0;
    bool seen_root = false;
    int current_depth = 0;

    // Stack of command nodes by depth (stack[0] = root after first command)
    CommandNode *stack[MAX_DEPTH];
    for (int i = 0; i < MAX_DEPTH; i++) stack[i] = NULL;

    while (line && *line) {
        line_num++;

        // Find end of line
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';

        // Validation: leading spaces are forbidden
        if (line[0] == ' ') {
            fprintf(stderr, "%s:%d: error: leading spaces not allowed, use tabs for indentation\n", path, line_num);
            free(content);
            return false;
        }

        int tabs = count_leading_tabs(line);
        if (tabs >= MAX_DEPTH) {
            fprintf(stderr, "%s:%d: error: indentation too deep (max depth %d)\n", path, line_num, MAX_DEPTH - 1);
            free(content);
            return false;
        }
        char *content_start = line + tabs;

        trim_trailing(content_start);

        // Skip empty lines and comment lines (# only)
        if (!*content_start || content_start[0] == '#') {
            line = eol ? eol + 1 : NULL;
            continue;
        }

        // Handle parameter lines
        if (content_start[0] == '-' && content_start[1] == '-') {
            if (!seen_root) {
                // Parameters before root command are not allowed
                fprintf(stderr, "%s:%d: error: parameters must come after the root command; define them on the root command instead\n", path, line_num);
                free(content);
                return false;
            }
            // Param at depth N belongs to command at depth N-1
            // (params are indented one level under their command)
            if (tabs == 0) {
                fprintf(stderr, "%s:%d: error: parameter after root command must be indented\n", path, line_num);
                free(content);
                return false;
            }
            if (tabs > current_depth + 1) {
                fprintf(stderr, "%s:%d: error: parameter indentation (%d) too deep for current command depth (%d)\n",
                        path, line_num, tabs, current_depth);
                free(content);
                return false;
            }
            CommandNode *target = stack[tabs - 1];
            if (!target) {
                fprintf(stderr, "%s:%d: error: no command at depth %d for parameter\n", path, line_num, tabs - 1);
                free(content);
                return false;
            }
            if (!parse_param_line(bg, content_start, target, path, line_num)) {
                free(content);
                return false;
            }
            line = eol ? eol + 1 : NULL;
            continue;
        }

        // Command line: name [# description]
        // Validate that line starts with a valid command name character (alphanumeric or _)
        char c = content_start[0];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            fprintf(stderr, "%s:%d: error: unexpected character '%c'; expected command name, parameter (--), or comment (#)\n",
                    path, line_num, c);
            free(content);
            return false;
        }

        // Parse command name and description using tokenizer
        TokenList cmd_tl;
        if (!tokenize_line(content_start, &cmd_tl, path, line_num)) {
            free(content);
            return false;
        }
        const char *cmd_name = NULL;
        const char *cmd_desc = NULL;
        for (size_t i = 0; i < cmd_tl.count; i++) {
            if (cmd_tl.tokens[i].type == TOK_WORD && !cmd_name) {
                cmd_name = cmd_tl.tokens[i].value;
            } else if (cmd_tl.tokens[i].type == TOK_DESC) {
                cmd_desc = cmd_tl.tokens[i].value;
            }
        }
        if (!cmd_name) {
            token_list_free(&cmd_tl);
            line = eol ? eol + 1 : NULL;
            continue;
        }

        if (!seen_root) {
            // First depth-0 command is the root
            if (tabs != 0) {
                fprintf(stderr, "%s:%d: error: first command must be at depth 0 (the root/CLI name)\n", path, line_num);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }
            seen_root = true;
            current_depth = 0;

            // Set root name and description
            free(root->name);
            root->name = strdup(cmd_name);
            if (cmd_desc && *cmd_desc && out_root_desc) {
                *out_root_desc = strdup(cmd_desc);
            }
            stack[0] = root;
        } else {
            // Subsequent commands
            // Validation: indentation can only increase by 1
            if (tabs > current_depth + 1) {
                fprintf(stderr, "%s:%d: error: indentation increased by more than 1 level (from %d to %d)\n",
                        path, line_num, current_depth, tabs);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }
            if (tabs == 0) {
                fprintf(stderr, "%s:%d: error: only one root command allowed; subsequent commands must be indented\n",
                        path, line_num);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }

            current_depth = tabs;

            // Get parent node
            CommandNode *parent = stack[tabs - 1];
            if (!parent) {
                fprintf(stderr, "%s:%d: error: no parent command at depth %d\n", path, line_num, tabs - 1);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }

            // Get or create child node
            CommandNode *node = node_get_child(parent, cmd_name);
            if (!node) {
                node = node_add_child(parent, cmd_name);
            }
            if (cmd_desc && *cmd_desc) {
                free(node->description);
                node->description = strdup(cmd_desc);
            }
            stack[tabs] = node;

            // Clear deeper stack entries
            for (int i = tabs + 1; i < MAX_DEPTH; i++) stack[i] = NULL;

            // Track command path length for buffer sizing
            // Calculate full path length by walking up the stack (excluding root)
            size_t path_len = strlen(cmd_name);
            for (int i = tabs - 1; i >= 1; i--) {
                if (stack[i] && stack[i]->name[0]) {
                    path_len += 1 + strlen(stack[i]->name); // +1 for space
                }
            }
            track_command_path_len(bg, path_len);
        }

        token_list_free(&cmd_tl);
        line = eol ? eol + 1 : NULL;
    }

    if (!seen_root) {
        fprintf(stderr, "%s: error: no root command found\n", path);
        free(content);
        return false;
    }

    free(content);

    // Sort params alphabetically within each depth level
    sort_node_params(bg, root);

    return true;
}

// --------------------------------------------------------------------------
// Schema name extraction
// --------------------------------------------------------------------------

// Extract schema name from first depth-0 command (the root/CLI name)
char *get_schema_name(const char *schema_path) {
    char *content = load_file(schema_path);
    if (!content) return NULL;

    char *result = NULL;
    char *line = content;

    while (line && *line && !result) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';

        // Skip lines with leading tabs (not depth 0)
        if (line[0] == '\t') {
            line = eol ? eol + 1 : NULL;
            continue;
        }

        trim_trailing(line);

        // Skip empty lines, comments, and params
        if (!*line || line[0] == '#' || (line[0] == '-' && line[1] == '-')) {
            line = eol ? eol + 1 : NULL;
            continue;
        }

        // First depth-0 non-param non-comment line is the root command
        // Extract just the name (first word before space, tab, or #)
        const char *p = line;
        while (*p && *p != ' ' && *p != '\t' && *p != '#') p++;
        result = str_ndup(line, p - line);
        break;
    }

    free(content);
    return result;
}

// --------------------------------------------------------------------------
// Main blob generation
// --------------------------------------------------------------------------

static inline size_t align4(size_t v) {
    return (v + 3u) & ~((size_t)3u);
}

bool generate_blob(const char *schema_path, const char *output_path, bool big_endian, DescriptionMode desc_mode, size_t desc_max_len) {
    BlobGen bg;
    blobgen_init(&bg, big_endian, desc_mode, desc_max_len);

    CommandNode *root = node_create("");
    char *root_desc = NULL;

    if (!parse_tsv_schema(schema_path, &bg, root, &root_desc)) {
        node_free(root);
        blobgen_free(&bg);
        return false;
    }

    sort_children(root);

    IdxCount top_level = collect_commands(&bg, root);

    // Collect root's own params (these inherit to all children, so they're the "global" params)
    IdxCount root_params = collect_params_from_node(&bg, root);

    // Root description
    uint32_t root_desc_off = strtab_add_desc_ex(&bg, root_desc ? root_desc : "CLI", false);

    // Check for integer overflow in counts
    if (bg.commands_count > 65535) {
        fprintf(stderr, "Too many commands: %zu (max 65535)\n", bg.commands_count);
        node_free(root); blobgen_free(&bg); free(root_desc);
        return false;
    }
    if (bg.params_count > 16777215) {
        fprintf(stderr, "Too many params: %zu (max 16777215)\n", bg.params_count);
        node_free(root); blobgen_free(&bg); free(root_desc);
        return false;
    }

    // String table layout: [commands][params][choices][descriptions]
    size_t cmd_len = bg.cmd_strtab.data_len;
    size_t param_len = bg.param_strtab.data_len;
    size_t choice_len = bg.choice_strtab.data_len;
    size_t desc_len = bg.desc_strtab.data_len;
    size_t total_strtab_size = cmd_len + param_len + choice_len + desc_len;
    if (total_strtab_size > UINT32_MAX) {
        fprintf(stderr, "String table too large: %zu bytes (max 4GB)\n", total_strtab_size);
        node_free(root); blobgen_free(&bg); free(root_desc);
        return false;
    }
    // Offset adjustments for each section
    uint32_t param_off_adj = (uint32_t)cmd_len;
    uint32_t choice_off_adj = (uint32_t)(cmd_len + param_len);
    uint32_t desc_off_adj = (uint32_t)(cmd_len + param_len + choice_len);

    size_t commands_size = bg.commands_count * COMMAND_SIZE;
    size_t params_size = bg.params_count * PARAM_SIZE;

    size_t choices_size = 0;
    for (size_t i = 0; i < bg.choices_count; i++) {
        size_t count = bg.choices_lists[i].count;
        if (count > 65535) {
            fprintf(stderr, "Choice list %zu too large: %zu items (max 65535)\n", i, count);
            node_free(root); blobgen_free(&bg); free(root_desc);
            return false;
        }
        choices_size += 4 + count * 4;
    }
    size_t members_size = 0;
    for (size_t i = 0; i < bg.members_count; i++) {
        size_t count = bg.members_lists[i].count;
        if (count > 65535) {
            fprintf(stderr, "Member list %zu too large: %zu items (max 65535)\n", i, count);
            node_free(root); blobgen_free(&bg); free(root_desc);
            return false;
        }
        members_size += 4 + count * 4;
    }

    uint32_t string_table_off = HEADER_SIZE;
    uint32_t commands_off = (uint32_t)align4(string_table_off + total_strtab_size);
    uint32_t params_off = (uint32_t)align4(commands_off + commands_size);
    uint32_t choices_off = (uint32_t)align4(params_off + params_size);
    uint32_t members_off = (uint32_t)align4(choices_off + choices_size);
    uint32_t root_command_off = (uint32_t)align4(members_off + members_size);
    size_t total_size = root_command_off + COMMAND_SIZE;

    uint32_t *choices_offsets = malloc(bg.choices_count * sizeof(uint32_t));
    uint32_t offset = choices_off;
    for (size_t i = 0; i < bg.choices_count; i++) {
        choices_offsets[i] = offset;
        size_t count = bg.choices_lists[i].count;
        offset += 4 + (uint32_t)count * 4;
    }
    uint32_t *members_offsets = malloc(bg.members_count * sizeof(uint32_t));
    offset = members_off;
    for (size_t i = 0; i < bg.members_count; i++) {
        members_offsets[i] = offset;
        size_t count = bg.members_lists[i].count;
        offset += 4 + (uint32_t)count * 4;
    }

    uint8_t *blob = calloc(1, total_size);
    memcpy(blob, BLOB_MAGIC, 4);
    write_u16(blob + 4, BLOB_VERSION, big_endian);
    uint16_t flags = 0;
    if (big_endian) flags |= HEADER_FLAG_BIG_ENDIAN;
    if (desc_mode == DESC_NONE || !bg.has_any_descriptions) flags |= HEADER_FLAG_NO_DESCRIPTIONS;
    write_u16(blob + 6, flags, big_endian);
    write_u32(blob + 8, (uint32_t)bg.max_command_path_len + 1, big_endian);
    write_u32(blob + 12, (uint32_t)bg.commands_count, big_endian);
    write_u32(blob + 16, (uint32_t)bg.params_count, big_endian);
    write_u32(blob + 20, (uint32_t)total_strtab_size, big_endian);
    write_u32(blob + 24, (uint32_t)bg.choices_count, big_endian);
    write_u32(blob + 28, (uint32_t)bg.members_count, big_endian);
    write_u32(blob + 32, string_table_off, big_endian);
    write_u32(blob + 36, commands_off, big_endian);
    write_u32(blob + 40, params_off, big_endian);
    write_u32(blob + 44, choices_off, big_endian);
    write_u32(blob + 48, members_off, big_endian);
    write_u32(blob + 52, root_command_off, big_endian);

    // Write string tables in order: commands, params, choices, descriptions
    uint32_t st_off = string_table_off;
    memcpy(blob + st_off, bg.cmd_strtab.data, cmd_len);
    st_off += cmd_len;
    memcpy(blob + st_off, bg.param_strtab.data, param_len);
    st_off += param_len;
    memcpy(blob + st_off, bg.choice_strtab.data, choice_len);
    st_off += choice_len;
    memcpy(blob + st_off, bg.desc_strtab.data, desc_len);

    offset = commands_off;
    for (size_t i = 0; i < bg.commands_count; i++) {
        CommandEntry *ce = &bg.commands[i];
        // Command names are in cmd_strtab (no adjustment needed - first section)
        // Descriptions are in desc_strtab (need desc_off_adj)
        uint32_t adj_desc_off = ce->desc_off ? ce->desc_off + desc_off_adj : 0;
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
        // Param names are in param_strtab (need param_off_adj)
        // Descriptions are in desc_strtab (need desc_off_adj)
        // Completer strings are in choice_strtab (need choice_off_adj)
        uint32_t adj_name_off = pe->name_off ? pe->name_off + param_off_adj : 0;
        uint32_t adj_short_off = pe->short_off ? pe->short_off + param_off_adj : 0;
        uint32_t adj_desc_off = pe->desc_off ? pe->desc_off + desc_off_adj : 0;
        uint32_t choices_off_val = 0;
        if (pe->choices_idx != (uint32_t)-1) {
            if (pe->flags & FLAG_IS_COMPLETER) {
                // Completer string is in choice_strtab
                choices_off_val = pe->choices_idx + choice_off_adj;
            } else if (pe->flags & FLAG_IS_MEMBERS) {
                choices_off_val = members_offsets[pe->choices_idx];
            } else {
                choices_off_val = choices_offsets[pe->choices_idx];
            }
        }
        write_u32(blob + offset, adj_name_off, big_endian);
        write_u32(blob + offset + 4, adj_short_off, big_endian);
        write_u32(blob + offset + 8, adj_desc_off, big_endian);
        write_u32(blob + offset + 12, choices_off_val, big_endian);
        blob[offset + 16] = pe->flags;
        offset += PARAM_SIZE;
    }

    // Write choices lists (string offsets are in choice_strtab, need choice_off_adj)
    offset = choices_off;
    for (size_t i = 0; i < bg.choices_count; i++) {
        StringList *sl = &bg.choices_lists[i];
        if (sl->count < 255) {
            blob[offset] = (uint8_t)sl->count;
            blob[offset + 1] = 0;
            blob[offset + 2] = 0;
            blob[offset + 3] = 0;
        } else {
            blob[offset] = 0xFF;
            write_u16(blob + offset + 1, (uint16_t)sl->count, big_endian);
            blob[offset + 3] = 0;
        }
        offset += 4;
        for (size_t j = 0; j < sl->count; j++) {
            uint32_t adj_off = sl->offsets[j] ? sl->offsets[j] + choice_off_adj : 0;
            write_u32(blob + offset, adj_off, big_endian);
            offset += 4;
        }
    }

    // Write members lists (string offsets are in choice_strtab, need choice_off_adj)
    offset = members_off;
    for (size_t i = 0; i < bg.members_count; i++) {
        StringList *sl = &bg.members_lists[i];
        if (sl->count < 255) {
            blob[offset] = (uint8_t)sl->count;
            blob[offset + 1] = 0;
            blob[offset + 2] = 0;
            blob[offset + 3] = 0;
        } else {
            blob[offset] = 0xFF;
            write_u16(blob + offset + 1, (uint16_t)sl->count, big_endian);
            blob[offset + 3] = 0;
        }
        offset += 4;
        for (size_t j = 0; j < sl->count; j++) {
            uint32_t adj_off = sl->offsets[j] ? sl->offsets[j] + choice_off_adj : 0;
            write_u32(blob + offset, adj_off, big_endian);
            offset += 4;
        }
    }

    uint32_t adj_root_desc_off = root_desc_off ? root_desc_off + desc_off_adj : 0;
    write_u32(blob + root_command_off, 0, big_endian);
    write_u32(blob + root_command_off + 4, adj_root_desc_off, big_endian);
    write_u32(blob + root_command_off + 8, root_params.idx, big_endian);
    write_u16(blob + root_command_off + 12, top_level.idx, big_endian);
    write_u16(blob + root_command_off + 14, root_params.count, big_endian);
    write_u16(blob + root_command_off + 16, top_level.count, big_endian);

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror(output_path);
        node_free(root); blobgen_free(&bg); free(root_desc);
        free(blob); free(choices_offsets); free(members_offsets);
        return false;
    }
    if (fwrite(blob, 1, total_size, out) != total_size) {
        perror(output_path);
        node_free(root); blobgen_free(&bg); free(root_desc);
        free(blob); free(choices_offsets); free(members_offsets);
        return false;
    }
    fclose(out);

    fprintf(stderr, "Generated %s (%zu bytes)\n", output_path, total_size);
    fprintf(stderr, "  Commands: %zu\n", bg.commands_count);
    fprintf(stderr, "  Params: %zu\n", bg.params_count);
    fprintf(stderr, "  Choices lists: %zu\n", bg.choices_count);
    fprintf(stderr, "  Members lists: %zu\n", bg.members_count);
    fprintf(stderr, "  String table: %zu bytes (cmds: %zu, params: %zu, choices: %zu, descs: %zu)\n",
            total_strtab_size, cmd_len, param_len, choice_len, desc_len);

    free(blob); free(choices_offsets); free(members_offsets);
    node_free(root); blobgen_free(&bg); free(root_desc);
    return true;
}
