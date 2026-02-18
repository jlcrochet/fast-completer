/*
 * generate_blob.c - Blob generation from .fcmps schema files
 *
 * Generates binary completion data blob from indentation-based tab-indented command schema.
 */

#include "generate_blob.h"
#include "diagnostic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>

#if defined(_MSC_VER)
#define strdup _strdup
static char *fcmp_strtok_r(char *str, const char *delim, char **saveptr) {
    return strtok_s(str, delim, saveptr);
}
#else
static char *fcmp_strtok_r(char *str, const char *delim, char **saveptr) {
    return strtok_r(str, delim, saveptr);
}
#endif

// Limits
#define VLQ_MAX_LENGTH 32767
#define SHORT_DESC_MAX_LEN 200
#define MAX_LINE_LEN 8192

static char *str_ndup(const char *s, size_t n) {
    size_t len = strnlen(s, n);
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
    if (!s || n_chars == 0) return 0;
    const unsigned char *p = (const unsigned char *)s;
    const unsigned char *start = p;
    size_t chars = 0;
    while (*p && chars < n_chars) {
        size_t adv = 1;
        unsigned char c = *p;
        if (c < 0x80) {
            adv = 1;
        } else if ((c & 0xE0) == 0xC0) {
            adv = 2;
        } else if ((c & 0xF0) == 0xE0) {
            adv = 3;
        } else if ((c & 0xF8) == 0xF0) {
            adv = 4;
        } else {
            // Invalid lead byte; treat as a single byte.
            adv = 1;
        }

        while (adv > 0 && *p) {
            p++;
            adv--;
        }
        chars++;
    }
    return (size_t)(p - start);
}

static void trim_ws_span(const char **start, const char **end) {
    while (*start < *end && isspace((unsigned char)**start)) (*start)++;
    while (*end > *start && isspace((unsigned char)*((*end) - 1))) (*end)--;
}

// --------------------------------------------------------------------------
// Description truncation helpers
// --------------------------------------------------------------------------

static bool in_url(const char *s, size_t pos) {
    if (pos < 3) return false;
    for (size_t i = pos; i-- > 2; ) {
        if (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') return false;
        if (s[i] == ':' && s[i+1] == '/' && s[i+2] == '/') return true;
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
    if (end == len && utf8_strlen(desc) > SHORT_DESC_MAX_LEN) {
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
    bool error;
} StringTable;

static bool strtab_grow_arrays(StringTable *st, size_t new_cap) {
    if (st->error) return false;
    if (new_cap < st->capacity) return true;
    char **new_strings = realloc(st->strings, new_cap * sizeof(char *));
    if (!new_strings) {
        fcmp_perror("realloc");
        st->error = true;
        return false;
    }
    st->strings = new_strings;
    uint32_t *new_offsets = realloc(st->offsets, new_cap * sizeof(uint32_t));
    if (!new_offsets) {
        fcmp_perror("realloc");
        st->error = true;
        return false;
    }
    st->offsets = new_offsets;
    st->capacity = new_cap;
    return true;
}

static uint32_t hash_string(const char *s) {
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) ^ (uint8_t)*s++;
    return h ? h : 1;
}

static void strtab_init(StringTable *st) {
    memset(st, 0, sizeof(*st));
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
    if (!st->strings || !st->offsets || !st->data || !st->hash_table) {
        fcmp_perror("malloc");
        st->error = true;
        free(st->strings);
        free(st->offsets);
        free(st->data);
        free(st->hash_table);
        st->strings = NULL;
        st->offsets = NULL;
        st->data = NULL;
        st->hash_table = NULL;
        st->capacity = 0;
        st->data_cap = 0;
        st->hash_cap = 0;
        return;
    }
    st->strings[0] = strdup("");
    if (!st->strings[0]) {
        fcmp_perror("strdup");
        st->error = true;
        return;
    }
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
    if (st->strings) {
        for (size_t i = 0; i < st->count; i++) free(st->strings[i]);
    }
    free(st->strings);
    free(st->offsets);
    free(st->data);
    free(st->hash_table);
}

static void strtab_grow_hash(StringTable *st) {
    if (st->error) return;
    size_t old_cap = st->hash_cap;
    HashEntry *old_table = st->hash_table;
    st->hash_cap *= 2;
    st->hash_table = calloc(st->hash_cap, sizeof(HashEntry));
    if (!st->hash_table) {
        fcmp_perror("calloc");
        st->hash_table = old_table;
        st->hash_cap = old_cap;
        st->error = true;
        return;
    }
    for (size_t i = 0; i < old_cap; i++) {
        if (old_table[i].hash) {
            size_t idx = old_table[i].hash & (st->hash_cap - 1);
            while (st->hash_table[idx].hash) idx = (idx + 1) & (st->hash_cap - 1);
            st->hash_table[idx] = old_table[i];
        }
    }
    free(old_table);
}

// Write VLQ-encoded string to data buffer, store in string array.
// Returns data offset, or 0 on error (with st->error set).
static uint32_t strtab_write_entry(StringTable *st, const char *s) {
    size_t len = strlen(s);
    if (len > st->max_str_len) st->max_str_len = len;
    if (len > VLQ_MAX_LENGTH) {
        fcmp_errorf("String too long: %zu bytes\n", len);
        st->error = true;
        return 0;
    }
    // strdup before writing to data buffer so failure doesn't leave orphaned data
    char *copy = strdup(s);
    if (!copy) {
        fcmp_perror("strdup");
        st->error = true;
        return 0;
    }
    size_t vlq_len = (len < 128) ? 1 : 2;
    size_t total = vlq_len + len;
    while (st->data_len + total > st->data_cap) {
        st->data_cap *= 2;
        uint8_t *new_data = realloc(st->data, st->data_cap);
        if (!new_data) {
            fcmp_perror("realloc");
            free(copy);
            st->error = true;
            return 0;
        }
        st->data = new_data;
    }
    uint32_t offset = (uint32_t)st->data_len;
    if (len < 128) {
        st->data[st->data_len++] = (uint8_t)len;
    } else {
        st->data[st->data_len++] = 0x80 | (uint8_t)(len >> 8);
        st->data[st->data_len++] = (uint8_t)(len & 0xff);
    }
    memcpy(st->data + st->data_len, s, len);
    st->data_len += len;
    st->strings[st->count] = copy;
    st->offsets[st->count] = offset;
    st->count++;
    return offset;
}

static uint32_t strtab_add(StringTable *st, const char *s) {
    if (st->error) return 0;
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
        size_t new_cap = st->capacity ? st->capacity * 2 : 1024;
        if (!strtab_grow_arrays(st, new_cap)) return 0;
    }
    if (st->count * 2 >= st->hash_cap) {
        strtab_grow_hash(st);
        if (st->error) return 0;
        idx = h & (st->hash_cap - 1);
        while (st->hash_table[idx].hash) idx = (idx + 1) & (st->hash_cap - 1);
    }
    uint32_t str_idx = (uint32_t)st->count;
    uint32_t offset = strtab_write_entry(st, s);
    if (st->error) return 0;
    st->hash_table[idx].hash = h;
    st->hash_table[idx].idx = str_idx;
    return offset;
}

// Add string without deduplication (for subtree clustering of command names)
static uint32_t strtab_add_nodupe(StringTable *st, const char *s) {
    if (st->error) return 0;
    if (!s) s = "";
    if (st->count >= st->capacity) {
        size_t new_cap = st->capacity ? st->capacity * 2 : 1024;
        if (!strtab_grow_arrays(st, new_cap)) return 0;
    }
    return strtab_write_entry(st, s);
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
    uint32_t value_ref;
    uint8_t value_kind;
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
    uint32_t *choices_hash_idx;   // hash -> index mapping for dedup
    size_t choices_hash_cap;
    uint32_t *members_hash_idx;
    size_t members_hash_cap;
    size_t max_command_path_len;
    uint32_t max_completer_tokens;
    DescriptionMode desc_mode;
    size_t desc_max_len;
    bool has_any_descriptions;
    bool error;
} BlobGen;

static inline bool blobgen_strtab_error(const BlobGen *bg) {
    return bg->cmd_strtab.error || bg->param_strtab.error || bg->choice_strtab.error || bg->desc_strtab.error;
}

static void blobgen_init(BlobGen *bg, DescriptionMode desc_mode, size_t desc_max_len) {
    memset(bg, 0, sizeof(*bg));
    bg->error = false;
    strtab_init(&bg->cmd_strtab);
    strtab_init(&bg->param_strtab);
    strtab_init(&bg->choice_strtab);
    strtab_init(&bg->desc_strtab);
    if (bg->cmd_strtab.error || bg->param_strtab.error || bg->choice_strtab.error || bg->desc_strtab.error) {
        bg->error = true;
        return;
    }
    bg->params_cap = 1024;
    bg->params = calloc(bg->params_cap, sizeof(ParamEntry));
    bg->commands_cap = 1024;
    bg->commands = calloc(bg->commands_cap, sizeof(CommandEntry));
    bg->choices_cap = 256;
    bg->choices_lists = calloc(bg->choices_cap, sizeof(StringList));
    bg->members_cap = 256;
    bg->members_lists = calloc(bg->members_cap, sizeof(StringList));
    bg->choices_hash_cap = 512;
    bg->choices_hash_idx = malloc(bg->choices_hash_cap * sizeof(uint32_t));
    if (bg->choices_hash_idx) memset(bg->choices_hash_idx, 0xFF, bg->choices_hash_cap * sizeof(uint32_t));
    bg->members_hash_cap = 512;
    bg->members_hash_idx = malloc(bg->members_hash_cap * sizeof(uint32_t));
    if (bg->members_hash_idx) memset(bg->members_hash_idx, 0xFF, bg->members_hash_cap * sizeof(uint32_t));
    if (!bg->params || !bg->commands || !bg->choices_lists || !bg->members_lists ||
        !bg->choices_hash_idx || !bg->members_hash_idx) {
        fcmp_perror("calloc");
        bg->error = true;
    }
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
    free(bg->choices_hash_idx);
    free(bg->members_hash_idx);
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

static bool buf_append(char **buf, size_t *len, size_t *cap, char c) {
    if (*len + 1 >= *cap) {
        size_t next = (*cap > 0) ? (*cap * 2) : 64;
        char *tmp = realloc(*buf, next);
        if (!tmp) {
            fcmp_perror("realloc");
            return false;
        }
        *buf = tmp;
        *cap = next;
    }
    (*buf)[(*len)++] = c;
    return true;
}

static bool parse_list_items(const char *input, const char *path, int line_num,
                             char ***out_items, size_t *out_count) {
    size_t cap = 8;
    size_t count = 0;
    char **items = malloc(cap * sizeof(char *));
    if (!items) {
        fcmp_perror("malloc");
        return false;
    }

    size_t buf_cap = strlen(input) + 1;
    char *buf = malloc(buf_cap);
    if (!buf) {
        fcmp_perror("malloc");
        free(items);
        return false;
    }
    size_t len = 0;
    size_t last_keep = 0;
    bool token_started = false;
    bool in_single = false;
    bool in_double = false;
    bool escaped = false;

    for (const char *p = input; ; p++) {
        char c = *p;
        bool at_end = (c == '\0');

        if (!at_end) {
            if (in_single) {
                if (c == '\'') {
                    in_single = false;
                } else {
                    if (!buf_append(&buf, &len, &buf_cap, c)) goto error;
                    last_keep = len;
                    token_started = true;
                }
                continue;
            }
            if (in_double) {
                if (escaped) {
                    char out = c;
                    switch (c) {
                        case 'n': out = '\n'; break;
                        case 'r': out = '\r'; break;
                        case 't': out = '\t'; break;
                        case 'v': out = '\v'; break;
                        case 'b': out = '\b'; break;
                        case 'a': out = '\a'; break;
                        case 'f': out = '\f'; break;
                        case '"': out = '"'; break;
                        case '\\': out = '\\'; break;
                        case 'x':
                            if (isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2])) {
                                int hi = isdigit((unsigned char)p[1]) ? p[1] - '0' : (tolower((unsigned char)p[1]) - 'a' + 10);
                                int lo = isdigit((unsigned char)p[2]) ? p[2] - '0' : (tolower((unsigned char)p[2]) - 'a' + 10);
                                out = (char)((hi << 4) | lo);
                                p += 2;
                            } else {
                                out = 'x';
                            }
                            break;
                        default:
                            out = c;
                            break;
                    }
                    if (!buf_append(&buf, &len, &buf_cap, out)) goto error;
                    last_keep = len;
                    token_started = true;
                    escaped = false;
                    continue;
                }
                if (c == '\\') {
                    escaped = true;
                    continue;
                }
                if (c == '"') {
                    in_double = false;
                    token_started = true;
                    continue;
                }
                if (!buf_append(&buf, &len, &buf_cap, c)) goto error;
                last_keep = len;
                token_started = true;
                continue;
            }

            if (c == '\'') {
                in_single = true;
                token_started = true;
                continue;
            }
            if (c == '"') {
                in_double = true;
                token_started = true;
                continue;
            }
            if (c == '\\' && p[1] != '\0') {
                p++;
                if (!buf_append(&buf, &len, &buf_cap, *p)) goto error;
                last_keep = len;
                token_started = true;
                continue;
            }
            /* No nested delimiter tracking; use quotes for literal braces/parens. */
        }

        if (at_end || c == '|') {
            if (in_single || in_double || escaped) {
                fcmp_errorf("%s:%d: error: unmatched quote in list\n", path, line_num);
                for (size_t i = 0; i < count; i++) free(items[i]);
                free(items);
                free(buf);
                return false;
            }
            if (token_started) {
                size_t out_len = last_keep;
                char *token = malloc(out_len + 1);
                if (!token) {
                    fcmp_perror("malloc");
                    goto error;
                }
                memcpy(token, buf, out_len);
                token[out_len] = '\0';
                if (count >= cap) {
                    cap *= 2;
                    char **next = realloc(items, cap * sizeof(char *));
                    if (!next) {
                        fcmp_perror("realloc");
                        free(token);
                        goto error;
                    }
                    items = next;
                }
                items[count++] = token;
            }
            if (at_end) break;
            len = 0;
            last_keep = 0;
            token_started = false;
            continue;
        }

        if (isspace((unsigned char)c)) {
            if (!token_started && len == 0) {
                continue;  // Leading whitespace
            }
            if (!buf_append(&buf, &len, &buf_cap, c)) goto error;
            continue;
        }

        if (!buf_append(&buf, &len, &buf_cap, c)) goto error;
        last_keep = len;
        token_started = true;
    }

    free(buf);

    if (count == 0) {
        fcmp_errorf("%s:%d: error: list must contain at least one value\n", path, line_num);
        free(items);
        return false;
    }

    *out_items = items;
    *out_count = count;
    return true;

error:
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
    free(buf);
    return false;
}

static uint32_t hash_string_list(const uint32_t *offsets, size_t count) {
    uint32_t h = 5381;
    for (size_t i = 0; i < count; i++) {
        h = ((h << 5) + h) ^ offsets[i];
    }
    return h ? h : 1;
}

static size_t find_existing_list(StringList *lists,
                                 uint32_t *hash_idx, size_t hash_cap,
                                 const uint32_t *offsets, size_t n, uint32_t hash) {
    if (!hash_idx || hash_cap == 0) return (size_t)-1;
    size_t slot = hash & (hash_cap - 1);
    for (size_t probes = 0; probes < hash_cap; probes++) {
        uint32_t idx = hash_idx[slot];
        if (idx == UINT32_MAX) return (size_t)-1;  // empty slot
        StringList *sl = &lists[idx];
        if (sl->hash == hash && sl->count == n &&
            memcmp(sl->offsets, offsets, n * sizeof(uint32_t)) == 0) {
            return idx;
        }
        slot = (slot + 1) & (hash_cap - 1);
    }
    return (size_t)-1;
}

static void list_hash_insert(uint32_t *hash_idx, size_t hash_cap,
                             uint32_t hash, uint32_t index) {
    size_t slot = hash & (hash_cap - 1);
    while (hash_idx[slot] != UINT32_MAX) {
        slot = (slot + 1) & (hash_cap - 1);
    }
    hash_idx[slot] = index;
}

static void list_hash_rebuild(uint32_t **hash_idx, size_t *hash_cap,
                              StringList *lists, size_t count) {
    size_t new_cap = *hash_cap * 2;
    uint32_t *new_idx = malloc(new_cap * sizeof(uint32_t));
    if (!new_idx) { free(*hash_idx); *hash_idx = NULL; *hash_cap = 0; return; }
    memset(new_idx, 0xFF, new_cap * sizeof(uint32_t));
    for (size_t i = 0; i < count; i++) {
        list_hash_insert(new_idx, new_cap, lists[i].hash, (uint32_t)i);
    }
    free(*hash_idx);
    *hash_idx = new_idx;
    *hash_cap = new_cap;
}

// Store a string list with deduplication, return index via out_idx.
// Takes ownership of offsets on success or frees them on error.
static bool store_string_list(BlobGen *bg, uint32_t *offsets, size_t count,
                              StringList **lists, size_t *list_count, size_t *list_cap,
                              uint32_t **hash_idx, size_t *hash_cap,
                              size_t *out_idx) {
    uint32_t hash = hash_string_list(offsets, count);
    size_t existing = find_existing_list(*lists, *hash_idx, *hash_cap,
                                         offsets, count, hash);
    if (existing != (size_t)-1) {
        free(offsets);
        *out_idx = existing;
        return true;
    }

    if (*list_count >= *list_cap) {
        size_t new_cap = *list_cap * 2;
        StringList *next = realloc(*lists, new_cap * sizeof(StringList));
        if (!next) {
            fcmp_perror("realloc");
            free(offsets);
            bg->error = true;
            return false;
        }
        *lists = next;
        *list_cap = new_cap;
    }
    if (*list_count * 10 >= *hash_cap * 7) {
        list_hash_rebuild(hash_idx, hash_cap, *lists, *list_count);
    }
    StringList *sl = &(*lists)[*list_count];
    sl->offsets = offsets;
    sl->count = count;
    sl->hash = hash;
    sl->blob_off = 0;
    if (*hash_idx) {
        list_hash_insert(*hash_idx, *hash_cap, hash, (uint32_t)*list_count);
    }
    *out_idx = (*list_count)++;
    return true;
}

// Add choices from pipe-separated string, return index
static bool add_choices_from_string(BlobGen *bg, const char *choices_str,
                                    const char *path, int line_num, size_t *out_idx) {
    if (!choices_str || !*choices_str) {
        fcmp_errorf("%s:%d: error: choices list is empty\n", path, line_num);
        return false;
    }
    if (bg->error || blobgen_strtab_error(bg)) return false;

    char **items = NULL;
    size_t count = 0;
    if (!parse_list_items(choices_str, path, line_num, &items, &count)) return false;

    uint32_t *offsets = malloc(count * sizeof(uint32_t));
    if (!offsets) {
        fcmp_perror("malloc");
        for (size_t i = 0; i < count; i++) free(items[i]);
        free(items);
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        offsets[i] = strtab_add(&bg->choice_strtab, items[i]);
        free(items[i]);
        if (bg->choice_strtab.error) {
            for (size_t j = i + 1; j < count; j++) free(items[j]);
            free(items);
            free(offsets);
            bg->error = true;
            return false;
        }
    }
    free(items);

    return store_string_list(bg, offsets, count,
                             &bg->choices_lists, &bg->choices_count, &bg->choices_cap,
                             &bg->choices_hash_idx, &bg->choices_hash_cap, out_idx);
}

// Add members from {key1|key2} string, return index
// Add members from already-stripped inner content (without braces)
static bool add_members_from_items(BlobGen *bg, const char *content,
                                   const char *path, int line_num, size_t *out_idx) {
    if (bg->error || blobgen_strtab_error(bg)) return false;

    char *inner = strdup(content);
    if (!inner) {
        fcmp_perror("malloc");
        return false;
    }

    char **items = NULL;
    size_t count = 0;
    bool ok = parse_list_items(inner, path, line_num, &items, &count);
    free(inner);
    if (!ok) return false;

    uint32_t *offsets = malloc(count * sizeof(uint32_t));
    if (!offsets) {
        fcmp_perror("malloc");
        for (size_t i = 0; i < count; i++) free(items[i]);
        free(items);
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        char *item = items[i];
        size_t token_len = strlen(item);
        char with_eq[256];
        char *with_eq_alloc = NULL;
        char *eq_buf = with_eq;
        if (token_len + 2 > sizeof(with_eq)) {
            with_eq_alloc = malloc(token_len + 2);
            if (!with_eq_alloc) {
                fcmp_perror("malloc");
                for (size_t j = i; j < count; j++) free(items[j]);
                free(items);
                free(offsets);
                return false;
            }
            eq_buf = with_eq_alloc;
        }
        memcpy(eq_buf, item, token_len);
        eq_buf[token_len] = '=';
        eq_buf[token_len + 1] = '\0';
        offsets[i] = strtab_add(&bg->choice_strtab, eq_buf);
        free(with_eq_alloc);
        free(item);
        if (bg->choice_strtab.error) {
            for (size_t j = i + 1; j < count; j++) free(items[j]);
            free(items);
            free(offsets);
            bg->error = true;
            return false;
        }
    }
    free(items);

    return store_string_list(bg, offsets, count,
                             &bg->members_lists, &bg->members_count, &bg->members_cap,
                             &bg->members_hash_idx, &bg->members_hash_cap, out_idx);
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
    if (!node) {
        fcmp_perror("calloc");
        return NULL;
    }
    node->name = strdup(name ? name : "");
    if (!node->name) {
        fcmp_perror("strdup");
        free(node);
        return NULL;
    }
    node->children_cap = 8;
    node->children = calloc(node->children_cap, sizeof(CommandNode *));
    if (!node->children) {
        fcmp_perror("calloc");
        free(node->name);
        free(node);
        return NULL;
    }
    node->params_cap = 8;
    node->params = calloc(node->params_cap, sizeof(ParamEntry));
    if (!node->params) {
        fcmp_perror("calloc");
        free(node->children);
        free(node->name);
        free(node);
        return NULL;
    }
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

static size_t node_child_lower_bound(CommandNode *node, const char *name, bool *out_found) {
    size_t lo = 0, hi = node->children_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strcmp(node->children[mid]->name, name);
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    if (out_found) {
        *out_found = (lo < node->children_count && strcmp(node->children[lo]->name, name) == 0);
    }
    return lo;
}

static CommandNode *node_get_or_add_child(CommandNode *node, const char *name) {
    bool found = false;
    size_t idx = node_child_lower_bound(node, name, &found);
    if (found) return node->children[idx];

    if (node->children_count >= node->children_cap) {
        size_t next_cap = node->children_cap ? node->children_cap * 2 : 8;
        CommandNode **next = realloc(node->children, next_cap * sizeof(CommandNode *));
        if (!next) {
            fcmp_perror("realloc");
            return NULL;
        }
        node->children = next;
        node->children_cap = next_cap;
    }
    CommandNode *child = node_create(name);
    if (!child) return NULL;
    if (idx < node->children_count) {
        memmove(&node->children[idx + 1], &node->children[idx],
                (node->children_count - idx) * sizeof(CommandNode *));
    }
    node->children[idx] = child;
    node->children_count++;
    return child;
}

static bool node_add_param(CommandNode *node, ParamEntry *pe) {
    if (node->params_count >= node->params_cap) {
        size_t next_cap = node->params_cap ? node->params_cap * 2 : 8;
        ParamEntry *next = realloc(node->params, next_cap * sizeof(ParamEntry));
        if (!next) {
            fcmp_perror("realloc");
            return false;
        }
        node->params = next;
        node->params_cap = next_cap;
    }
    node->params[node->params_count++] = *pe;
    return true;
}

// Children are kept sorted on insert (binary search + memmove), so no post-pass sort is needed.

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
    if (bg->error || blobgen_strtab_error(bg)) return result;
    if (node->params_count == 0) return result;

    if (node->params_count > 65535) {
        fcmp_errorf("Too many params in one command: %zu (max 65535)\n", node->params_count);
        bg->error = true;
        return result;
    }

    uint32_t start_idx = (uint32_t)bg->params_count;
    for (size_t i = 0; i < node->params_count; i++) {
        if (bg->params_count >= bg->params_cap) {
            bg->params_cap *= 2;
            ParamEntry *next = realloc(bg->params, bg->params_cap * sizeof(ParamEntry));
            if (!next) {
                fcmp_perror("realloc");
                bg->error = true;
                return result;
            }
            bg->params = next;
        }
        bg->params[bg->params_count++] = node->params[i];
    }

    // Params are sorted alphabetically within each depth level, with inheritance order preserved
    // (command's own params first, then parent's, then grandparent's, etc.)
    // Linear search is used in the completer, which is fine for typical param counts
    result.idx = start_idx;
    result.count = (uint16_t)node->params_count;
    return result;
}

static IdxCount collect_commands(BlobGen *bg, CommandNode *node) {
    IdxCount result = {0, 0};
    if (bg->error || blobgen_strtab_error(bg)) return result;
    if (node->children_count == 0) return result;
    if (node->children_count > 65535) {
        fcmp_errorf("Too many subcommands in one command: %zu (max 65535)\n", node->children_count);
        bg->error = true;
        return result;
    }

    typedef struct {
        uint32_t name_off, desc_off, params_idx;
        uint16_t subcommands_idx;
        uint16_t params_count, subcommands_count;
    } ChildData;

    if (node->children_count > SIZE_MAX / sizeof(ChildData)) {
        fcmp_errorf("Too many subcommands (overflow)\n");
        bg->error = true;
        return result;
    }
    ChildData *child_data = malloc(node->children_count * sizeof(ChildData));
    if (!child_data) {
        fcmp_errorf("malloc failed in collect_commands\n");
        bg->error = true;
        return result;
    }

    for (size_t i = 0; i < node->children_count; i++) {
        CommandNode *child = node->children[i];

        // Add name BEFORE recursing (pre-order) for subtree clustering
        child_data[i].name_off = strtab_add_nodupe(&bg->cmd_strtab, child->name);
        if (bg->cmd_strtab.error) {
            bg->error = true;
            free(child_data);
            return result;
        }

        // Recurse into children
        IdxCount sub_result = collect_commands(bg, child);
        if (bg->error || blobgen_strtab_error(bg)) {
            free(child_data);
            return result;
        }
        if (sub_result.idx > UINT16_MAX) {
            fcmp_errorf("subcommand index overflow: %u\n", sub_result.idx);
            bg->error = true;
            free(child_data);
            return result;
        }
        child_data[i].subcommands_idx = (uint16_t)sub_result.idx;
        child_data[i].subcommands_count = sub_result.count;

        // Collect params
        IdxCount params_result = collect_params_from_node(bg, child);
        if (bg->error || blobgen_strtab_error(bg)) {
            free(child_data);
            return result;
        }
        child_data[i].params_idx = params_result.idx;
        child_data[i].params_count = params_result.count;
        child_data[i].desc_off = strtab_add_desc(bg, child->description);
        if (blobgen_strtab_error(bg)) {
            bg->error = true;
            free(child_data);
            return result;
        }
    }

    uint32_t start_idx = (uint32_t)bg->commands_count;
    for (size_t i = 0; i < node->children_count; i++) {
        if (bg->commands_count >= bg->commands_cap) {
            bg->commands_cap *= 2;
            CommandEntry *next = realloc(bg->commands, bg->commands_cap * sizeof(CommandEntry));
            if (!next) {
                fcmp_perror("realloc");
                bg->error = true;
                free(child_data);
                return result;
            }
            bg->commands = next;
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

static void write_u16(uint8_t *buf, uint16_t val) {
    buf[0] = (uint8_t)(val & 0xffu);
    buf[1] = (uint8_t)((val >> 8) & 0xffu);
}

static void write_u32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val & 0xffu);
    buf[1] = (uint8_t)((val >> 8) & 0xffu);
    buf[2] = (uint8_t)((val >> 16) & 0xffu);
    buf[3] = (uint8_t)((val >> 24) & 0xffu);
}

static size_t write_string_list_section(uint8_t *blob, size_t section_off,
                                        StringList *lists, size_t list_count,
                                        uint32_t off_adj) {
    write_u32(blob + section_off, (uint32_t)list_count);
    size_t offset = section_off + 4 + list_count * 4;
    for (size_t i = 0; i < list_count; i++) {
        write_u32(blob + section_off + 4 + i * 4, (uint32_t)(offset - section_off));
        StringList *sl = &lists[i];
        if (sl->count < 255) {
            blob[offset] = (uint8_t)sl->count;
            blob[offset + 1] = 0;
            blob[offset + 2] = 0;
            blob[offset + 3] = 0;
        } else {
            blob[offset] = 0xFF;
            write_u16(blob + offset + 1, (uint16_t)sl->count);
            blob[offset + 3] = 0;
        }
        offset += 4;
        for (size_t j = 0; j < sl->count; j++) {
            uint32_t adj_off = sl->offsets[j] ? sl->offsets[j] + off_adj : 0;
            write_u32(blob + offset, adj_off);
            offset += 4;
        }
    }
    return offset;
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
    TOK_DESC        // # description (rest of line)
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

static bool token_list_init_checked(TokenList *tl) {
    tl->capacity = 8;
    tl->tokens = malloc(tl->capacity * sizeof(Token));
    tl->count = 0;
    return tl->tokens != NULL;
}

static bool token_list_add(TokenList *tl, TokenType type, const char *start, size_t len) {
    if (tl->count >= tl->capacity) {
        tl->capacity *= 2;
        Token *next = realloc(tl->tokens, tl->capacity * sizeof(Token));
        if (!next) return false;
        tl->tokens = next;
    }
    Token *t = &tl->tokens[tl->count];
    t->type = type;
    t->value = malloc(len + 1);
    if (!t->value) return false;
    memcpy(t->value, start, len);
    t->value[len] = '\0';
    tl->count++;
    return true;
}

static void token_list_free(TokenList *tl) {
    for (size_t i = 0; i < tl->count; i++) {
        free(tl->tokens[i].value);
    }
    free(tl->tokens);
}

// Scan past a quote-aware delimited block (for choices/members).
// p points to the first char after the opening delimiter.
// Returns pointer to closing delimiter, or NULL if not found.
static const char *scan_delimited(const char *p, char close) {
    bool in_single = false;
    bool in_double = false;
    bool escaped = false;
    while (*p) {
        char c = *p;
        if (in_single) {
            if (c == '\'') in_single = false;
            p++;
            continue;
        }
        if (in_double) {
            if (escaped) { escaped = false; p++; continue; }
            if (c == '\\') { escaped = true; p++; continue; }
            if (c == '"') { in_double = false; p++; continue; }
            p++;
            continue;
        }
        if (c == '\\' && p[1] != '\0') { p += 2; continue; }
        if (c == '\'') { in_single = true; p++; continue; }
        if (c == '"') { in_double = true; p++; continue; }
        if (c == close) return p;
        p++;
    }
    return NULL;
}

// Tokenize a line in the new schema format
// Returns false on error (unmatched delimiters)
static bool tokenize_line(const char *line, TokenList *tl, const char *path, int line_num) {
    if (!token_list_init_checked(tl)) {
        fcmp_perror("malloc");
        return false;
    }
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
            if (!token_list_add(tl, TOK_DESC, p, len)) {
                fcmp_perror("malloc");
                token_list_free(tl);
                return false;
            }
            break;  // Description consumes rest of line
        }

        // Check for choices: (...)
        if (*p == '(') {
            const char *start = p + 1;
            const char *end = scan_delimited(start, ')');
            if (!end) {
                fcmp_errorf("%s:%d: error: unmatched '(' in choices\n", path, line_num);
                token_list_free(tl);
                return false;
            }
            if (!token_list_add(tl, TOK_CHOICES, start, end - start)) {
                fcmp_perror("malloc");
                token_list_free(tl);
                return false;
            }
            p = end + 1;  // Skip closing )
            continue;
        }

        // Check for members: {...}
        if (*p == '{') {
            const char *start = p + 1;
            const char *end = scan_delimited(start, '}');
            if (!end) {
                fcmp_errorf("%s:%d: error: unmatched '{' in members\n", path, line_num);
                token_list_free(tl);
                return false;
            }
            if (!token_list_add(tl, TOK_MEMBERS, start, end - start)) {
                fcmp_perror("malloc");
                token_list_free(tl);
                return false;
            }
            p = end + 1;  // Skip closing }
            continue;
        }

        // Check for completer: `...` (supports escaping \` inside)
        if (*p == '`') {
            p++;  // Skip opening `
            size_t cap = strlen(p) + 1;
            char *buf = malloc(cap);
            if (!buf) {
                fcmp_perror("malloc");
                token_list_free(tl);
                return false;
            }
            size_t len = 0;
            bool escaped = false;
            while (*p) {
                if (!escaped && *p == '`') break;
                if (escaped) {
                    if (*p == '`') {
                        buf[len++] = '`';
                    } else {
                        buf[len++] = '\\';
                        buf[len++] = *p;
                    }
                    escaped = false;
                    p++;
                    continue;
                }
                if (*p == '\\') {
                    escaped = true;
                    p++;
                    continue;
                }
                buf[len++] = *p++;
            }
            if (*p != '`' || escaped) {
                fcmp_errorf("%s:%d: error: unmatched '`' in completer\n", path, line_num);
                free(buf);
                token_list_free(tl);
                return false;
            }
            buf[len] = '\0';
            const char *start = buf;
            const char *end = buf + len;
            trim_ws_span(&start, &end);
            if (!token_list_add(tl, TOK_COMPLETER, start, (size_t)(end - start))) {
                fcmp_perror("malloc");
                free(buf);
                token_list_free(tl);
                return false;
            }
            free(buf);
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
                if (!token_list_add(tl, TOK_BOOL, "bool", 4)) {
                    fcmp_perror("malloc");
                    token_list_free(tl);
                    return false;
                }
            } else {
                // Unknown @ keyword, treat as word
                if (!token_list_add(tl, TOK_WORD, start, len)) {
                    fcmp_perror("malloc");
                    token_list_free(tl);
                    return false;
                }
            }
            continue;
        }

        // Regular word (until whitespace or # or special delimiter)
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '#' && *p != '(' && *p != '{' && *p != '`') p++;
        if (p > start) {
            if (!token_list_add(tl, TOK_WORD, start, p - start)) {
                fcmp_perror("malloc");
                token_list_free(tl);
                return false;
            }
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

static uint32_t count_completer_tokens_u32(const char *s) {
    if (!s || !*s) return 0;
    uint32_t count = 0;
    const char *p = s;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (count == UINT32_MAX) return UINT32_MAX;
        count++;

        while (*p && *p != ' ' && *p != '\t') {
            if (*p == '\'') {
                p++;
                while (*p && *p != '\'') p++;
                if (*p == '\'') p++;
                continue;
            }
            if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && p[1] != '\0') {
                        p += 2;
                        continue;
                    }
                    p++;
                }
                if (*p == '"') p++;
                continue;
            }
            if (*p == '\\' && p[1] != '\0') {
                p += 2;
                continue;
            }
            p++;
        }
    }
    return count;
}

// Parse option spec and extract long/short options
// Format: --long|-s, --long, -s, --long|--alias, etc.
// Aliases separated by |, first of each type (short=2 chars, long=other) used
static bool parse_option_spec(const char *spec, char **long_opt, char **short_opt, const char **err_msg) {
    static char long_buf[256];
    static char short_buf[8];
    *long_opt = NULL;
    *short_opt = NULL;
    if (err_msg) *err_msg = NULL;

    char *copy = strdup(spec);
    if (!copy) {
        if (err_msg) *err_msg = "out of memory";
        return false;
    }
    char *saveptr;
    char *token = fcmp_strtok_r(copy, "|", &saveptr);
    while (token) {
        size_t len = strlen(token);
        if (len >= 2 && token[0] == '-') {
            if (len == 2) {
                // Short option: exactly 2 chars like -s
                if (len >= sizeof(short_buf)) {
                    if (err_msg) *err_msg = "short option too long";
                    free(copy);
                    return false;
                }
                if (!*short_opt) {
                    strcpy(short_buf, token);
                    *short_opt = short_buf;
                }
            } else {
                // Long option: -foo, --foo, or longer
                if (len >= sizeof(long_buf)) {
                    if (err_msg) *err_msg = "long option too long";
                    free(copy);
                    return false;
                }
                if (!*long_opt) {
                    strcpy(long_buf, token);
                    *long_opt = long_buf;
                }
            }
        }
        token = fcmp_strtok_r(NULL, "|", &saveptr);
    }
    free(copy);
    return true;
}

// Parse param line in new format:
//   --long-option|-s @bool # description
//   --long-option|-s (choice1|choice2) # description
//   --long-option {key1|key2} # description
//   --long-option `completer` # description
//
// Tokens: option_spec [@bool | (choices) | {members} | `completer`] [# description]
static bool parse_param_line(BlobGen *bg, const char *line, CommandNode *current_cmd, const char *path, int line_num) {
    if (bg->error || blobgen_strtab_error(bg)) return false;

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
    const char *opt_err = NULL;
    if (!parse_option_spec(tl.tokens[0].value, &long_opt, &short_opt, &opt_err)) {
        fcmp_errorf("%s:%d: error: %s in option spec '%s'\n",
                path, line_num, opt_err ? opt_err : "invalid option", tl.tokens[0].value);
        token_list_free(&tl);
        return false;
    }
    if (!long_opt && !short_opt) {
        fcmp_errorf("%s:%d: error: invalid option spec '%s'\n", path, line_num, tl.tokens[0].value);
        token_list_free(&tl);
        return false;
    }

    ParamEntry pe;
    pe.name_off = long_opt ? strtab_add(&bg->param_strtab, long_opt) : 0;
    pe.short_off = short_opt ? strtab_add(&bg->param_strtab, short_opt) : 0;
    pe.desc_off = 0;
    pe.value_ref = 0;
    pe.value_kind = VALUE_KIND_NONE;
    pe.flags = 0;
    if (blobgen_strtab_error(bg)) {
        bg->error = true;
        token_list_free(&tl);
        return false;
    }

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
                size_t idx = (size_t)-1;
                if (!add_choices_from_string(bg, t->value, path, line_num, &idx)) {
                    token_list_free(&tl);
                    return false;
                }
                pe.value_ref = (uint32_t)idx;
                pe.value_kind = VALUE_KIND_CHOICES;
                pe.flags |= FLAG_TAKES_VALUE;
                has_type = true;
                break;
            }
            case TOK_MEMBERS: {
                size_t idx = (size_t)-1;
                if (!add_members_from_items(bg, t->value, path, line_num, &idx)) {
                    token_list_free(&tl);
                    return false;
                }
                pe.value_ref = (uint32_t)idx;
                pe.value_kind = VALUE_KIND_MEMBERS;
                pe.flags |= FLAG_TAKES_VALUE;
                has_type = true;
                break;
            }
            case TOK_COMPLETER:
                {
                    uint32_t tok_count = count_completer_tokens_u32(t->value);
                    if (tok_count > UINT16_MAX) {
                        fcmp_errorf("%s:%d: error: completer has too many arguments (%u > %u)\n",
                                   path, line_num, tok_count, (unsigned)UINT16_MAX);
                        token_list_free(&tl);
                        return false;
                    }
                    if (tok_count > bg->max_completer_tokens) bg->max_completer_tokens = tok_count;
                }
                pe.value_ref = strtab_add(&bg->choice_strtab, t->value);
                pe.value_kind = VALUE_KIND_COMPLETER;
                pe.flags |= FLAG_TAKES_VALUE;
                has_type = true;
                break;
            case TOK_DESC:
                pe.desc_off = strtab_add_desc(bg, t->value);
                break;
            case TOK_WORD:
                // Ignore unknown words
                break;
        }
    }

    // Validation: @bool cannot combine with choices/members/completer
    if (is_bool && (pe.flags & FLAG_TAKES_VALUE)) {
        fcmp_warnf("%s:%d: warning: @bool cannot combine with choices/members/completer; ignoring type specifier\n",
                path, line_num);
        pe.flags &= ~FLAG_TAKES_VALUE;
        pe.value_ref = 0;
        pe.value_kind = VALUE_KIND_NONE;
    }

    // If no type specified and not bool, default to takes value
    if (!is_bool && !has_type) {
        pe.flags |= FLAG_TAKES_VALUE;
    }

    if (current_cmd) {
        if (!node_add_param(current_cmd, &pe)) {
            bg->error = true;
            token_list_free(&tl);
            return false;
        }
    }

    token_list_free(&tl);
    return true;
}

// Load file contents
static char *load_file(const char *path) {
    // Use binary mode to avoid newline translation (notably on Windows).
    FILE *f = fopen(path, "rb");
    if (!f) { fcmp_perror(path); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fcmp_perror(path); fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0) { fcmp_perror("ftell"); fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fcmp_perror(path); fclose(f); return NULL; }
    if ((size_t)size > SIZE_MAX - 1) {
        fcmp_errorf("%s: file too large\n", path);
        fclose(f);
        return NULL;
    }
    char *content = malloc((size_t)size + 1);
    if (!content) { fcmp_perror("malloc"); fclose(f); return NULL; }
    size_t nread = fread(content, 1, (size_t)size, f);
    if (nread != (size_t)size) {
        if (ferror(f)) fcmp_perror(path);
        else fcmp_errorf("%s: short read\n", path);
        free(content);
        fclose(f);
        return NULL;
    }
    content[nread] = '\0';
    fclose(f);
    return content;
}

// Main schema parser - indentation-based format
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
            fcmp_errorf("%s:%d: error: leading spaces not allowed, use tabs for indentation\n", path, line_num);
            free(content);
            return false;
        }

        int tabs = count_leading_tabs(line);
        if (tabs >= MAX_DEPTH) {
            fcmp_errorf("%s:%d: error: indentation too deep (max depth %d)\n", path, line_num, MAX_DEPTH - 1);
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
        if (content_start[0] == '-') {
            if (!seen_root) {
                // Parameters before root command are not allowed
                fcmp_errorf("%s:%d: error: parameters must come after the root command; define them on the root command instead\n", path, line_num);
                free(content);
                return false;
            }
            // Param at depth N belongs to command at depth N-1
            // (params are indented one level under their command)
            if (tabs == 0) {
                fcmp_errorf("%s:%d: error: parameter after root command must be indented\n", path, line_num);
                free(content);
                return false;
            }
            if (tabs > current_depth + 1) {
                fcmp_errorf("%s:%d: error: parameter indentation (%d) too deep for current command depth (%d)\n",
                        path, line_num, tabs, current_depth);
                free(content);
                return false;
            }
            CommandNode *target = stack[tabs - 1];
            if (!target) {
                fcmp_errorf("%s:%d: error: no command at depth %d for parameter\n", path, line_num, tabs - 1);
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
            fcmp_errorf("%s:%d: error: unexpected character '%c'; expected command name, parameter (--), or comment (#)\n",
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
                fcmp_errorf("%s:%d: error: first command must be at depth 0 (the root/CLI name)\n", path, line_num);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }
            seen_root = true;
            current_depth = 0;

            // Set root name and description
            free(root->name);
            root->name = strdup(cmd_name);
            if (!root->name) {
                fcmp_perror("strdup");
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }
            if (cmd_desc && *cmd_desc && out_root_desc) {
                *out_root_desc = strdup(cmd_desc);
                if (!*out_root_desc) {
                    fcmp_perror("strdup");
                    token_list_free(&cmd_tl);
                    free(content);
                    return false;
                }
            }
            stack[0] = root;
        } else {
            // Subsequent commands
            // Validation: indentation can only increase by 1
            if (tabs > current_depth + 1) {
                fcmp_errorf("%s:%d: error: indentation increased by more than 1 level (from %d to %d)\n",
                        path, line_num, current_depth, tabs);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }
            if (tabs == 0) {
                fcmp_errorf("%s:%d: error: only one root command allowed; subsequent commands must be indented\n",
                        path, line_num);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }

            current_depth = tabs;

            // Get parent node
            CommandNode *parent = stack[tabs - 1];
            if (!parent) {
                fcmp_errorf("%s:%d: error: no parent command at depth %d\n", path, line_num, tabs - 1);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }

            // Get or create child node
            CommandNode *node = node_get_or_add_child(parent, cmd_name);
            if (!node) {
                fcmp_errorf("%s:%d: error: out of memory\n", path, line_num);
                token_list_free(&cmd_tl);
                free(content);
                return false;
            }
            if (cmd_desc && *cmd_desc) {
                free(node->description);
                node->description = strdup(cmd_desc);
                if (!node->description) {
                    fcmp_perror("strdup");
                    token_list_free(&cmd_tl);
                    free(content);
                    return false;
                }
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
        fcmp_errorf("%s: error: no root command found\n", path);
        free(content);
        return false;
    }

    free(content);

    // Sort params alphabetically within each depth level
    sort_node_params(bg, root);

    if (bg->error || blobgen_strtab_error(bg)) return false;

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
        if (!*line || line[0] == '#' || line[0] == '-') {
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


typedef struct {
    uint32_t id;
    uint32_t offset;
    uint32_t size;
    uint32_t entry_size;
    uint32_t flags;
} SectionEntry;

static bool section_append(SectionEntry *sections, size_t *count, size_t cap, uint32_t id, uint32_t size,
                           uint32_t entry_size, uint32_t flags) {
    if (*count >= cap) return false;
    sections[*count].id = id;
    sections[*count].offset = 0;
    sections[*count].size = size;
    sections[*count].entry_size = entry_size;
    sections[*count].flags = flags;
    (*count)++;
    return true;
}

static void sort_string_lists(StringTable *st, StringList *lists, size_t count) {
    for (size_t i = 0; i < count; i++) {
        StringList *sl = &lists[i];
        for (size_t j = 1; j < sl->count; j++) {
            uint32_t key = sl->offsets[j];
            size_t k = j;
            while (k > 0 && strtab_cmp(st, sl->offsets[k - 1], key) > 0) {
                sl->offsets[k] = sl->offsets[k - 1];
                k--;
            }
            sl->offsets[k] = key;
        }
    }
}

bool generate_blob(const char *schema_path, const char *output_path, DescriptionMode desc_mode, size_t desc_max_len) {
    bool result = false;
    BlobGen bg;
    blobgen_init(&bg, desc_mode, desc_max_len);
    if (bg.error) return false;

    CommandNode *root = node_create("");
    if (!root) return false;
    char *root_desc = NULL;
    uint32_t cli_name_off = 0;
    uint32_t *parent_ref = NULL;
    uint32_t *own_params_idx = NULL;
    uint32_t *own_params_count = NULL;
    Slice32 *long_slices = NULL;
    Slice32 *short_slices = NULL;
    LongIndexEntry *long_entries = NULL;
    ShortIndexEntry *short_entries = NULL;
    uint8_t *blob = NULL;
    FILE *out = NULL;

    if (!parse_tsv_schema(schema_path, &bg, root, &root_desc)) {
        goto cleanup;
    }
    if (blobgen_strtab_error(&bg)) {
        goto cleanup;
    }

    // Store the schema root/CLI name in the blob header (used to validate runtime calls and
    // to constrain dynamic completer execution).
    if (root->name && root->name[0]) {
        cli_name_off = strtab_add(&bg.cmd_strtab, root->name);
        if (cli_name_off == 0) {
            fcmp_errorf("Failed to store CLI name in string table\n");
            goto cleanup;
        }
    } else {
        fcmp_errorf("%s: error: root command name missing\n", schema_path);
        goto cleanup;
    }
    if (blobgen_strtab_error(&bg)) {
        goto cleanup;
    }

    IdxCount top_level = collect_commands(&bg, root);

    // Collect root's own params (these inherit to all children, so they're the "global" params)
    IdxCount root_params = collect_params_from_node(&bg, root);

    if (bg.error || blobgen_strtab_error(&bg)) {
        goto cleanup;
    }

    bool has_desc_section = (desc_mode != DESC_NONE && bg.has_any_descriptions);

    // Root description (cold strings section only, and only when descriptions are enabled)
    uint32_t root_desc_off = 0;
    if (has_desc_section) {
        root_desc_off = strtab_add_desc_ex(&bg, root_desc ? root_desc : "CLI", false);
        if (blobgen_strtab_error(&bg)) {
            goto cleanup;
        }
    }

    // Check for integer overflow in counts
    if (bg.commands_count > 65535) {
        fcmp_errorf("Too many commands: %zu (max 65535)\n", bg.commands_count);
        goto cleanup;
    }
    if (bg.params_count > 16777215) {
        fcmp_errorf("Too many params: %zu (max 16777215)\n", bg.params_count);
        goto cleanup;
    }
    if (bg.max_completer_tokens > UINT16_MAX) {
        fcmp_errorf("Max completer args too large: %u (max %u)\n",
                    bg.max_completer_tokens, (unsigned)UINT16_MAX);
        goto cleanup;
    }

    // Hot strings layout: [commands][params][choices]
    size_t cmd_len = bg.cmd_strtab.data_len;
    size_t param_len = bg.param_strtab.data_len;
    size_t choice_len = bg.choice_strtab.data_len;
    size_t hot_len = cmd_len + param_len + choice_len;
    size_t desc_len = has_desc_section ? bg.desc_strtab.data_len : 0;
    if (hot_len > UINT32_MAX || desc_len > UINT32_MAX) {
        fcmp_errorf("String section too large (max 4GB)\n");
        goto cleanup;
    }
    // Offset adjustments within hot strings section
    uint32_t param_off_adj = (uint32_t)cmd_len;
    uint32_t choice_off_adj = (uint32_t)(cmd_len + param_len);

    size_t commands_size = bg.commands_count * COMMAND_SIZE;
    size_t params_size = bg.params_count * PARAM_SIZE;

    // Sort choices and members lists for binary search at runtime
    sort_string_lists(&bg.choice_strtab, bg.choices_lists, bg.choices_count);
    sort_string_lists(&bg.choice_strtab, bg.members_lists, bg.members_count);

    // Choices/members section layout:
    // u32 list_count + list_count*u32 list_offsets + list payloads
    size_t choices_payload_size = 0;
    for (size_t i = 0; i < bg.choices_count; i++) {
        size_t count = bg.choices_lists[i].count;
        if (count > 65535) {
            fcmp_errorf("Choice list %zu too large: %zu items (max 65535)\n", i, count);
            goto cleanup;
        }
        if (count > (SIZE_MAX - 4) / 4) {
            fcmp_errorf("Choice list %zu too large (overflow)\n", i);
            goto cleanup;
        }
        if (choices_payload_size > SIZE_MAX - (4 + count * 4)) {
            fcmp_errorf("Choices section too large (overflow)\n");
            goto cleanup;
        }
        choices_payload_size += 4 + count * 4;
    }
    size_t choices_size = 4 + bg.choices_count * 4 + choices_payload_size;

    size_t members_payload_size = 0;
    for (size_t i = 0; i < bg.members_count; i++) {
        size_t count = bg.members_lists[i].count;
        if (count > 65535) {
            fcmp_errorf("Member list %zu too large: %zu items (max 65535)\n", i, count);
            goto cleanup;
        }
        if (count > (SIZE_MAX - 4) / 4) {
            fcmp_errorf("Member list %zu too large (overflow)\n", i);
            goto cleanup;
        }
        if (members_payload_size > SIZE_MAX - (4 + count * 4)) {
            fcmp_errorf("Members section too large (overflow)\n");
            goto cleanup;
        }
        members_payload_size += 4 + count * 4;
    }
    size_t members_size = 4 + bg.members_count * 4 + members_payload_size;

    // Build parent links and per-command option indices (root + each command)
    size_t cmd_ref_count = bg.commands_count + 1;
    if (cmd_ref_count > UINT32_MAX) {
        fcmp_errorf("Too many command refs: %zu\n", cmd_ref_count);
        goto cleanup;
    }
    parent_ref = malloc(cmd_ref_count * sizeof(uint32_t));
    own_params_idx = malloc(cmd_ref_count * sizeof(uint32_t));
    own_params_count = malloc(cmd_ref_count * sizeof(uint32_t));
    long_slices = calloc(cmd_ref_count, sizeof(Slice32));
    short_slices = calloc(cmd_ref_count, sizeof(Slice32));
    if (!parent_ref || !own_params_idx || !own_params_count || !long_slices || !short_slices) {
        fcmp_perror("malloc");
        goto cleanup;
    }

    own_params_idx[0] = root_params.idx;
    own_params_count[0] = root_params.count;
    parent_ref[0] = UINT32_MAX;
    for (size_t i = 0; i < bg.commands_count; i++) {
        own_params_idx[i + 1] = bg.commands[i].params_idx;
        own_params_count[i + 1] = bg.commands[i].params_count;
        parent_ref[i + 1] = UINT32_MAX;
    }
    for (uint32_t i = 0; i < top_level.count; i++) {
        uint32_t child = top_level.idx + i;
        if (child >= bg.commands_count) continue;
        parent_ref[child + 1] = 0;
    }
    for (size_t i = 0; i < bg.commands_count; i++) {
        CommandEntry *ce = &bg.commands[i];
        for (uint32_t j = 0; j < ce->subcommands_count; j++) {
            uint32_t child = ce->subcommands_idx + j;
            if (child >= bg.commands_count) {
                fcmp_errorf("Internal error: subcommand index out of range\n");
                goto cleanup;
            }
            parent_ref[child + 1] = (uint32_t)i + 1;
        }
    }
    for (size_t i = 1; i < cmd_ref_count; i++) {
        if (parent_ref[i] == UINT32_MAX) {
            fcmp_errorf("Internal error: unresolved parent for command %zu\n", i - 1);
            goto cleanup;
        }
    }

    // Build per-command long/short option indices from inherited params.
    size_t long_total = 0, long_cap = 0;
    size_t short_total = 0, short_cap = 0;

    for (size_t ref = 0; ref < cmd_ref_count; ref++) {
        long_slices[ref].start = (uint32_t)long_total;
        short_slices[ref].start = (uint32_t)short_total;

        // Build the chain from current command to root so we can walk root->...->current.
        uint32_t chain_buf[128];
        uint32_t *chain = chain_buf;
        size_t chain_len = 0;
        size_t chain_cap = sizeof(chain_buf) / sizeof(chain_buf[0]);
        uint32_t cur = (uint32_t)ref;
        while (1) {
            if (chain_len == chain_cap) {
                size_t next_cap = chain_cap * 2;
                uint32_t *tmp = malloc(next_cap * sizeof(uint32_t));
                if (!tmp) {
                    fcmp_perror("malloc");
                    if (chain != chain_buf) free(chain);
                    goto cleanup;
                }
                memcpy(tmp, chain, chain_len * sizeof(uint32_t));
                if (chain != chain_buf) free(chain);
                chain = tmp;
                chain_cap = next_cap;
            }
            chain[chain_len++] = cur;
            if (cur == 0) break;
            cur = parent_ref[cur];
            if (chain_len > cmd_ref_count) {
                fcmp_errorf("Internal error: cycle in command parent map\n");
                if (chain != chain_buf) free(chain);
                goto cleanup;
            }
        }

        size_t inherited_count = 0;
        for (size_t i = 0; i < chain_len; i++) {
            inherited_count += own_params_count[chain[i]];
        }
        // Hash set for long option dedup (open addressing, 0 = empty sentinel).
        // name_off is always > 0 for real params (checked by `if (pe->name_off)`).
        size_t seen_cap = 16;
        while (seen_cap < inherited_count * 2) seen_cap *= 2;
        uint32_t *seen_long = calloc(seen_cap, sizeof(uint32_t));
        if (!seen_long) {
            fcmp_perror("calloc");
            if (chain != chain_buf) free(chain);
            goto cleanup;
        }
        size_t seen_mask = seen_cap - 1;
        bool seen_short[256] = {0};

        // Iterate root->...->current so closer commands override inherited options.
        for (size_t ci = chain_len; ci > 0; ci--) {
            uint32_t node_ref = chain[ci - 1];
            uint32_t base = own_params_idx[node_ref];
            uint32_t cnt = own_params_count[node_ref];
            for (uint32_t i = 0; i < cnt; i++) {
                uint32_t param_idx = base + i;
                if (param_idx >= bg.params_count) continue;
                ParamEntry *pe = &bg.params[param_idx];

                if (pe->name_off) {
                    // Hash set lookup/insert for long option dedup
                    size_t slot = pe->name_off & seen_mask;
                    while (seen_long[slot] && seen_long[slot] != pe->name_off)
                        slot = (slot + 1) & seen_mask;
                    bool exists = (seen_long[slot] != 0);
                    if (!exists) {
                        seen_long[slot] = pe->name_off;
                        if (long_total >= long_cap) {
                            size_t next = long_cap ? long_cap * 2 : 1024;
                            LongIndexEntry *tmp = realloc(long_entries, next * sizeof(LongIndexEntry));
                            if (!tmp) {
                                fcmp_perror("realloc");
                                free(seen_long);
                                if (chain != chain_buf) free(chain);
                                goto cleanup;
                            }
                            long_entries = tmp;
                            long_cap = next;
                        }
                        long_entries[long_total].param_idx = param_idx;
                        long_total++;
                    }
                }

                if (pe->short_off) {
                    const uint8_t *sp = bg.param_strtab.data + pe->short_off;
                    size_t slen = (sp[0] < 128) ? sp[0] : (((sp[0] & 0x7f) << 8) | sp[1]);
                    const char *ss = (const char *)(sp + (sp[0] < 128 ? 1 : 2));
                    if (slen >= 2 && ss[0] == '-') {
                        uint8_t ch = (uint8_t)ss[1];
                        if (!seen_short[ch]) {
                            seen_short[ch] = true;
                            if (short_total >= short_cap) {
                                size_t next = short_cap ? short_cap * 2 : 1024;
                                ShortIndexEntry *tmp = realloc(short_entries, next * sizeof(ShortIndexEntry));
                                if (!tmp) {
                                    fcmp_perror("realloc");
                                    free(seen_long);
                                    if (chain != chain_buf) free(chain);
                                    goto cleanup;
                                }
                                short_entries = tmp;
                                short_cap = next;
                            }
                            short_entries[short_total].short_ch = ch;
                            short_entries[short_total]._pad[0] = 0;
                            short_entries[short_total]._pad[1] = 0;
                            short_entries[short_total]._pad[2] = 0;
                            short_entries[short_total].param_idx = param_idx;
                            short_total++;
                        }
                    }
                }
            }
        }

        // Sort long entries for binary prefix search by option name.
        size_t lstart = long_slices[ref].start;
        size_t lcount = long_total - lstart;
        for (size_t i = 1; i < lcount; i++) {
            LongIndexEntry key = long_entries[lstart + i];
            size_t k = i;
            while (k > 0) {
                LongIndexEntry prev = long_entries[lstart + k - 1];
                if (strtab_cmp(&bg.param_strtab,
                               bg.params[prev.param_idx].name_off,
                               bg.params[key.param_idx].name_off) <= 0) break;
                long_entries[lstart + k] = prev;
                k--;
            }
            long_entries[lstart + k] = key;
        }

        // Sort short entries by short char for fast lookup.
        size_t sstart = short_slices[ref].start;
        size_t scount = short_total - sstart;
        for (size_t i = 1; i < scount; i++) {
            ShortIndexEntry key = short_entries[sstart + i];
            size_t k = i;
            while (k > 0 && short_entries[sstart + k - 1].short_ch > key.short_ch) {
                short_entries[sstart + k] = short_entries[sstart + k - 1];
                k--;
            }
            short_entries[sstart + k] = key;
        }

        long_slices[ref].count = (uint32_t)lcount;
        short_slices[ref].count = (uint32_t)scount;
        if (chain != chain_buf) free(chain);
        free(seen_long);
    }

    size_t option_long_size = 8 + cmd_ref_count * sizeof(Slice32) + long_total * sizeof(uint32_t);
    size_t option_short_size = short_total > 0
        ? (8 + cmd_ref_count * sizeof(Slice32) + short_total * sizeof(ShortIndexEntry))
        : 0;
    if (commands_size > UINT32_MAX || params_size > UINT32_MAX ||
        choices_size > UINT32_MAX || members_size > UINT32_MAX ||
        option_long_size > UINT32_MAX ||
        option_short_size > UINT32_MAX) {
        fcmp_errorf("Blob section too large (max 4GB per section)\n");
        goto cleanup;
    }

    // Build section list and offsets.
    SectionEntry sections[10];
    size_t section_count = 0;
    if (!section_append(sections, &section_count, 10, SECTION_STRINGS_HOT, (uint32_t)hot_len, 1, 0) ||
        !section_append(sections, &section_count, 10, SECTION_COMMANDS, (uint32_t)commands_size, COMMAND_SIZE, 0) ||
        !section_append(sections, &section_count, 10, SECTION_PARAMS, (uint32_t)params_size, PARAM_SIZE, 0) ||
        !section_append(sections, &section_count, 10, SECTION_CHOICES, (uint32_t)choices_size, 0, 0) ||
        !section_append(sections, &section_count, 10, SECTION_MEMBERS, (uint32_t)members_size, 0, 0) ||
        !section_append(sections, &section_count, 10, SECTION_ROOT, COMMAND_SIZE, COMMAND_SIZE, 0) ||
        !section_append(sections, &section_count, 10, SECTION_OPTION_LONG, (uint32_t)option_long_size, 0, 0)) {
        fcmp_errorf("Internal error: section append failed\n");
        goto cleanup;
    }
    if (short_total > 0) {
        if (!section_append(sections, &section_count, 10, SECTION_OPTION_SHORT, (uint32_t)option_short_size, 0, 0)) {
            fcmp_errorf("Internal error: section append failed\n");
            goto cleanup;
        }
    }
    if (has_desc_section) {
        if (!section_append(sections, &section_count, 10, SECTION_STRINGS_COLD, (uint32_t)desc_len, 1, SECTION_FLAG_OPTIONAL)) {
            fcmp_errorf("Internal error: section append failed\n");
            goto cleanup;
        }
    }

    size_t section_dir_off = HEADER_SIZE;
    size_t section_dir_size = section_count * SECTION_ENTRY_SIZE;
    size_t data_off = align4(section_dir_off + section_dir_size);
    for (size_t i = 0; i < section_count; i++) {
        data_off = align4(data_off);
        sections[i].offset = (uint32_t)data_off;
        data_off += sections[i].size;
    }
    size_t total_size = align4(data_off);
    if (total_size > UINT32_MAX) {
        fcmp_errorf("Blob too large: %zu bytes (max 4GB)\n", total_size);
        goto cleanup;
    }

    blob = calloc(1, total_size);
    if (!blob) {
        fcmp_perror("calloc");
        goto cleanup;
    }

    memcpy(blob, BLOB_MAGIC, 4);
    write_u16(blob + 4, BLOB_VERSION);
    uint16_t flags = 0;
    if (!has_desc_section) flags |= HEADER_FLAG_NO_DESCRIPTIONS;
    write_u16(blob + 6, flags);
    write_u16(blob + 8, (uint16_t)section_count);
    write_u16(blob + 10, 0);
    write_u32(blob + 12, (uint32_t)section_dir_off);
    write_u32(blob + 16, (uint32_t)bg.commands_count);
    write_u32(blob + 20, (uint32_t)bg.params_count);
    write_u32(blob + 24, cli_name_off);
    write_u32(blob + 28, (uint32_t)bg.max_command_path_len + 1);
    write_u32(blob + 32, bg.max_completer_tokens);

    // Write section directory.
    size_t dir_pos = section_dir_off;
    for (size_t i = 0; i < section_count; i++) {
        write_u32(blob + dir_pos, sections[i].id);
        write_u32(blob + dir_pos + 4, sections[i].offset);
        write_u32(blob + dir_pos + 8, sections[i].size);
        write_u32(blob + dir_pos + 12, sections[i].entry_size);
        write_u32(blob + dir_pos + 16, sections[i].flags);
        dir_pos += SECTION_ENTRY_SIZE;
    }

    uint32_t off_hot = 0, off_cold = 0, off_cmd = 0, off_params = 0, off_choices = 0, off_members = 0;
    uint32_t off_root = 0, off_long = 0, off_short = 0;
    for (size_t i = 0; i < section_count; i++) {
        switch (sections[i].id) {
            case SECTION_STRINGS_HOT: off_hot = sections[i].offset; break;
            case SECTION_STRINGS_COLD: off_cold = sections[i].offset; break;
            case SECTION_COMMANDS: off_cmd = sections[i].offset; break;
            case SECTION_PARAMS: off_params = sections[i].offset; break;
            case SECTION_CHOICES: off_choices = sections[i].offset; break;
            case SECTION_MEMBERS: off_members = sections[i].offset; break;
            case SECTION_ROOT: off_root = sections[i].offset; break;
            case SECTION_OPTION_LONG: off_long = sections[i].offset; break;
            case SECTION_OPTION_SHORT: off_short = sections[i].offset; break;
            default: break;
        }
    }

    // Strings
    memcpy(blob + off_hot, bg.cmd_strtab.data, cmd_len);
    memcpy(blob + off_hot + cmd_len, bg.param_strtab.data, param_len);
    memcpy(blob + off_hot + cmd_len + param_len, bg.choice_strtab.data, choice_len);
    if (has_desc_section) memcpy(blob + off_cold, bg.desc_strtab.data, desc_len);

    // Commands
    size_t offset = off_cmd;
    for (size_t i = 0; i < bg.commands_count; i++) {
        CommandEntry *ce = &bg.commands[i];
        uint32_t desc_off = has_desc_section ? ce->desc_off : 0;
        write_u32(blob + offset, ce->name_off);
        write_u32(blob + offset + 4, desc_off);
        write_u32(blob + offset + 8, ce->params_idx);
        write_u16(blob + offset + 12, ce->subcommands_idx);
        write_u16(blob + offset + 14, ce->params_count);
        write_u16(blob + offset + 16, ce->subcommands_count);
        write_u16(blob + offset + 18, 0);
        offset += COMMAND_SIZE;
    }

    // Params
    offset = off_params;
    for (size_t i = 0; i < bg.params_count; i++) {
        ParamEntry *pe = &bg.params[i];
        uint32_t name_off = pe->name_off ? pe->name_off + param_off_adj : 0;
        uint32_t short_off = pe->short_off ? pe->short_off + param_off_adj : 0;
        uint32_t desc_off = has_desc_section ? pe->desc_off : 0;
        uint32_t value_ref = pe->value_ref;
        if (pe->value_kind == VALUE_KIND_COMPLETER && value_ref) value_ref += choice_off_adj;
        write_u32(blob + offset, name_off);
        write_u32(blob + offset + 4, short_off);
        write_u32(blob + offset + 8, desc_off);
        write_u32(blob + offset + 12, value_ref);
        blob[offset + 16] = pe->value_kind;
        blob[offset + 17] = pe->flags;
        blob[offset + 18] = 0;
        blob[offset + 19] = 0;
        offset += PARAM_SIZE;
    }

    // Choices section
    offset = write_string_list_section(blob, off_choices,
                                       bg.choices_lists, bg.choices_count, choice_off_adj);

    // Members section
    offset = write_string_list_section(blob, off_members,
                                       bg.members_lists, bg.members_count, choice_off_adj);

    // Root command
    write_u32(blob + off_root, 0);
    write_u32(blob + off_root + 4, has_desc_section ? root_desc_off : 0);
    write_u32(blob + off_root + 8, root_params.idx);
    write_u16(blob + off_root + 12, top_level.idx);
    write_u16(blob + off_root + 14, root_params.count);
    write_u16(blob + off_root + 16, top_level.count);
    write_u16(blob + off_root + 18, 0);

    // Long index section
    write_u32(blob + off_long, (uint32_t)cmd_ref_count);
    write_u32(blob + off_long + 4, (uint32_t)long_total);
    offset = off_long + 8;
    for (size_t i = 0; i < cmd_ref_count; i++) {
        write_u32(blob + offset, long_slices[i].start);
        write_u32(blob + offset + 4, long_slices[i].count);
        offset += 8;
    }
    for (size_t i = 0; i < long_total; i++) {
        write_u32(blob + offset, long_entries[i].param_idx);
        offset += 4;
    }

    // Short index section
    if (short_total > 0) {
        write_u32(blob + off_short, (uint32_t)cmd_ref_count);
        write_u32(blob + off_short + 4, (uint32_t)short_total);
        offset = off_short + 8;
        for (size_t i = 0; i < cmd_ref_count; i++) {
            write_u32(blob + offset, short_slices[i].start);
            write_u32(blob + offset + 4, short_slices[i].count);
            offset += 8;
        }
        for (size_t i = 0; i < short_total; i++) {
            blob[offset] = short_entries[i].short_ch;
            blob[offset + 1] = 0;
            blob[offset + 2] = 0;
            blob[offset + 3] = 0;
            write_u32(blob + offset + 4, short_entries[i].param_idx);
            offset += 8;
        }
    }

    out = fopen(output_path, "wb");
    if (!out) {
        fcmp_perror(output_path);
        goto cleanup;
    }
    if (fwrite(blob, 1, total_size, out) != total_size) {
        fcmp_perror(output_path);
        goto cleanup;
    }

    fcmp_infof("Generated %s (%zu bytes)\n", output_path, total_size);
    fcmp_infof("  Commands: %zu\n", bg.commands_count);
    fcmp_infof("  Params: %zu\n", bg.params_count);
    fcmp_infof("  Choices lists: %zu\n", bg.choices_count);
    fcmp_infof("  Members lists: %zu\n", bg.members_count);
    fcmp_infof("  Sections: %zu\n", section_count);
    fcmp_infof("  Hot strings: %zu bytes (cmds: %zu, params: %zu, choices: %zu)\n",
            hot_len, cmd_len, param_len, choice_len);
    if (has_desc_section) fcmp_infof("  Cold strings: %zu bytes\n", desc_len);
    fcmp_infof("  Option long index entries: %zu\n", long_total);
    fcmp_infof("  Option short index entries: %zu\n", short_total);
    result = true;

cleanup:
    if (out) fclose(out);
    free(blob);
    free(parent_ref); free(own_params_idx); free(own_params_count);
    free(long_slices); free(short_slices);
    free(long_entries); free(short_entries);
    node_free(root); blobgen_free(&bg); free(root_desc);
    return result;
}

bool lint_schema(const char *schema_path) {
    BlobGen bg;
    blobgen_init(&bg, DESC_SHORT, 0);
    if (bg.error) return false;

    CommandNode *root = node_create("");
    if (!root) {
        blobgen_free(&bg);
        return false;
    }
    char *root_desc = NULL;

    bool ok = parse_tsv_schema(schema_path, &bg, root, &root_desc);
    if (ok && blobgen_strtab_error(&bg)) ok = false;

    node_free(root);
    blobgen_free(&bg);
    free(root_desc);

    return ok;
}
