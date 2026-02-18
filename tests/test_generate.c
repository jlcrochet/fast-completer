/*
 * test_generate.c - Unit tests for generate_blob.c
 *
 * Tests: UTF-8 helpers, description truncation, schema helpers,
 *        blob format, string table, option parsing, tokenizer.
 */

#include "greatest.h"

/* Include the implementation directly to access static functions */
#include "../src/generate_blob.c"

/* ======================================================================
 * suite_utf8 — utf8_strlen, utf8_byte_offset
 * ====================================================================== */

TEST utf8_strlen_ascii(void) {
    ASSERT_EQ(5, utf8_strlen("hello"));
    PASS();
}

TEST utf8_strlen_empty(void) {
    ASSERT_EQ(0, utf8_strlen(""));
    PASS();
}

TEST utf8_strlen_2byte(void) {
    /* "café" = c a f é (4 chars, 5 bytes) */
    ASSERT_EQ(4, utf8_strlen("caf\xc3\xa9"));
    PASS();
}

TEST utf8_strlen_4byte(void) {
    /* U+1F600 = 😀 (1 char, 4 bytes) */
    ASSERT_EQ(1, utf8_strlen("\xf0\x9f\x98\x80"));
    PASS();
}

TEST utf8_strlen_mixed(void) {
    /* "a" + 2-byte + 4-byte = 3 chars */
    ASSERT_EQ(3, utf8_strlen("a\xc3\xa9\xf0\x9f\x98\x80"));
    PASS();
}

TEST utf8_byte_offset_ascii(void) {
    ASSERT_EQ(3, utf8_byte_offset("hello", 3));
    PASS();
}

TEST utf8_byte_offset_2byte(void) {
    /* "café" — offset for 4 chars = 5 bytes */
    ASSERT_EQ(5, utf8_byte_offset("caf\xc3\xa9", 4));
    PASS();
}

TEST utf8_byte_offset_4byte(void) {
    /* 4-byte char + "a" — offset for 1 char = 4 bytes */
    ASSERT_EQ(4, utf8_byte_offset("\xf0\x9f\x98\x80" "a", 1));
    PASS();
}

TEST utf8_byte_offset_zero(void) {
    ASSERT_EQ(0, utf8_byte_offset("hello", 0));
    PASS();
}

TEST utf8_byte_offset_null(void) {
    ASSERT_EQ(0, utf8_byte_offset(NULL, 5));
    PASS();
}

SUITE(suite_utf8) {
    RUN_TEST(utf8_strlen_ascii);
    RUN_TEST(utf8_strlen_empty);
    RUN_TEST(utf8_strlen_2byte);
    RUN_TEST(utf8_strlen_4byte);
    RUN_TEST(utf8_strlen_mixed);
    RUN_TEST(utf8_byte_offset_ascii);
    RUN_TEST(utf8_byte_offset_2byte);
    RUN_TEST(utf8_byte_offset_4byte);
    RUN_TEST(utf8_byte_offset_zero);
    RUN_TEST(utf8_byte_offset_null);
}

/* ======================================================================
 * suite_description — in_url, is_abbreviation, is_version_number,
 *                     truncate_to_first_sentence
 * ====================================================================== */

TEST in_url_positive(void) {
    const char *s = "See https://example.com/path.html for details";
    /* The '.' in "path.html" — should detect URL context */
    size_t dot_pos = (size_t)(strchr(s + 25, '.') - s);
    ASSERT(in_url(s, dot_pos));
    PASS();
}

TEST in_url_negative(void) {
    const char *s = "This is a sentence. Another one.";
    ASSERT_FALSE(in_url(s, 18));
    PASS();
}

TEST in_url_too_short(void) {
    ASSERT_FALSE(in_url("ab", 1));
    PASS();
}

TEST is_abbreviation_eg(void) {
    const char *s = "e.g. something";
    ASSERT(is_abbreviation(s, 3)); /* pos of '.' after "e.g" */
    PASS();
}

TEST is_abbreviation_ie(void) {
    const char *s = "i.e. something";
    ASSERT(is_abbreviation(s, 3));
    PASS();
}

TEST is_abbreviation_etc(void) {
    const char *s = "and etc. more";
    ASSERT(is_abbreviation(s, 7));
    PASS();
}

TEST is_abbreviation_negative(void) {
    const char *s = "the end. next";
    ASSERT_FALSE(is_abbreviation(s, 7));
    PASS();
}

TEST is_version_number_positive(void) {
    const char *s = "version 1.2.3";
    ASSERT(is_version_number(s, 9, strlen(s)));   /* '.' between 1 and 2 */
    ASSERT(is_version_number(s, 11, strlen(s)));  /* '.' between 2 and 3 */
    PASS();
}

TEST is_version_number_negative(void) {
    const char *s = "end. next";
    ASSERT_FALSE(is_version_number(s, 3, strlen(s)));
    PASS();
}

TEST truncate_simple_sentence(void) {
    char *r = truncate_to_first_sentence("First sentence. Second sentence.");
    ASSERT_STR_EQ("First sentence", r);
    free(r);
    PASS();
}

TEST truncate_semicolon(void) {
    char *r = truncate_to_first_sentence("Part one; part two");
    ASSERT_STR_EQ("Part one", r);
    free(r);
    PASS();
}

TEST truncate_colon(void) {
    char *r = truncate_to_first_sentence("Header: details follow");
    ASSERT_STR_EQ("Header", r);
    free(r);
    PASS();
}

TEST truncate_newline(void) {
    char *r = truncate_to_first_sentence("Line one\nLine two");
    ASSERT_STR_EQ("Line one", r);
    free(r);
    PASS();
}

TEST truncate_preserves_abbreviation(void) {
    char *r = truncate_to_first_sentence("Use e.g. this one");
    ASSERT_STR_EQ("Use e.g. this one", r);
    free(r);
    PASS();
}

TEST truncate_preserves_url(void) {
    char *r = truncate_to_first_sentence("See https://example.com/path.html for info");
    ASSERT_STR_EQ("See https://example.com/path.html for info", r);
    free(r);
    PASS();
}

TEST truncate_preserves_version(void) {
    char *r = truncate_to_first_sentence("Requires version 2.1.0 or later");
    ASSERT_STR_EQ("Requires version 2.1.0 or later", r);
    free(r);
    PASS();
}

TEST truncate_empty(void) {
    char *r = truncate_to_first_sentence("");
    ASSERT_STR_EQ("", r);
    free(r);
    PASS();
}

TEST truncate_null(void) {
    char *r = truncate_to_first_sentence(NULL);
    ASSERT_STR_EQ("", r);
    free(r);
    PASS();
}

SUITE(suite_description) {
    RUN_TEST(in_url_positive);
    RUN_TEST(in_url_negative);
    RUN_TEST(in_url_too_short);
    RUN_TEST(is_abbreviation_eg);
    RUN_TEST(is_abbreviation_ie);
    RUN_TEST(is_abbreviation_etc);
    RUN_TEST(is_abbreviation_negative);
    RUN_TEST(is_version_number_positive);
    RUN_TEST(is_version_number_negative);
    RUN_TEST(truncate_simple_sentence);
    RUN_TEST(truncate_semicolon);
    RUN_TEST(truncate_colon);
    RUN_TEST(truncate_newline);
    RUN_TEST(truncate_preserves_abbreviation);
    RUN_TEST(truncate_preserves_url);
    RUN_TEST(truncate_preserves_version);
    RUN_TEST(truncate_empty);
    RUN_TEST(truncate_null);
}

/* ======================================================================
 * suite_schema_helpers — count_leading_tabs, trim_trailing,
 *                        count_completer_tokens_u32
 * ====================================================================== */

TEST count_leading_tabs_none(void) {
    ASSERT_EQ(0, count_leading_tabs("hello"));
    PASS();
}

TEST count_leading_tabs_some(void) {
    ASSERT_EQ(3, count_leading_tabs("\t\t\thello"));
    PASS();
}

TEST count_leading_tabs_spaces(void) {
    /* Spaces don't count as tabs */
    ASSERT_EQ(0, count_leading_tabs("    hello"));
    PASS();
}

TEST trim_trailing_spaces(void) {
    char buf[] = "hello   ";
    trim_trailing(buf);
    ASSERT_STR_EQ("hello", buf);
    PASS();
}

TEST trim_trailing_crlf(void) {
    char buf[] = "hello\r\n";
    trim_trailing(buf);
    ASSERT_STR_EQ("hello", buf);
    PASS();
}

TEST trim_trailing_tabs(void) {
    char buf[] = "hello\t\t";
    trim_trailing(buf);
    ASSERT_STR_EQ("hello", buf);
    PASS();
}

TEST trim_trailing_empty(void) {
    char buf[] = "";
    trim_trailing(buf);
    ASSERT_STR_EQ("", buf);
    PASS();
}

TEST count_tokens_simple(void) {
    ASSERT_EQ(3, count_completer_tokens_u32("ls -la /tmp"));
    PASS();
}

TEST count_tokens_quoted(void) {
    ASSERT_EQ(2, count_completer_tokens_u32("echo 'hello world'"));
    PASS();
}

TEST count_tokens_double_quoted(void) {
    ASSERT_EQ(2, count_completer_tokens_u32("echo \"hello world\""));
    PASS();
}

TEST count_tokens_escaped(void) {
    ASSERT_EQ(2, count_completer_tokens_u32("echo hello\\ world"));
    PASS();
}

TEST count_tokens_empty(void) {
    ASSERT_EQ(0, count_completer_tokens_u32(""));
    PASS();
}

TEST count_tokens_null(void) {
    ASSERT_EQ(0, count_completer_tokens_u32(NULL));
    PASS();
}

SUITE(suite_schema_helpers) {
    RUN_TEST(count_leading_tabs_none);
    RUN_TEST(count_leading_tabs_some);
    RUN_TEST(count_leading_tabs_spaces);
    RUN_TEST(trim_trailing_spaces);
    RUN_TEST(trim_trailing_crlf);
    RUN_TEST(trim_trailing_tabs);
    RUN_TEST(trim_trailing_empty);
    RUN_TEST(count_tokens_simple);
    RUN_TEST(count_tokens_quoted);
    RUN_TEST(count_tokens_double_quoted);
    RUN_TEST(count_tokens_escaped);
    RUN_TEST(count_tokens_empty);
    RUN_TEST(count_tokens_null);
}

/* ======================================================================
 * suite_blob_format — align4, write_u16, write_u32
 * ====================================================================== */

TEST align4_already_aligned(void) {
    ASSERT_EQ(4, align4(4));
    ASSERT_EQ(8, align4(8));
    ASSERT_EQ(0, align4(0));
    PASS();
}

TEST align4_needs_padding(void) {
    ASSERT_EQ(4, align4(1));
    ASSERT_EQ(4, align4(2));
    ASSERT_EQ(4, align4(3));
    ASSERT_EQ(8, align4(5));
    ASSERT_EQ(8, align4(7));
    PASS();
}

TEST write_u16_le(void) {
    uint8_t buf[2] = {0};
    write_u16(buf, 0x0102);
    ASSERT_EQ(0x02, buf[0]);
    ASSERT_EQ(0x01, buf[1]);
    PASS();
}

TEST write_u16_zero(void) {
    uint8_t buf[2] = {0xFF, 0xFF};
    write_u16(buf, 0);
    ASSERT_EQ(0, buf[0]);
    ASSERT_EQ(0, buf[1]);
    PASS();
}

TEST write_u32_le(void) {
    uint8_t buf[4] = {0};
    write_u32(buf, 0x01020304);
    ASSERT_EQ(0x04, buf[0]);
    ASSERT_EQ(0x03, buf[1]);
    ASSERT_EQ(0x02, buf[2]);
    ASSERT_EQ(0x01, buf[3]);
    PASS();
}

TEST write_u32_zero(void) {
    uint8_t buf[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    write_u32(buf, 0);
    ASSERT_EQ(0, buf[0]);
    ASSERT_EQ(0, buf[1]);
    ASSERT_EQ(0, buf[2]);
    ASSERT_EQ(0, buf[3]);
    PASS();
}

SUITE(suite_blob_format) {
    RUN_TEST(align4_already_aligned);
    RUN_TEST(align4_needs_padding);
    RUN_TEST(write_u16_le);
    RUN_TEST(write_u16_zero);
    RUN_TEST(write_u32_le);
    RUN_TEST(write_u32_zero);
}

/* ======================================================================
 * suite_strtab — strtab_add, strtab_add_nodupe, strtab_cmp
 * ====================================================================== */

TEST strtab_add_dedup(void) {
    StringTable st;
    strtab_init(&st);
    ASSERT_FALSE(st.error);

    uint32_t off1 = strtab_add(&st, "hello");
    uint32_t off2 = strtab_add(&st, "hello");
    ASSERT_EQ(off1, off2); /* Same string → same offset */

    uint32_t off3 = strtab_add(&st, "world");
    ASSERT(off3 != off1); /* Different string → different offset */

    strtab_free(&st);
    PASS();
}

TEST strtab_add_nodupe_no_dedup(void) {
    StringTable st;
    strtab_init(&st);
    ASSERT_FALSE(st.error);

    uint32_t off1 = strtab_add_nodupe(&st, "hello");
    uint32_t off2 = strtab_add_nodupe(&st, "hello");
    ASSERT(off1 != off2); /* Same string → different offsets */

    strtab_free(&st);
    PASS();
}

TEST strtab_cmp_ordering(void) {
    StringTable st;
    strtab_init(&st);
    ASSERT_FALSE(st.error);

    uint32_t off_a = strtab_add(&st, "apple");
    uint32_t off_b = strtab_add(&st, "banana");
    uint32_t off_a2 = strtab_add(&st, "apple");

    ASSERT(strtab_cmp(&st, off_a, off_b) < 0);  /* apple < banana */
    ASSERT(strtab_cmp(&st, off_b, off_a) > 0);  /* banana > apple */
    ASSERT_EQ(0, strtab_cmp(&st, off_a, off_a2)); /* apple == apple */

    strtab_free(&st);
    PASS();
}

TEST strtab_cmp_same_offset(void) {
    StringTable st;
    strtab_init(&st);
    ASSERT_FALSE(st.error);

    uint32_t off = strtab_add(&st, "test");
    ASSERT_EQ(0, strtab_cmp(&st, off, off));

    strtab_free(&st);
    PASS();
}

TEST strtab_empty_string(void) {
    StringTable st;
    strtab_init(&st);
    ASSERT_FALSE(st.error);

    uint32_t off1 = strtab_add(&st, "");
    uint32_t off2 = strtab_add(&st, "");
    ASSERT_EQ(off1, off2); /* Empty string dedup */
    ASSERT_EQ(0, off1);    /* Empty string always at offset 0 */

    strtab_free(&st);
    PASS();
}

TEST strtab_null_becomes_empty(void) {
    StringTable st;
    strtab_init(&st);
    ASSERT_FALSE(st.error);

    uint32_t off = strtab_add(&st, NULL);
    ASSERT_EQ(0, off); /* NULL treated as "" → offset 0 */

    strtab_free(&st);
    PASS();
}

SUITE(suite_strtab) {
    RUN_TEST(strtab_add_dedup);
    RUN_TEST(strtab_add_nodupe_no_dedup);
    RUN_TEST(strtab_cmp_ordering);
    RUN_TEST(strtab_cmp_same_offset);
    RUN_TEST(strtab_empty_string);
    RUN_TEST(strtab_null_becomes_empty);
}

/* ======================================================================
 * suite_option_parse — parse_option_spec, parse_list_items
 * ====================================================================== */

TEST parse_option_long_and_short(void) {
    char *long_opt, *short_opt;
    const char *err;
    ASSERT(parse_option_spec("--verbose|-v", &long_opt, &short_opt, &err));
    ASSERT_STR_EQ("--verbose", long_opt);
    ASSERT_STR_EQ("-v", short_opt);
    PASS();
}

TEST parse_option_long_only(void) {
    char *long_opt, *short_opt;
    const char *err;
    ASSERT(parse_option_spec("--output", &long_opt, &short_opt, &err));
    ASSERT_STR_EQ("--output", long_opt);
    ASSERT_EQ(NULL, short_opt);
    PASS();
}

TEST parse_option_short_only(void) {
    char *long_opt, *short_opt;
    const char *err;
    ASSERT(parse_option_spec("-v", &long_opt, &short_opt, &err));
    ASSERT_EQ(NULL, long_opt);
    ASSERT_STR_EQ("-v", short_opt);
    PASS();
}

TEST parse_list_items_simple(void) {
    char **items = NULL;
    size_t count = 0;
    ASSERT(parse_list_items("a|b|c", "<test>", 1, &items, &count));
    ASSERT_EQ(3, count);
    ASSERT_STR_EQ("a", items[0]);
    ASSERT_STR_EQ("b", items[1]);
    ASSERT_STR_EQ("c", items[2]);
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
    PASS();
}

TEST parse_list_items_single(void) {
    char **items = NULL;
    size_t count = 0;
    ASSERT(parse_list_items("only", "<test>", 1, &items, &count));
    ASSERT_EQ(1, count);
    ASSERT_STR_EQ("only", items[0]);
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
    PASS();
}

TEST parse_list_items_quoted(void) {
    char **items = NULL;
    size_t count = 0;
    ASSERT(parse_list_items("'hello world'|normal", "<test>", 1, &items, &count));
    ASSERT_EQ(2, count);
    ASSERT_STR_EQ("hello world", items[0]);
    ASSERT_STR_EQ("normal", items[1]);
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
    PASS();
}

SUITE(suite_option_parse) {
    RUN_TEST(parse_option_long_and_short);
    RUN_TEST(parse_option_long_only);
    RUN_TEST(parse_option_short_only);
    RUN_TEST(parse_list_items_simple);
    RUN_TEST(parse_list_items_single);
    RUN_TEST(parse_list_items_quoted);
}

/* ======================================================================
 * suite_tokenizer — tokenize_line
 * ====================================================================== */

TEST tokenize_command_name(void) {
    TokenList tl;
    ASSERT(tokenize_line("subcommand", &tl, "<test>", 1));
    ASSERT_EQ(1, tl.count);
    ASSERT_EQ(TOK_WORD, tl.tokens[0].type);
    ASSERT_STR_EQ("subcommand", tl.tokens[0].value);
    token_list_free(&tl);
    PASS();
}

TEST tokenize_command_with_desc(void) {
    TokenList tl;
    ASSERT(tokenize_line("mycmd # A description", &tl, "<test>", 1));
    ASSERT_EQ(2, tl.count);
    ASSERT_EQ(TOK_WORD, tl.tokens[0].type);
    ASSERT_STR_EQ("mycmd", tl.tokens[0].value);
    ASSERT_EQ(TOK_DESC, tl.tokens[1].type);
    ASSERT_STR_EQ("A description", tl.tokens[1].value);
    token_list_free(&tl);
    PASS();
}

TEST tokenize_flag_bool(void) {
    TokenList tl;
    ASSERT(tokenize_line("--verbose @bool # Enable verbose", &tl, "<test>", 1));
    ASSERT_EQ(3, tl.count);
    ASSERT_EQ(TOK_WORD, tl.tokens[0].type);
    ASSERT_STR_EQ("--verbose", tl.tokens[0].value);
    ASSERT_EQ(TOK_BOOL, tl.tokens[1].type);
    ASSERT_EQ(TOK_DESC, tl.tokens[2].type);
    token_list_free(&tl);
    PASS();
}

TEST tokenize_choices(void) {
    TokenList tl;
    ASSERT(tokenize_line("--format (json|text|csv)", &tl, "<test>", 1));
    ASSERT_EQ(2, tl.count);
    ASSERT_EQ(TOK_WORD, tl.tokens[0].type);
    ASSERT_STR_EQ("--format", tl.tokens[0].value);
    ASSERT_EQ(TOK_CHOICES, tl.tokens[1].type);
    ASSERT_STR_EQ("json|text|csv", tl.tokens[1].value);
    token_list_free(&tl);
    PASS();
}

TEST tokenize_members(void) {
    TokenList tl;
    ASSERT(tokenize_line("--label {key1|key2}", &tl, "<test>", 1));
    ASSERT_EQ(2, tl.count);
    ASSERT_EQ(TOK_WORD, tl.tokens[0].type);
    ASSERT_EQ(TOK_MEMBERS, tl.tokens[1].type);
    ASSERT_STR_EQ("key1|key2", tl.tokens[1].value);
    token_list_free(&tl);
    PASS();
}

TEST tokenize_completer(void) {
    TokenList tl;
    ASSERT(tokenize_line("--file `ls -la`", &tl, "<test>", 1));
    ASSERT_EQ(2, tl.count);
    ASSERT_EQ(TOK_WORD, tl.tokens[0].type);
    ASSERT_EQ(TOK_COMPLETER, tl.tokens[1].type);
    ASSERT_STR_EQ("ls -la", tl.tokens[1].value);
    token_list_free(&tl);
    PASS();
}

TEST tokenize_full_line(void) {
    TokenList tl;
    ASSERT(tokenize_line("--opt|-o (a|b|c) # Pick one", &tl, "<test>", 1));
    ASSERT_EQ(3, tl.count);
    ASSERT_EQ(TOK_WORD, tl.tokens[0].type);
    ASSERT_STR_EQ("--opt|-o", tl.tokens[0].value);
    ASSERT_EQ(TOK_CHOICES, tl.tokens[1].type);
    ASSERT_STR_EQ("a|b|c", tl.tokens[1].value);
    ASSERT_EQ(TOK_DESC, tl.tokens[2].type);
    ASSERT_STR_EQ("Pick one", tl.tokens[2].value);
    token_list_free(&tl);
    PASS();
}

TEST tokenize_unmatched_paren(void) {
    TokenList tl;
    ASSERT_FALSE(tokenize_line("--opt (a|b", &tl, "<test>", 1));
    PASS();
}

TEST tokenize_unmatched_brace(void) {
    TokenList tl;
    ASSERT_FALSE(tokenize_line("--opt {a|b", &tl, "<test>", 1));
    PASS();
}

TEST tokenize_unmatched_backtick(void) {
    TokenList tl;
    ASSERT_FALSE(tokenize_line("--opt `ls -la", &tl, "<test>", 1));
    PASS();
}

SUITE(suite_tokenizer) {
    RUN_TEST(tokenize_command_name);
    RUN_TEST(tokenize_command_with_desc);
    RUN_TEST(tokenize_flag_bool);
    RUN_TEST(tokenize_choices);
    RUN_TEST(tokenize_members);
    RUN_TEST(tokenize_completer);
    RUN_TEST(tokenize_full_line);
    RUN_TEST(tokenize_unmatched_paren);
    RUN_TEST(tokenize_unmatched_brace);
    RUN_TEST(tokenize_unmatched_backtick);
}

/* ======================================================================
 * Main
 * ====================================================================== */

GREATEST_MAIN_DEFS();

int main(int argc, char *argv[]) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(suite_utf8);
    RUN_SUITE(suite_description);
    RUN_SUITE(suite_schema_helpers);
    RUN_SUITE(suite_blob_format);
    RUN_SUITE(suite_strtab);
    RUN_SUITE(suite_option_parse);
    RUN_SUITE(suite_tokenizer);
    GREATEST_MAIN_END();
}
