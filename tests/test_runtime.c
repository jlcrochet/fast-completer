/*
 * test_runtime.c - Unit tests for fast-completer.c
 *
 * Tests: hash functions, string operations, parsing, emit_set.
 *
 * Includes fast-completer.c directly with main() renamed via #define
 * to avoid conflict with the test runner's main().
 */

#include "greatest.h"

/* Rename the production main so it doesn't conflict with our test main */
#define main fc_main
#include "../src/fast-completer.c"
#undef main

/* ======================================================================
 * suite_hash_math — hash_str, hash_str_nonzero, next_pow2
 * ====================================================================== */

TEST hash_str_deterministic(void) {
    uint32_t h1 = hash_str("hello", 5);
    uint32_t h2 = hash_str("hello", 5);
    ASSERT_EQ(h1, h2);
    PASS();
}

TEST hash_str_different(void) {
    uint32_t h1 = hash_str("hello", 5);
    uint32_t h2 = hash_str("world", 5);
    ASSERT(h1 != h2);
    PASS();
}

TEST hash_str_empty(void) {
    /* Empty string should produce the initial seed (5381) */
    uint32_t h = hash_str("", 0);
    ASSERT_EQ(5381, h);
    PASS();
}

TEST hash_str_nonzero_never_zero(void) {
    /* hash_str_nonzero must never return 0 */
    uint32_t h = hash_str_nonzero("", 0);
    ASSERT(h != 0);

    h = hash_str_nonzero("hello", 5);
    ASSERT(h != 0);

    h = hash_str_nonzero("x", 1);
    ASSERT(h != 0);
    PASS();
}

TEST next_pow2_already_power(void) {
    ASSERT_EQ(1, next_pow2(1));
    ASSERT_EQ(2, next_pow2(2));
    ASSERT_EQ(4, next_pow2(4));
    ASSERT_EQ(256, next_pow2(256));
    PASS();
}

TEST next_pow2_round_up(void) {
    ASSERT_EQ(4, next_pow2(3));
    ASSERT_EQ(8, next_pow2(5));
    ASSERT_EQ(16, next_pow2(9));
    ASSERT_EQ(512, next_pow2(300));
    PASS();
}

TEST next_pow2_one(void) {
    ASSERT_EQ(1, next_pow2(1));
    PASS();
}

SUITE(suite_hash_math) {
    RUN_TEST(hash_str_deterministic);
    RUN_TEST(hash_str_different);
    RUN_TEST(hash_str_empty);
    RUN_TEST(hash_str_nonzero_never_zero);
    RUN_TEST(next_pow2_already_power);
    RUN_TEST(next_pow2_round_up);
    RUN_TEST(next_pow2_one);
}

/* ======================================================================
 * suite_string_ops — str_cmp, ascii_tolower, str_eq_mode,
 *                    str_starts_with_mode, is_match_case_sensitive
 * ====================================================================== */

TEST str_cmp_equal(void) {
    ASSERT_EQ(0, str_cmp("abc", 3, "abc", 3));
    PASS();
}

TEST str_cmp_less(void) {
    ASSERT(str_cmp("abc", 3, "abd", 3) < 0);
    PASS();
}

TEST str_cmp_greater(void) {
    ASSERT(str_cmp("abd", 3, "abc", 3) > 0);
    PASS();
}

TEST str_cmp_shorter(void) {
    ASSERT(str_cmp("ab", 2, "abc", 3) < 0);
    PASS();
}

TEST str_cmp_longer(void) {
    ASSERT(str_cmp("abc", 3, "ab", 2) > 0);
    PASS();
}

TEST str_cmp_empty(void) {
    ASSERT_EQ(0, str_cmp("", 0, "", 0));
    ASSERT(str_cmp("", 0, "a", 1) < 0);
    PASS();
}

TEST ascii_tolower_uppercase(void) {
    ASSERT_EQ('a', ascii_tolower('A'));
    ASSERT_EQ('z', ascii_tolower('Z'));
    PASS();
}

TEST ascii_tolower_lowercase(void) {
    ASSERT_EQ('a', ascii_tolower('a'));
    ASSERT_EQ('z', ascii_tolower('z'));
    PASS();
}

TEST ascii_tolower_nonalpha(void) {
    ASSERT_EQ('1', ascii_tolower('1'));
    ASSERT_EQ('-', ascii_tolower('-'));
    PASS();
}

TEST str_eq_mode_case_sensitive(void) {
    ASSERT(str_eq_mode("abc", 3, "abc", 3, true));
    ASSERT_FALSE(str_eq_mode("abc", 3, "ABC", 3, true));
    PASS();
}

TEST str_eq_mode_case_insensitive(void) {
    ASSERT(str_eq_mode("abc", 3, "ABC", 3, false));
    ASSERT(str_eq_mode("Hello", 5, "hello", 5, false));
    PASS();
}

TEST str_eq_mode_different_lengths(void) {
    ASSERT_FALSE(str_eq_mode("ab", 2, "abc", 3, true));
    ASSERT_FALSE(str_eq_mode("ab", 2, "abc", 3, false));
    PASS();
}

TEST str_starts_with_mode_sensitive(void) {
    ASSERT(str_starts_with_mode("hello world", 11, "hello", 5, true));
    ASSERT_FALSE(str_starts_with_mode("hello world", 11, "Hello", 5, true));
    PASS();
}

TEST str_starts_with_mode_insensitive(void) {
    ASSERT(str_starts_with_mode("Hello world", 11, "hello", 5, false));
    PASS();
}

TEST str_starts_with_mode_empty_prefix(void) {
    ASSERT(str_starts_with_mode("hello", 5, "", 0, true));
    PASS();
}

TEST str_starts_with_mode_prefix_longer(void) {
    ASSERT_FALSE(str_starts_with_mode("hi", 2, "hello", 5, true));
    PASS();
}

TEST is_match_case_sensitive_true_mode(void) {
    CaseSensitivityMode saved = g_case_sensitive;
    g_case_sensitive = CASE_SENSITIVE_TRUE;
    ASSERT(is_match_case_sensitive("abc", 3));
    ASSERT(is_match_case_sensitive("ABC", 3));
    g_case_sensitive = saved;
    PASS();
}

TEST is_match_case_sensitive_false_mode(void) {
    CaseSensitivityMode saved = g_case_sensitive;
    g_case_sensitive = CASE_SENSITIVE_FALSE;
    ASSERT_FALSE(is_match_case_sensitive("abc", 3));
    ASSERT_FALSE(is_match_case_sensitive("ABC", 3));
    g_case_sensitive = saved;
    PASS();
}

TEST is_match_case_sensitive_smart_lowercase(void) {
    CaseSensitivityMode saved = g_case_sensitive;
    g_case_sensitive = CASE_SENSITIVE_SMART;
    /* All lowercase → case insensitive */
    ASSERT_FALSE(is_match_case_sensitive("abc", 3));
    g_case_sensitive = saved;
    PASS();
}

TEST is_match_case_sensitive_smart_has_upper(void) {
    CaseSensitivityMode saved = g_case_sensitive;
    g_case_sensitive = CASE_SENSITIVE_SMART;
    /* Has uppercase → case sensitive */
    ASSERT(is_match_case_sensitive("Abc", 3));
    g_case_sensitive = saved;
    PASS();
}

SUITE(suite_string_ops) {
    RUN_TEST(str_cmp_equal);
    RUN_TEST(str_cmp_less);
    RUN_TEST(str_cmp_greater);
    RUN_TEST(str_cmp_shorter);
    RUN_TEST(str_cmp_longer);
    RUN_TEST(str_cmp_empty);
    RUN_TEST(ascii_tolower_uppercase);
    RUN_TEST(ascii_tolower_lowercase);
    RUN_TEST(ascii_tolower_nonalpha);
    RUN_TEST(str_eq_mode_case_sensitive);
    RUN_TEST(str_eq_mode_case_insensitive);
    RUN_TEST(str_eq_mode_different_lengths);
    RUN_TEST(str_starts_with_mode_sensitive);
    RUN_TEST(str_starts_with_mode_insensitive);
    RUN_TEST(str_starts_with_mode_empty_prefix);
    RUN_TEST(str_starts_with_mode_prefix_longer);
    RUN_TEST(is_match_case_sensitive_true_mode);
    RUN_TEST(is_match_case_sensitive_false_mode);
    RUN_TEST(is_match_case_sensitive_smart_lowercase);
    RUN_TEST(is_match_case_sensitive_smart_has_upper);
}

/* ======================================================================
 * suite_parsing — parse_escape_char, split_args
 * ====================================================================== */

TEST parse_escape_newline(void) {
    const char *p = "n";
    char out;
    ASSERT(parse_escape_char(&p, &out, NULL));
    ASSERT_EQ('\n', out);
    PASS();
}

TEST parse_escape_tab(void) {
    const char *p = "t";
    char out;
    ASSERT(parse_escape_char(&p, &out, NULL));
    ASSERT_EQ('\t', out);
    PASS();
}

TEST parse_escape_backslash(void) {
    const char *p = "\\";
    char out;
    ASSERT(parse_escape_char(&p, &out, NULL));
    ASSERT_EQ('\\', out);
    PASS();
}

TEST parse_escape_hex(void) {
    const char *p = "x41rest";
    char out;
    ASSERT(parse_escape_char(&p, &out, NULL));
    ASSERT_EQ('A', out); /* 0x41 = 'A' */
    PASS();
}

TEST parse_escape_invalid_hex(void) {
    const char *p = "xZZ";
    char out;
    ASSERT(parse_escape_char(&p, &out, NULL));
    ASSERT_EQ('x', out); /* Falls back to literal 'x' */
    PASS();
}

TEST parse_escape_unknown(void) {
    const char *p = "q";
    char out;
    ASSERT(parse_escape_char(&p, &out, NULL));
    ASSERT_EQ('q', out); /* Unknown escape → literal */
    PASS();
}

TEST parse_escape_unterminated(void) {
    const char *p = "";
    char out;
    const char *err = NULL;
    ASSERT_FALSE(parse_escape_char(&p, &out, &err));
    ASSERT(err != NULL);
    PASS();
}

TEST split_args_simple(void) {
    char buf[] = "hello world foo";
    char *argv[10];
    int argc = split_args(buf, argv, 10, NULL);
    ASSERT_EQ(3, argc);
    ASSERT_STR_EQ("hello", argv[0]);
    ASSERT_STR_EQ("world", argv[1]);
    ASSERT_STR_EQ("foo", argv[2]);
    ASSERT_EQ(NULL, argv[3]);
    PASS();
}

TEST split_args_single_quoted(void) {
    char buf[] = "echo 'hello world'";
    char *argv[10];
    int argc = split_args(buf, argv, 10, NULL);
    ASSERT_EQ(2, argc);
    ASSERT_STR_EQ("echo", argv[0]);
    ASSERT_STR_EQ("hello world", argv[1]);
    PASS();
}

TEST split_args_double_quoted(void) {
    char buf[] = "echo \"hello world\"";
    char *argv[10];
    int argc = split_args(buf, argv, 10, NULL);
    ASSERT_EQ(2, argc);
    ASSERT_STR_EQ("echo", argv[0]);
    ASSERT_STR_EQ("hello world", argv[1]);
    PASS();
}

TEST split_args_escaped(void) {
    char buf[] = "echo hello\\ world";
    char *argv[10];
    int argc = split_args(buf, argv, 10, NULL);
    ASSERT_EQ(2, argc);
    ASSERT_STR_EQ("echo", argv[0]);
    ASSERT_STR_EQ("hello world", argv[1]);
    PASS();
}

TEST split_args_unterminated_single(void) {
    char buf[] = "echo 'hello";
    char *argv[10];
    const char *err = NULL;
    int argc = split_args(buf, argv, 10, &err);
    ASSERT_EQ(-1, argc);
    ASSERT(err != NULL);
    PASS();
}

TEST split_args_unterminated_double(void) {
    char buf[] = "echo \"hello";
    char *argv[10];
    const char *err = NULL;
    int argc = split_args(buf, argv, 10, &err);
    ASSERT_EQ(-1, argc);
    ASSERT(err != NULL);
    PASS();
}

TEST split_args_max_exceeded(void) {
    char buf[] = "a b c d e";
    char *argv[4];
    const char *err = NULL;
    int argc = split_args(buf, argv, 3, &err);
    ASSERT_EQ(-1, argc);
    ASSERT(err != NULL);
    PASS();
}

TEST split_args_empty(void) {
    char buf[] = "";
    char *argv[10];
    int argc = split_args(buf, argv, 10, NULL);
    ASSERT_EQ(0, argc);
    PASS();
}

TEST split_args_whitespace_only(void) {
    char buf[] = "   \t  ";
    char *argv[10];
    int argc = split_args(buf, argv, 10, NULL);
    ASSERT_EQ(0, argc);
    PASS();
}

TEST decode_string_at_rejects_truncated_payload(void) {
    const uint8_t section[] = {0, 5, 'a', 'b'};
    String s = decode_string_at(section, 1, sizeof(section));
    ASSERT_EQ(0, s.n);
    PASS();
}

TEST find_value_param_for_token_short_cluster_terminal_value(void) {
    const char *blob_path = "tests/.tmp_fc_runtime_1.fcmpb";
    remove(blob_path);
    ASSERT(generate_blob("tests/fixtures/minimal.fcmps", blob_path, DESC_SHORT, 0));
    ASSERT(load_blob(blob_path));

    g_current_cmd_ref = 0;  // root command
    const Param *param = find_value_param_for_token("-vo", 3);
    ASSERT(param != NULL);
    String name = str_get(param->name_off);
    ASSERT(name.n == 8);
    ASSERT(memcmp(name.p, "--output", 8) == 0);

    remove(blob_path);
    PASS();
}

TEST find_value_param_for_token_short_attached_value_returns_null(void) {
    const char *blob_path = "tests/.tmp_fc_runtime_2.fcmpb";
    remove(blob_path);
    ASSERT(generate_blob("tests/fixtures/minimal.fcmps", blob_path, DESC_SHORT, 0));
    ASSERT(load_blob(blob_path));

    g_current_cmd_ref = 0;  // root command
    const Param *param = find_value_param_for_token("-ovalue", 7);
    ASSERT(param == NULL);

    remove(blob_path);
    PASS();
}

SUITE(suite_parsing) {
    RUN_TEST(parse_escape_newline);
    RUN_TEST(parse_escape_tab);
    RUN_TEST(parse_escape_backslash);
    RUN_TEST(parse_escape_hex);
    RUN_TEST(parse_escape_invalid_hex);
    RUN_TEST(parse_escape_unknown);
    RUN_TEST(parse_escape_unterminated);
    RUN_TEST(split_args_simple);
    RUN_TEST(split_args_single_quoted);
    RUN_TEST(split_args_double_quoted);
    RUN_TEST(split_args_escaped);
    RUN_TEST(split_args_unterminated_single);
    RUN_TEST(split_args_unterminated_double);
    RUN_TEST(split_args_max_exceeded);
    RUN_TEST(split_args_empty);
    RUN_TEST(split_args_whitespace_only);
    RUN_TEST(decode_string_at_rejects_truncated_payload);
    RUN_TEST(find_value_param_for_token_short_cluster_terminal_value);
    RUN_TEST(find_value_param_for_token_short_attached_value_returns_null);
}

/* ======================================================================
 * suite_emit_set — emit_set_reset, emit_set_add, emit_set_contains
 *
 * Note: emit_set_reset() requires header.param_count to be set because
 * it sizes the hash table based on it. We set it to a small value for
 * testing and clean up after.
 * ====================================================================== */

TEST emit_set_init_and_add(void) {
    header.param_count = 16;
    g_emit_set = NULL;
    g_emit_set_size = 0;
    g_emit_set_ready = false;

    emit_set_reset();
    ASSERT(g_emit_set != NULL);
    ASSERT(g_emit_set_ready);

    ASSERT_FALSE(emit_set_contains("hello", 5));

    emit_set_add("hello", 5);
    ASSERT(emit_set_contains("hello", 5));
    ASSERT_FALSE(emit_set_contains("world", 5));

    free(g_emit_set);
    g_emit_set = NULL;
    g_emit_set_size = 0;
    g_emit_set_ready = false;
    PASS();
}

TEST emit_set_duplicates(void) {
    header.param_count = 16;
    g_emit_set = NULL;
    g_emit_set_size = 0;
    g_emit_set_ready = false;

    emit_set_reset();
    emit_set_add("hello", 5);
    emit_set_add("hello", 5); /* duplicate add */
    ASSERT(emit_set_contains("hello", 5));

    free(g_emit_set);
    g_emit_set = NULL;
    g_emit_set_size = 0;
    g_emit_set_ready = false;
    PASS();
}

TEST emit_set_multiple(void) {
    header.param_count = 16;
    g_emit_set = NULL;
    g_emit_set_size = 0;
    g_emit_set_ready = false;

    emit_set_reset();
    emit_set_add("alpha", 5);
    emit_set_add("bravo", 5);
    emit_set_add("charlie", 7);

    ASSERT(emit_set_contains("alpha", 5));
    ASSERT(emit_set_contains("bravo", 5));
    ASSERT(emit_set_contains("charlie", 7));
    ASSERT_FALSE(emit_set_contains("delta", 5));

    free(g_emit_set);
    g_emit_set = NULL;
    g_emit_set_size = 0;
    g_emit_set_ready = false;
    PASS();
}

TEST emit_set_reset_clears(void) {
    header.param_count = 16;
    g_emit_set = NULL;
    g_emit_set_size = 0;
    g_emit_set_ready = false;

    emit_set_reset();
    emit_set_add("hello", 5);
    ASSERT(emit_set_contains("hello", 5));

    /* Reset should clear without reallocating */
    emit_set_reset();
    ASSERT_FALSE(emit_set_contains("hello", 5));

    free(g_emit_set);
    g_emit_set = NULL;
    g_emit_set_size = 0;
    g_emit_set_ready = false;
    PASS();
}

SUITE(suite_emit_set) {
    RUN_TEST(emit_set_init_and_add);
    RUN_TEST(emit_set_duplicates);
    RUN_TEST(emit_set_multiple);
    RUN_TEST(emit_set_reset_clears);
}

/* ======================================================================
 * Main
 * ====================================================================== */

GREATEST_MAIN_DEFS();

int main(int argc, char *argv[]) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(suite_hash_math);
    RUN_SUITE(suite_string_ops);
    RUN_SUITE(suite_parsing);
    RUN_SUITE(suite_emit_set);
    GREATEST_MAIN_END();
}
