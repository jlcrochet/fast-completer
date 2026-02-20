/*
 * test_integration.c - End-to-end tests for fast-completer
 *
 * Tests: blob generation via API, validation, linting, completion
 * output via CLI invocation using posix_spawnp().
 */

#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <poll.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>

#include "../src/generate_blob.h"

extern char **environ;

/* Paths */
#define FC_BIN          "./fast-completer"
#define FUNC_SCHEMA     "schemas/func/func.fcmps"
#define MINIMAL_SCHEMA  "tests/fixtures/minimal.fcmps"
#define SCHEMAS_DIR     "schemas"
#define MAX_SCHEMAS     256

/* All schemas to test — discovered dynamically from schemas/ subdirs */
typedef struct {
    char name[64];          /* CLI name from root command (e.g. "aws") */
    char schema[256];       /* Path to .fcmps file */
    char blob[256];         /* Temp blob path, filled at setup time */
} SchemaEntry;

static SchemaEntry g_schemas[MAX_SCHEMAS];
static size_t g_num_schemas;

/* Temporary blob output paths */
static char g_func_blob[256];
static char g_minimal_blob[256];

/* ======================================================================
 * Helper: run a command and capture stdout, stderr, exit code
 * ====================================================================== */

typedef struct {
    char *out;       /* stdout (heap-allocated, caller frees) */
    size_t out_len;
    char *err;       /* stderr (heap-allocated, caller frees) */
    size_t err_len;
    int exit_code;
} RunResult;

static void run_result_free(RunResult *r) {
    free(r->out);
    free(r->err);
    r->out = NULL;
    r->err = NULL;
}

static bool append_bytes(char **buf, size_t *len, size_t *cap, const char *src, size_t n) {
    if (!buf || !len || !cap) return false;
    if (*buf == NULL) {
        *cap = 4096;
        *buf = malloc(*cap);
        if (!*buf) return false;
        *len = 0;
    }
    if (n > SIZE_MAX - 1 - *len) return false;
    if (*len + n + 1 > *cap) {
        size_t next = *cap;
        while (*len + n + 1 > next) {
            if (next > SIZE_MAX / 2) return false;
            next *= 2;
        }
        char *tmp = realloc(*buf, next);
        if (!tmp) return false;
        *buf = tmp;
        *cap = next;
    }
    memcpy(*buf + *len, src, n);
    *len += n;
    (*buf)[*len] = '\0';
    return true;
}

static bool drain_pipes(int fd_out, int fd_err, RunResult *result) {
    char *out = NULL, *err = NULL;
    size_t out_len = 0, err_len = 0;
    size_t out_cap = 0, err_cap = 0;
    bool out_open = true, err_open = true;
    char tmp[4096];

    while (out_open || err_open) {
        struct pollfd pfds[2];
        int out_idx = -1, err_idx = -1;
        int nfds = 0;
        if (out_open) {
            out_idx = nfds;
            pfds[nfds].fd = fd_out;
            pfds[nfds].events = POLLIN | POLLHUP;
            pfds[nfds].revents = 0;
            nfds++;
        }
        if (err_open) {
            err_idx = nfds;
            pfds[nfds].fd = fd_err;
            pfds[nfds].events = POLLIN | POLLHUP;
            pfds[nfds].revents = 0;
            nfds++;
        }

        int pr = poll(pfds, (nfds_t)nfds, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            free(out);
            free(err);
            return false;
        }

        if (out_open && out_idx >= 0 && (pfds[out_idx].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(fd_out, tmp, sizeof(tmp));
            if (n > 0) {
                if (!append_bytes(&out, &out_len, &out_cap, tmp, (size_t)n)) {
                    free(out);
                    free(err);
                    return false;
                }
            } else if (n == 0) {
                out_open = false;
            } else if (errno != EINTR) {
                free(out);
                free(err);
                return false;
            }
        }

        if (err_open && err_idx >= 0 && (pfds[err_idx].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(fd_err, tmp, sizeof(tmp));
            if (n > 0) {
                if (!append_bytes(&err, &err_len, &err_cap, tmp, (size_t)n)) {
                    free(out);
                    free(err);
                    return false;
                }
            } else if (n == 0) {
                err_open = false;
            } else if (errno != EINTR) {
                free(out);
                free(err);
                return false;
            }
        }
    }

    if (!out) {
        out = strdup("");
        if (!out) { free(err); return false; }
    }
    if (!err) {
        err = strdup("");
        if (!err) { free(out); return false; }
    }

    result->out = out;
    result->out_len = out_len;
    result->err = err;
    result->err_len = err_len;
    return true;
}

static bool run_capture(const char **argv, RunResult *result) {
    memset(result, 0, sizeof(*result));

    int stdout_pipe[2], stderr_pipe[2];
    if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) return false;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, stdout_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, stderr_pipe[0]);
    posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, stderr_pipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, stdout_pipe[1]);
    posix_spawn_file_actions_addclose(&actions, stderr_pipe[1]);

    pid_t pid;
    int rc = posix_spawnp(&pid, argv[0], &actions, NULL, (char *const *)argv, environ);
    posix_spawn_file_actions_destroy(&actions);

    if (rc != 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        return false;
    }

    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    if (!drain_pipes(stdout_pipe[0], stderr_pipe[0], result)) {
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        waitpid(pid, NULL, 0);
        return false;
    }

    close(stdout_pipe[0]);
    close(stderr_pipe[0]);

    int status;
    waitpid(pid, &status, 0);
    result->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return true;
}

/* ======================================================================
 * Setup/teardown
 * ====================================================================== */

/* Extract CLI name from first non-comment, non-blank line of .fcmps file.
 * The root command is the first token (e.g. "aws # description" → "aws"). */
static bool extract_cli_name(const char *schema_path, char *out, size_t out_sz) {
    FILE *f = fopen(schema_path, "r");
    if (!f) return false;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        /* First non-comment line is the root command */
        char *p = line;
        size_t len = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
            p++;
            len++;
        }
        if (len > 0 && len < out_sz) {
            memcpy(out, line, len);
            out[len] = '\0';
            fclose(f);
            return true;
        }
        break;
    }
    fclose(f);
    return false;
}

/* Compare SchemaEntry by name for qsort */
static int schema_entry_cmp(const void *a, const void *b) {
    return strcmp(((const SchemaEntry *)a)->name,
                 ((const SchemaEntry *)b)->name);
}

/* Scan schemas/ directory for all *.fcmps files */
static void discover_schemas(void) {
    g_num_schemas = 0;
    DIR *dir = opendir(SCHEMAS_DIR);
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        /* Build path: schemas/<name>/ */
        char subdir[512];
        snprintf(subdir, sizeof(subdir), "%s/%s", SCHEMAS_DIR, ent->d_name);

        struct stat st;
        if (stat(subdir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;

        /* Look for <name>.fcmps inside */
        DIR *sub = opendir(subdir);
        if (!sub) continue;

        struct dirent *fent;
        while ((fent = readdir(sub)) != NULL) {
            size_t flen = strlen(fent->d_name);
            if (flen < 7 || strcmp(fent->d_name + flen - 6, ".fcmps") != 0)
                continue;

            if (g_num_schemas >= MAX_SCHEMAS) break;

            SchemaEntry *s = &g_schemas[g_num_schemas];
            int n = snprintf(s->schema, sizeof(s->schema), "%s/%s",
                             subdir, fent->d_name);
            if (n < 0 || (size_t)n >= sizeof(s->schema))
                continue;  /* Path too long */

            if (!extract_cli_name(s->schema, s->name, sizeof(s->name)))
                continue;

            g_num_schemas++;
            break;  /* One .fcmps per directory */
        }
        closedir(sub);
    }
    closedir(dir);

    /* Sort by name for deterministic output */
    qsort(g_schemas, g_num_schemas, sizeof(SchemaEntry), schema_entry_cmp);
}

static SchemaEntry *find_schema_entry(const char *name) {
    for (size_t i = 0; i < g_num_schemas; i++) {
        if (strcmp(g_schemas[i].name, name) == 0) {
            return &g_schemas[i];
        }
    }
    return NULL;
}

static void setup_blobs(void) {
    pid_t pid = getpid();
    snprintf(g_func_blob, sizeof(g_func_blob), "/tmp/test_func_%d.fcmpb", pid);
    snprintf(g_minimal_blob, sizeof(g_minimal_blob), "/tmp/test_minimal_%d.fcmpb", pid);

    discover_schemas();

    for (size_t i = 0; i < g_num_schemas; i++) {
        char name_copy[64];
        memcpy(name_copy, g_schemas[i].name, sizeof(name_copy));
        snprintf(g_schemas[i].blob, sizeof(g_schemas[i].blob),
                 "/tmp/test_%s_%d.fcmpb", name_copy, pid);
    }
}

static void cleanup_blobs(void) {
    unlink(g_func_blob);
    unlink(g_minimal_blob);
    for (size_t i = 0; i < g_num_schemas; i++) {
        unlink(g_schemas[i].blob);
        /* Also clean up .nodesc variant if it wasn't cleaned */
        char blob_nd[280];
        snprintf(blob_nd, sizeof(blob_nd), "%s.nodesc", g_schemas[i].blob);
        unlink(blob_nd);
    }
}

/* ======================================================================
 * suite_integration
 * ====================================================================== */

TEST generate_func_blob(void) {
    bool ok = generate_blob(FUNC_SCHEMA, g_func_blob, DESC_SHORT, 0);
    ASSERT(ok);

    struct stat st;
    ASSERT_EQ(0, stat(g_func_blob, &st));
    ASSERT(st.st_size > HEADER_SIZE);
    PASS();
}

TEST generate_minimal_blob(void) {
    bool ok = generate_blob(MINIMAL_SCHEMA, g_minimal_blob, DESC_SHORT, 0);
    ASSERT(ok);

    struct stat st;
    ASSERT_EQ(0, stat(g_minimal_blob, &st));
    ASSERT(st.st_size > HEADER_SIZE);
    PASS();
}

TEST validate_func_blob(void) {
    const char *argv[] = {FC_BIN, "--validate-blob", g_func_blob, NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    run_result_free(&r);
    PASS();
}

TEST check_blob_exists_and_missing(void) {
    const char *argv_ok[] = {FC_BIN, "--check", g_func_blob, NULL};
    RunResult ok;
    ASSERT(run_capture(argv_ok, &ok));
    ASSERT_EQ(0, ok.exit_code);
    run_result_free(&ok);

    const char *argv_missing[] = {FC_BIN, "--check", "/tmp/definitely-missing-fc-blob.fcmpb", NULL};
    RunResult missing;
    ASSERT(run_capture(argv_missing, &missing));
    ASSERT_EQ(1, missing.exit_code);
    run_result_free(&missing);
    PASS();
}

TEST dump_header_minimal_blob(void) {
    const char *argv[] = {FC_BIN, "--dump-header", g_minimal_blob, NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "magic: FCMP") != NULL);
    ASSERT(strstr(r.out, "section_count:") != NULL);
    run_result_free(&r);
    PASS();
}

TEST lint_func_schema(void) {
    const char *argv[] = {FC_BIN, "--lint", FUNC_SCHEMA, NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    run_result_free(&r);
    PASS();
}

TEST lint_minimal_schema(void) {
    const char *argv[] = {FC_BIN, "--lint", MINIMAL_SCHEMA, NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    run_result_free(&r);
    PASS();
}

TEST complete_func_subcommands(void) {
    const char *argv[] = {FC_BIN, "--blob", g_func_blob, "json", "func", "", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "init") != NULL);
    ASSERT(strstr(r.out, "start") != NULL);
    run_result_free(&r);
    PASS();
}

TEST complete_func_flags(void) {
    const char *argv[] = {FC_BIN, "--blob", g_func_blob, "json", "func", "init", "--", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "--docker") != NULL);
    ASSERT(strstr(r.out, "--language") != NULL);
    run_result_free(&r);
    PASS();
}

TEST complete_func_choices(void) {
    const char *argv[] = {FC_BIN, "--blob", g_func_blob, "json", "func", "init", "--worker-runtime=", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "python") != NULL);
    ASSERT(strstr(r.out, "javascript") != NULL);
    run_result_free(&r);
    PASS();
}

TEST complete_minimal_subcommands(void) {
    const char *argv[] = {FC_BIN, "--blob", g_minimal_blob, "json", "test-cli", "", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "sub") != NULL);
    ASSERT(strstr(r.out, "--verbose") != NULL);
    ASSERT(strstr(r.out, "--output") != NULL);
    run_result_free(&r);
    PASS();
}

TEST complete_minimal_choices(void) {
    const char *argv[] = {FC_BIN, "--blob", g_minimal_blob, "json", "test-cli", "--output=", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "json") != NULL);
    ASSERT(strstr(r.out, "text") != NULL);
    run_result_free(&r);
    PASS();
}

TEST complete_minimal_members(void) {
    const char *argv[] = {FC_BIN, "--blob", g_minimal_blob, "json", "test-cli", "sub", "--flag=", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "key1") != NULL);
    ASSERT(strstr(r.out, "key2") != NULL);
    run_result_free(&r);
    PASS();
}

TEST quiet_missing_blob_is_silent(void) {
    const char *argv[] = {FC_BIN, "-q", "json", "definitely-missing-fc-cli", "", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(1, r.exit_code);
    ASSERT_EQ(0, r.err_len);
    run_result_free(&r);
    PASS();
}

TEST add_space_appends_space_to_values(void) {
    const char *argv[] = {FC_BIN, "--blob", g_minimal_blob, "--add-space", "lines",
                          "test-cli", "--output=", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "--output=json ") != NULL);
    ASSERT(strstr(r.out, "--output=text ") != NULL);
    run_result_free(&r);
    PASS();
}

TEST full_commands_emits_leaf_paths(void) {
    char schema_path[256];
    char blob_path[256];
    snprintf(schema_path, sizeof(schema_path), "/tmp/test_full_%d.fcmps", getpid());
    snprintf(blob_path, sizeof(blob_path), "/tmp/test_full_%d.fcmpb", getpid());

    FILE *f = fopen(schema_path, "w");
    ASSERT(f != NULL);
    fprintf(f, "mycli\n");
    fprintf(f, "\talpha\n");
    fprintf(f, "\t\tbeta\n");
    fclose(f);

    ASSERT(generate_blob(schema_path, blob_path, DESC_SHORT, 0));
    const char *argv[] = {
        FC_BIN, "--blob", blob_path, "--full-commands", "lines",
        "mycli", "", NULL
    };
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "alpha beta\n") != NULL);
    ASSERT(strstr(r.out, "alpha\n") == NULL);
    run_result_free(&r);

    unlink(schema_path);
    unlink(blob_path);
    PASS();
}

TEST dynamic_completer_returns_values(void) {
    char schema_path[256];
    char blob_path[256];
    snprintf(schema_path, sizeof(schema_path), "/tmp/test_dyn_%d.fcmps", getpid());
    snprintf(blob_path, sizeof(blob_path), "/tmp/test_dyn_%d.fcmpb", getpid());

    FILE *f = fopen(schema_path, "w");
    ASSERT(f != NULL);
    fprintf(f, "printf\n");
    fprintf(f, "\t--pick `\"%%s\\\\n\" alpha beta`\n");
    fclose(f);

    ASSERT(generate_blob(schema_path, blob_path, DESC_SHORT, 0));
    const char *argv[] = {FC_BIN, "--blob", blob_path, "lines", "printf", "--pick=", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "--pick=alpha") != NULL);
    ASSERT(strstr(r.out, "--pick=beta") != NULL);
    run_result_free(&r);

    unlink(schema_path);
    unlink(blob_path);
    PASS();
}

TEST dynamic_completer_timeout_override(void) {
    char schema_path[256];
    char blob_path[256];
    snprintf(schema_path, sizeof(schema_path), "/tmp/test_dyn_to_%d.fcmps", getpid());
    snprintf(blob_path, sizeof(blob_path), "/tmp/test_dyn_to_%d.fcmpb", getpid());

    FILE *f = fopen(schema_path, "w");
    ASSERT(f != NULL);
    fprintf(f, "sh\n");
    fprintf(f, "\t--pick `-c \"sleep 1; printf 'slow\\\\n'\"`\n");
    fclose(f);

    ASSERT(generate_blob(schema_path, blob_path, DESC_SHORT, 0));
    const char *argv[] = {FC_BIN, "--blob", blob_path, "-T", "10", "lines", "sh", "--pick=", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT_EQ(0, r.out_len);
    ASSERT(r.err != NULL);
    ASSERT(strstr(r.err, "timed out") != NULL);
    run_result_free(&r);

    unlink(schema_path);
    unlink(blob_path);
    PASS();
}

TEST lint_malformed_schema(void) {
    /* Create a temporary malformed schema */
    char path[256];
    snprintf(path, sizeof(path), "/tmp/test_bad_%d.fcmps", getpid());
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL);
    fprintf(f, "\t\torphan-at-depth-2 # Bad\n");
    fclose(f);

    const char *argv[] = {FC_BIN, "--lint", path, NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT(r.exit_code != 0);
    ASSERT(r.err != NULL);
    ASSERT(r.err_len > 0);

    run_result_free(&r);
    unlink(path);
    PASS();
}

TEST complete_prefix_filter(void) {
    /* Complete with prefix "ini" → should match "init" */
    const char *argv[] = {FC_BIN, "--blob", g_func_blob, "json", "func", "ini", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "init") != NULL);
    /* "start" should NOT match prefix "ini" */
    ASSERT(strstr(r.out, "start") == NULL);
    run_result_free(&r);
    PASS();
}

TEST complete_flag_prefix(void) {
    /* Complete "--doc" → should match --docker but not --language */
    const char *argv[] = {FC_BIN, "--blob", g_func_blob, "json", "func", "init", "--doc", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);
    ASSERT(strstr(r.out, "--docker") != NULL);
    ASSERT(strstr(r.out, "--language") == NULL);
    run_result_free(&r);
    PASS();
}

TEST complete_pnpm_config_delete_leaf(void) {
    SchemaEntry *pnpm = find_schema_entry("pnpm");
    ASSERTm("pnpm schema not discovered", pnpm != NULL);

    bool ok = generate_blob(pnpm->schema, pnpm->blob, DESC_SHORT, 0);
    ASSERT(ok);

    const char *argv[] = {
        FC_BIN, "--blob", pnpm->blob, "lines",
        "pnpm", "config", "delete", "", NULL
    };
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQ(0, r.exit_code);
    ASSERT(r.out != NULL);

    ASSERT(strstr(r.out, "--global") != NULL);
    ASSERT(strstr(r.out, "--location") != NULL);
    ASSERT(strstr(r.out, "delete\n") == NULL);
    ASSERT(strstr(r.out, "get\n") == NULL);
    ASSERT(strstr(r.out, "list\n") == NULL);
    ASSERT(strstr(r.out, "set\n") == NULL);

    run_result_free(&r);
    PASS();
}

/* ======================================================================
 * suite_all_schemas — generate, lint, validate every .fcmps schema
 * ====================================================================== */

/* Parameterized test: generate blob for a schema */
TEST schema_generate(SchemaEntry *s) {
    bool ok = generate_blob(s->schema, s->blob, DESC_SHORT, 0);
    ASSERTm(s->name, ok);

    struct stat st;
    ASSERT_EQ(0, stat(s->blob, &st));
    ASSERT(st.st_size > HEADER_SIZE);
    PASS();
}

/* Parameterized test: lint a schema */
TEST schema_lint(SchemaEntry *s) {
    const char *argv[] = {FC_BIN, "--lint", s->schema, NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    if (r.exit_code != 0) {
        fprintf(stderr, "  lint failed for %s: %.*s\n",
                s->name, (int)r.err_len, r.err);
    }
    ASSERT_EQm(s->name, 0, r.exit_code);
    run_result_free(&r);
    PASS();
}

/* Parameterized test: validate a generated blob */
TEST schema_validate_blob(SchemaEntry *s) {
    const char *argv[] = {FC_BIN, "--validate-blob", s->blob, NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    if (r.exit_code != 0) {
        fprintf(stderr, "  validate failed for %s: %.*s\n",
                s->name, (int)r.err_len, r.err);
    }
    ASSERT_EQm(s->name, 0, r.exit_code);
    run_result_free(&r);
    PASS();
}

/* Parameterized test: root completions produce non-empty output */
TEST schema_complete_root(SchemaEntry *s) {
    const char *argv[] = {FC_BIN, "--blob", s->blob, "json", s->name, "", NULL};
    RunResult r;
    ASSERT(run_capture(argv, &r));
    ASSERT_EQm(s->name, 0, r.exit_code);
    ASSERT(r.out != NULL);
    /* Root completions should produce at least one result (a '[' followed by '{') */
    ASSERT(r.out_len > 2);
    ASSERT(r.out[0] == '[');
    ASSERT(strstr(r.out, "\"value\"") != NULL);
    run_result_free(&r);
    PASS();
}

/* Parameterized test: generate blob with no descriptions */
TEST schema_generate_no_desc(SchemaEntry *s) {
    char blob_nd[280];
    snprintf(blob_nd, sizeof(blob_nd), "%s.nodesc", s->blob);
    bool ok = generate_blob(s->schema, blob_nd, DESC_NONE, 0);
    ASSERTm(s->name, ok);

    struct stat st;
    ASSERT_EQ(0, stat(blob_nd, &st));
    ASSERT(st.st_size > HEADER_SIZE);

    /* No-description blob should be smaller than short-description blob */
    struct stat st_short;
    ASSERT_EQ(0, stat(s->blob, &st_short));
    ASSERT(st.st_size <= st_short.st_size);

    unlink(blob_nd);
    PASS();
}

SUITE(suite_all_schemas) {
    for (size_t i = 0; i < g_num_schemas; i++) {
        RUN_TEST1(schema_lint, &g_schemas[i]);
    }
    for (size_t i = 0; i < g_num_schemas; i++) {
        RUN_TEST1(schema_generate, &g_schemas[i]);
    }
    for (size_t i = 0; i < g_num_schemas; i++) {
        RUN_TEST1(schema_validate_blob, &g_schemas[i]);
    }
    for (size_t i = 0; i < g_num_schemas; i++) {
        RUN_TEST1(schema_complete_root, &g_schemas[i]);
    }
    for (size_t i = 0; i < g_num_schemas; i++) {
        RUN_TEST1(schema_generate_no_desc, &g_schemas[i]);
    }
}

SUITE(suite_integration) {
    /* Generate blobs first — other tests depend on them */
    RUN_TEST(generate_func_blob);
    RUN_TEST(generate_minimal_blob);

    /* Validation/linting */
    RUN_TEST(check_blob_exists_and_missing);
    RUN_TEST(dump_header_minimal_blob);
    RUN_TEST(validate_func_blob);
    RUN_TEST(lint_func_schema);
    RUN_TEST(lint_minimal_schema);

    /* Completion tests */
    RUN_TEST(complete_func_subcommands);
    RUN_TEST(complete_func_flags);
    RUN_TEST(complete_func_choices);
    RUN_TEST(complete_minimal_subcommands);
    RUN_TEST(complete_minimal_choices);
    RUN_TEST(complete_minimal_members);
    RUN_TEST(quiet_missing_blob_is_silent);
    RUN_TEST(add_space_appends_space_to_values);
    RUN_TEST(full_commands_emits_leaf_paths);
    RUN_TEST(dynamic_completer_returns_values);
    RUN_TEST(dynamic_completer_timeout_override);
    RUN_TEST(complete_prefix_filter);
    RUN_TEST(complete_flag_prefix);
    RUN_TEST(complete_pnpm_config_delete_leaf);

    /* Error cases */
    RUN_TEST(lint_malformed_schema);
}

/* ======================================================================
 * Main
 * ====================================================================== */

GREATEST_MAIN_DEFS();

int main(int argc, char *argv[]) {
    setup_blobs();
    atexit(cleanup_blobs);

    GREATEST_MAIN_BEGIN();
    RUN_SUITE(suite_all_schemas);
    RUN_SUITE(suite_integration);
    GREATEST_MAIN_END();
}
