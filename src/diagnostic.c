#include "diagnostic.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#define ANSI_RED "\x1b[31m"
#define ANSI_YELLOW "\x1b[33m"
#define ANSI_RESET "\x1b[0m"

static bool g_diag_inited = false;
static bool g_diag_use_color = false;

static bool stderr_is_tty_impl(void) {
#ifdef _WIN32
    return _isatty(_fileno(stderr));
#else
    return isatty(fileno(stderr));
#endif
}

#ifdef _WIN32
static bool win32_enable_vt_on_stderr(void) {
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode)) return false;
    if (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) return true;
    if (!SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) return false;
    return true;
}
#endif

void fcmp_diag_init(void) {
    if (g_diag_inited) return;
    g_diag_inited = true;
    g_diag_use_color = stderr_is_tty_impl();
#ifdef _WIN32
    if (g_diag_use_color) g_diag_use_color = win32_enable_vt_on_stderr();
#endif
}

static void diag_vprint(const char *color, const char *fmt, va_list ap) {
    if (!g_diag_inited) fcmp_diag_init();
    if (g_diag_use_color && color) fputs(color, stderr);
    vfprintf(stderr, fmt, ap);
    if (g_diag_use_color && color) fputs(ANSI_RESET, stderr);
}

void fcmp_infof(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    diag_vprint(NULL, fmt, ap);
    va_end(ap);
}

void fcmp_warnf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    diag_vprint(ANSI_YELLOW, fmt, ap);
    va_end(ap);
}

void fcmp_errorf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    diag_vprint(ANSI_RED, fmt, ap);
    va_end(ap);
}

void fcmp_perror(const char *what) {
    int err = errno;
    if (!g_diag_inited) fcmp_diag_init();
    if (g_diag_use_color) fputs(ANSI_RED, stderr);
    fprintf(stderr, "%s: %s\n", what, strerror(err));
    if (g_diag_use_color) fputs(ANSI_RESET, stderr);
}

#ifdef _WIN32
void fcmp_win32_errorf(const char *what, unsigned long code) {
    if (!g_diag_inited) fcmp_diag_init();
    if (g_diag_use_color) fputs(ANSI_RED, stderr);
    fprintf(stderr, "%s: %lu\n", what, code);
    if (g_diag_use_color) fputs(ANSI_RESET, stderr);
}
#endif
