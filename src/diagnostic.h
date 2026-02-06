#ifndef FCMP_DIAGNOSTIC_H
#define FCMP_DIAGNOSTIC_H

#include <stdbool.h>

#if defined(__MINGW32__) || defined(__MINGW64__)
#define FCMP_PRINTF_ATTR(fmt_idx, first_arg_idx) __attribute__((format(gnu_printf, fmt_idx, first_arg_idx)))
#elif defined(__GNUC__) || defined(__clang__)
#define FCMP_PRINTF_ATTR(fmt_idx, first_arg_idx) __attribute__((format(printf, fmt_idx, first_arg_idx)))
#else
#define FCMP_PRINTF_ATTR(fmt_idx, first_arg_idx)
#endif

void fcmp_diag_init(void);

void fcmp_infof(const char *fmt, ...) FCMP_PRINTF_ATTR(1, 2);
void fcmp_warnf(const char *fmt, ...) FCMP_PRINTF_ATTR(1, 2);
void fcmp_errorf(const char *fmt, ...) FCMP_PRINTF_ATTR(1, 2);
void fcmp_perror(const char *what);

#ifdef _WIN32
void fcmp_win32_errorf(const char *what, unsigned long code);
#endif

#endif
