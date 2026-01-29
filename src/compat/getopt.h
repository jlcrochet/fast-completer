/*
 * Portable getopt/getopt_long implementation
 * Based on musl libc (MIT licensed)
 * https://git.musl-libc.org/cgit/musl/
 *
 * Modifications for standalone use:
 * - Removed musl internal dependencies
 * - Simplified for single-byte locales
 * - Made Windows/MSVC compatible
 */

#ifndef COMPAT_GETOPT_H
#define COMPAT_GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

extern char *optarg;
extern int optind, opterr, optopt;

struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

#define no_argument        0
#define required_argument  1
#define optional_argument  2

int getopt(int argc, char * const argv[], const char *optstring);
int getopt_long(int argc, char * const *argv, const char *optstring,
                const struct option *longopts, int *idx);

#ifdef __cplusplus
}
#endif

#endif /* COMPAT_GETOPT_H */
