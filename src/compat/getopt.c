/*
 * Portable getopt/getopt_long implementation
 * Based on musl libc (MIT licensed)
 * https://git.musl-libc.org/cgit/musl/
 *
 * Modifications for standalone use:
 * - Removed musl internal dependencies (locale_impl.h, stdio_impl.h)
 * - Simplified for single-byte locales (removed wchar/mbtowc)
 * - Made Windows/MSVC compatible
 */

#include "getopt.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

char *optarg;
int optind = 1, opterr = 1, optopt;
static int optpos;

static void getopt_msg(const char *prog, const char *msg, const char *opt, size_t len)
{
    if (opterr) {
        fprintf(stderr, "%s%s%.*s\n", prog, msg, (int)len, opt);
    }
}

int getopt(int argc, char * const argv[], const char *optstring)
{
    int i;
    char c;
    const char *optchar;

    if (optind >= argc || !argv[optind])
        return -1;

    if (argv[optind][0] != '-') {
        if (optstring[0] == '-') {
            optarg = argv[optind++];
            return 1;
        }
        return -1;
    }

    if (!argv[optind][1])
        return -1;

    if (argv[optind][1] == '-' && !argv[optind][2])
        return optind++, -1;

    if (!optpos) optpos++;
    c = argv[optind][optpos];
    optchar = argv[optind] + optpos;
    optpos++;

    if (!argv[optind][optpos]) {
        optind++;
        optpos = 0;
    }

    if (optstring[0] == '-' || optstring[0] == '+')
        optstring++;

    for (i = 0; optstring[i]; i++) {
        if (optstring[i] == c && c != ':')
            break;
    }

    if (!optstring[i] || c == ':') {
        optopt = c;
        getopt_msg(argv[0], ": unrecognized option: ", optchar, 1);
        return '?';
    }

    if (optstring[i + 1] == ':') {
        optarg = NULL;
        if (optstring[i + 2] != ':' || optpos) {
            optarg = argv[optind++];
            if (optpos) optarg += optpos;
            optpos = 0;
        }
        if (optind > argc) {
            optopt = c;
            if (optstring[0] == ':') return ':';
            getopt_msg(argv[0], ": option requires an argument: ", optchar, 1);
            return '?';
        }
    }
    return c;
}

static int getopt_long_core(int argc, char * const *argv, const char *optstring,
                            const struct option *longopts, int *idx)
{
    optarg = NULL;
    if (longopts && argv[optind][0] == '-' && argv[optind][1] == '-' && argv[optind][2]) {
        int colon = optstring[optstring[0] == '+' || optstring[0] == '-'] == ':';
        int i, cnt, match = 0;
        const char *opt, *arg;
        char *start = argv[optind] + 2;

        for (cnt = i = 0; longopts[i].name; i++) {
            const char *name = longopts[i].name;
            opt = start;
            while (*opt && *opt != '=' && *opt == *name)
                name++, opt++;
            if (*opt && *opt != '=') continue;
            arg = opt;
            match = i;
            if (!*name) {
                cnt = 1;
                break;
            }
            cnt++;
        }

        if (cnt == 1) {
            i = match;
            opt = arg;
            optind++;
            if (*opt == '=') {
                if (!longopts[i].has_arg) {
                    optopt = longopts[i].val;
                    if (colon || !opterr)
                        return '?';
                    getopt_msg(argv[0],
                        ": option does not take an argument: ",
                        longopts[i].name, strlen(longopts[i].name));
                    return '?';
                }
                optarg = (char *)opt + 1;
            } else if (longopts[i].has_arg == required_argument) {
                if (!(optarg = argv[optind])) {
                    optopt = longopts[i].val;
                    if (colon) return ':';
                    if (!opterr) return '?';
                    getopt_msg(argv[0],
                        ": option requires an argument: ",
                        longopts[i].name, strlen(longopts[i].name));
                    return '?';
                }
                optind++;
            }
            if (idx) *idx = i;
            if (longopts[i].flag) {
                *longopts[i].flag = longopts[i].val;
                return 0;
            }
            return longopts[i].val;
        }

        if (argv[optind][1] == '-') {
            optopt = 0;
            if (!colon && opterr)
                getopt_msg(argv[0], cnt ?
                    ": option is ambiguous: " :
                    ": unrecognized option: ",
                    argv[optind] + 2, strlen(argv[optind] + 2));
            optind++;
            return '?';
        }
    }
    return getopt(argc, argv, optstring);
}

int getopt_long(int argc, char * const *argv, const char *optstring,
                const struct option *longopts, int *idx)
{
    if (optind >= argc || !argv[optind])
        return -1;

    /* POSIX mode ('+' prefix): stop at first non-option */
    if (optstring[0] == '+' && argv[optind][0] != '-')
        return -1;

    return getopt_long_core(argc, argv, optstring, longopts, idx);
}
