#!/usr/bin/env python3
"""Export pacman command tree for fast-completer.

pacman uses operations (-S, -Q, -R, etc.) as pseudo-subcommands,
each with its own set of flags. This script invokes `pacman <op> --help`
for each operation and parses the flags.
"""
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from command_cache import auto_setup, execute

auto_setup(Path(__file__).parent)

OPERATIONS = [
    ('-D', '--database', 'database', 'Modify the package database'),
    ('-F', '--files', 'files', 'Query the files database'),
    ('-Q', '--query', 'query', 'Query installed packages'),
    ('-R', '--remove', 'remove', 'Remove packages'),
    ('-S', '--sync', 'sync', 'Synchronize packages'),
    ('-T', '--deptest', 'deptest', 'Check dependency satisfaction'),
    ('-U', '--upgrade', 'upgrade', 'Upgrade or add packages from file'),
]

# Flags shared across all operations (shown in every --help)
GLOBAL_SKIP = {
    '-b', '--dbpath', '-r', '--root', '-v', '--verbose',
    '--arch', '--cachedir', '--color', '--config', '--confirm',
    '--debug', '--disable-download-timeout', '--gpgdir', '--hookdir',
    '--logfile', '--noconfirm', '--sysroot',
}


def parse_flags(text):
    """Parse flag lines from pacman help output."""
    flags = []
    for line in text.splitlines():
        m = re.match(r'^\s+(-\w)(?:,\s+(--[\w-]+))?\s*(.*)', line)
        if not m:
            m = re.match(r'^\s+(--[\w-]+)\s*(.*)', line)
            if not m:
                continue
            long_flag = m.group(1)
            desc = m.group(2).strip()
            short_flag = None
        else:
            short_flag = m.group(1)
            long_flag = m.group(2)
            desc = m.group(3).strip()

        # Skip global flags
        if short_flag in GLOBAL_SKIP or long_flag in GLOBAL_SKIP:
            continue
        # Skip help/version
        if long_flag in ('--help', '--version') or short_flag in ('-h', '-V'):
            continue

        # Check if flag takes a value (has <arg> or similar)
        takes_value = bool(re.search(r'<\w+>', line))

        flags.append((short_flag, long_flag, takes_value, desc))
    return flags


def fmt_flag(short, long, takes_value, desc):
    """Format a flag in .fcmps syntax."""
    parts = []
    if long:
        parts.append(long)
    if short:
        parts.append(f'|{short}')
    name = ''.join(parts)
    if not takes_value:
        name += ' @bool'
    if desc:
        return f'\t\t{name} # {desc}'
    return f'\t\t{name}'


def main():
    lines = []
    lines.append('# Pacman CLI schema for fast-completer')
    lines.append('pacman # Arch Linux package manager')

    # Global flags (from root --help)
    lines.append('\t--dbpath|-b # Set an alternate database location')
    lines.append('\t--root|-r # Set an alternate installation root')
    lines.append('\t--verbose|-v @bool # Be verbose')
    lines.append('\t--arch # Set an alternate architecture')
    lines.append('\t--cachedir # Set an alternate package cache location')
    lines.append('\t--color (auto|always|never) # Colorize the output')
    lines.append('\t--config # Set an alternate configuration file')
    lines.append('\t--confirm @bool # Always ask for confirmation')
    lines.append('\t--debug @bool # Display debug messages')
    lines.append('\t--disable-download-timeout @bool # Disable download timeout')
    lines.append('\t--gpgdir # Set an alternate home directory for GnuPG')
    lines.append('\t--hookdir # Set an alternate hook location')
    lines.append('\t--logfile # Set an alternate log file')
    lines.append('\t--noconfirm @bool # Do not ask for any confirmation')
    lines.append('\t--sysroot # Set an alternate system root')

    for short, long, name, desc in OPERATIONS:
        lines.append(f'\t{name} # {desc}')

        out, rc = execute('pacman', short, '--help', timeout=5)
        if rc != 0:
            continue

        flags = parse_flags(out)
        for s, l, tv, d in flags:
            lines.append(fmt_flag(s, l, tv, d))

    print('\n'.join(lines))


if __name__ == '__main__':
    main()
