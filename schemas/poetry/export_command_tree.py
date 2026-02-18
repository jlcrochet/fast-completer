#!/usr/bin/env python3
"""Export poetry command tree for fast-completer.

Poetry uses Symfony Console which lists commands via `poetry list` rather
than `poetry --help`. We parse the flat list and build the tree ourselves,
then fetch flags for each leaf command via `poetry <cmd> --help`.
"""
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import command_cache
from helptext_exporter import (HelptextExportConfig, run_command,
                                get_cli_version, parse_flags,
                                CommandTree, write_param)


INHERITED_SKIP = {'-h', '--help', '-V', '--version',
                  '-q', '--quiet', '-n', '--no-interaction',
                  '--ansi', '--no-ansi', '--no-plugins',
                  '--no-cache', '-v', '--verbose',
                  '-P', '--project', '-C', '--directory'}


def parse_poetry_list(config):
    """Parse `poetry list --no-ansi` into a list of (parts, description)."""
    output, _ = run_command(config.binary, 'list', '--no-ansi',
                            timeout=config.timeout)
    if not output:
        return []

    commands = []
    in_commands = False

    for line in output.split('\n'):
        stripped = line.strip()

        if re.match(r'^Available commands:', stripped):
            in_commands = True
            continue

        if not in_commands:
            continue

        # Group header: " cache" (skip, we'll infer from commands)
        if re.match(r'^ \w+$', line):
            continue

        # Command: "  command  description" or "  group subcmd  desc"
        m = re.match(r'^\s{2,}([\w][\w .-]*\w)\s{2,}(.+)', line)
        if m:
            full_name = m.group(1).strip()
            desc = m.group(2).strip()
            parts = full_name.split()
            if parts[0] not in ('help', 'list'):
                commands.append((parts, desc))

    return commands


def main():
    config = HelptextExportConfig(
        cli_name='poetry',
        root_description='Python package manager',
        schema_comment='Poetry CLI schema for fast-completer',
        inherited_skip_flags=INHERITED_SKIP,
    )

    if not command_cache.auto_setup(config.cli_name, config.binary):
        sys.exit(1)

    version = get_cli_version(config)

    print(f"Exporting poetry {version} commands...", file=sys.stderr)

    # Parse global flags from `poetry list --no-ansi` (the Options: section)
    global_flags = parse_flags(config, [])

    # Get all commands from `poetry list`
    all_commands = parse_poetry_list(config)
    print(f"Found {len(all_commands)} commands", file=sys.stderr)

    # Build tree and fetch flags for each leaf command
    tree = CommandTree()
    for parts, desc in all_commands:
        # Get flags for this specific command
        flags = parse_flags(config, parts)
        tree.add_command(parts, desc, flags)

    # Write schema
    print(f"# {config.schema_comment}", file=sys.stdout)
    print(f"# Generated from poetry {version}", file=sys.stdout)
    print("", file=sys.stdout)
    print(f"poetry # {config.root_description}", file=sys.stdout)

    for p in global_flags:
        write_param(p, 1, sys.stdout)

    for name in sorted(tree.children.keys()):
        tree.children[name].write(sys.stdout, indent=1)

    command_cache.save()


if __name__ == '__main__':
    main()
