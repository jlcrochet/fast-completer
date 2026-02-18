#!/usr/bin/env python3
"""Export conda command tree for fast-completer.

Conda uses argparse which puts subcommands under 'commands:' at the top
level but under 'positional arguments:' or 'subcommands:' at nested levels.
This custom exporter handles both patterns.
"""
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import command_cache
from helptext_exporter import (HelptextExportConfig, run_command,
                                get_cli_version, parse_flags,
                                CommandTree, write_param)


INHERITED_SKIP = {'-h', '--help', '-V', '--version'}

# Commands to skip entirely
SKIP_COMMANDS = {'help', 'commands'}


def discover_subcommands(config, command_parts):
    """Parse conda help for subcommands, handling argparse patterns.

    Argparse puts subcommands under 'commands:', 'subcommands:', or
    'positional arguments:' sections. In 'positional arguments:', only
    entries at deeper indent (4+ spaces, under a metavar/brace-list) are
    subcommands — entries at normal indent (2 spaces) with descriptions
    are regular positional args.
    """
    args = [config.binary] + list(command_parts) + ['--help']
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return []

    subcommands = []
    # 'commands' = in a commands/subcommands section (all entries are subcmds)
    # 'positional' = in positional arguments section (need deeper indent check)
    section_type = None
    # In positional args, set True after seeing metavar/brace-list
    saw_metavar = False

    for line in output.split('\n'):
        stripped = line.strip()

        # Detect section headers (case-insensitive)
        lower = stripped.lower()
        if lower in ('commands:', 'subcommands:', 'subcommand:') or \
           re.match(r'^(available |main |other )?commands:?\s*$', lower):
            section_type = 'commands'
            saw_metavar = False
            continue

        if lower == 'positional arguments:':
            section_type = 'positional'
            saw_metavar = False
            continue

        # End of section on 'options:' or similar non-command headers
        if lower in ('options:', 'optional arguments:', 'usage:',
                      'flags:', 'arguments:'):
            section_type = None
            continue

        # Non-indented section header ending with ':'
        if stripped and not stripped[0].isspace() and stripped.endswith(':') \
                and not stripped.startswith('-'):
            if re.match(r'^[A-Za-z][\w\s\'"-]+:$', stripped):
                if section_type:
                    section_type = None
                continue

        if not section_type:
            continue

        # Skip blank lines within section
        if not stripped:
            continue

        # Detect argparse brace choices: {cmd1,cmd2,...}
        m = re.match(r'^\s+\{([\w,.-]+)\}', line)
        if m:
            saw_metavar = True
            continue

        # Metavar line: "  COMMAND" or "  command" (no description)
        if re.match(r'^\s{2,8}[A-Za-z_]+\s*$', line):
            if section_type == 'positional':
                saw_metavar = True
            continue

        # Subcommand entry: "    name    description"
        m = re.match(r'^(\s+)([\w][\w.-]*(?:\s+\([\w.-]+\))?)\s{2,}(.+)', line)
        if m:
            indent = len(m.group(1))
            raw_name = m.group(2).strip()
            desc = m.group(3).strip()
            name = raw_name.split()[0] if ' ' in raw_name else raw_name

            if not re.fullmatch(r'[\w][\w.-]*', name) or name in SKIP_COMMANDS:
                continue

            if section_type == 'commands':
                # In commands section, all entries are subcommands
                subcommands.append({'name': name, 'summary': desc})
            elif section_type == 'positional' and saw_metavar and indent >= 4:
                # In positional args, only deeper-indented entries after
                # a metavar/brace-list are subcommands
                subcommands.append({'name': name, 'summary': desc})
            continue

        # Non-indented line = end of section
        if not re.match(r'^\s', line) and stripped:
            section_type = None

    return subcommands


def walk_commands(config, command_parts=None, depth=0, seen=None):
    """Recursively discover commands and their flags."""
    if command_parts is None:
        command_parts = []
    if seen is None:
        seen = set()

    if depth > 5:
        return

    command_path = ' '.join(command_parts)
    if command_path in seen:
        return
    seen.add(command_path)

    subcommands = discover_subcommands(config, command_parts)

    if subcommands:
        # Group command with flags
        if command_path:
            flags = parse_flags(config, command_parts)
            yield {
                'name': command_path,
                'description': '',
                'parameters': flags,
            }
        for sub in subcommands:
            yield from walk_commands(
                config,
                command_parts + [sub['name']],
                depth + 1,
                seen
            )
    else:
        # Leaf command
        if command_path:
            flags = parse_flags(config, command_parts)
            yield {
                'name': command_path,
                'description': '',
                'parameters': flags,
            }


def main():
    config = HelptextExportConfig(
        cli_name='conda',
        root_description='Package, dependency and environment management',
        schema_comment='Conda CLI schema for fast-completer',
        inherited_skip_flags=INHERITED_SKIP,
    )

    if not command_cache.auto_setup(config.cli_name, config.binary):
        sys.exit(1)

    version = get_cli_version(config)

    print(f"Exporting conda {version} commands...", file=sys.stderr)

    # Discover top-level subcommands
    top_level = discover_subcommands(config, [])
    print(f"Found {len(top_level)} top-level commands", file=sys.stderr)

    # Get global flags
    global_flags = parse_flags(config, [])

    # Walk all commands recursively
    commands = sorted(walk_commands(config), key=lambda x: x['name'])
    print(f"Exported {len(commands)} commands", file=sys.stderr)

    # Build description map from discovery
    desc_map = {}
    for sub in top_level:
        desc_map[sub['name']] = sub['summary']

    # Write schema
    print(f"# {config.schema_comment}", file=sys.stdout)
    print(f"# Generated from conda {version}", file=sys.stdout)
    print("", file=sys.stdout)
    print(f"conda # {config.root_description}", file=sys.stdout)

    for p in global_flags:
        write_param(p, 1, sys.stdout)

    root = CommandTree()
    for cmd in commands:
        parts = cmd['name'].split()
        root.add_command(parts, cmd.get('description', ''),
                         cmd.get('parameters', []))

    # Apply descriptions from top-level discovery
    for name, child in root.children.items():
        if name in desc_map and not child.description:
            child.description = desc_map[name]

    for name in sorted(root.children.keys()):
        root.children[name].write(sys.stdout, indent=1)

    command_cache.save()


if __name__ == '__main__':
    main()
