#!/usr/bin/env python3
"""
Shared oclif CLI exporter for fast-completer.

Parses `<cli> commands --json` output from any oclif-based CLI and writes
an .fcmps schema file. Each CLI provides a thin wrapper that calls
export_oclif_cli() with an OclifExportConfig.

Used by: heroku, sf, netlify, twilio.
"""

import json
import re
import sys
from dataclasses import dataclass, field
from typing import Optional, Set

import command_cache


@dataclass
class OclifExportConfig:
    """Configuration for an oclif CLI export."""
    cli_name: str
    root_description: str
    schema_comment: str
    cli_path: Optional[str] = None  # path to binary (defaults to cli_name)
    skip_flags: Set[str] = field(default_factory=lambda: {'help'})
    commands_args: tuple = ('commands', '--json')
    version_args: tuple = ('--version',)
    version_regex: Optional[str] = None
    timeout: int = 60
    separator: str = ':'  # command ID separator (e.g. "apps:create")

    @property
    def binary(self):
        """Return the actual binary path to invoke."""
        return self.cli_path or self.cli_name


def run_command(*args, timeout=60):
    """Run a command and return (stdout, returncode)."""
    return command_cache.execute(*args, timeout=timeout)


def get_cli_version(config):
    """Get CLI version string."""
    output, _ = run_command(config.binary, *config.version_args)
    regex = config.version_regex or r'([\d]+\.[\d]+\.[\d]+)'
    match = re.search(regex, output)
    return match.group(1) if match else 'unknown'


def get_commands_json(config):
    """Get all commands via <cli> commands --json."""
    output, rc = run_command(
        config.binary, *config.commands_args, timeout=config.timeout
    )
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def flag_to_param(flag_name, flag_def):
    """Convert an oclif flag definition to a param dict."""
    param = {'name': f'--{flag_name}'}

    char = flag_def.get('char')
    if char:
        param['short'] = f'-{char}'

    desc = flag_def.get('description') or flag_def.get('summary') or ''
    if desc:
        param['description'] = desc

    flag_type = flag_def.get('type', 'option')
    if flag_type == 'boolean':
        param['type'] = 'bool'
    elif flag_def.get('options'):
        param['choices'] = list(flag_def['options'])

    return param


def escape_field(s):
    """Escape a field for schema output."""
    if not s:
        return ''
    return s.replace('\t', ' ').replace('\n', ' ').replace('\r', '')


def write_param(p, indent, file):
    """Output single param line in schema format."""
    name = p.get('name', '')
    short = p.get('short')

    if not name.startswith('-'):
        return

    if short:
        opt_spec = f"{name}|{short}"
    else:
        opt_spec = name

    type_field = ''
    if p.get('type') == 'bool':
        type_field = '@bool'
    elif p.get('choices'):
        type_field = '(' + '|'.join(p['choices']) + ')'

    desc = escape_field(p.get('description', ''))
    tabs = '\t' * indent

    parts = [f"{tabs}{opt_spec}"]
    if type_field:
        parts.append(type_field)
    if desc:
        parts.append(f"# {desc}")
    print(' '.join(parts), file=file)


class CommandTree:
    """Tree structure for organizing commands by path."""

    def __init__(self, name='', description=''):
        self.name = name
        self.description = description
        self.parameters = []
        self.children = {}

    def add_command(self, path_parts, description='', parameters=None):
        """Add a command at the given path, creating intermediates."""
        if not path_parts:
            if description:
                self.description = description
            if parameters:
                self.parameters = parameters
            return

        first = path_parts[0]
        if first not in self.children:
            self.children[first] = CommandTree(first)
        self.children[first].add_command(path_parts[1:], description, parameters)

    def write(self, file, indent=1):
        """Write this node and its children."""
        tabs = '\t' * indent
        desc = escape_field(self.description)
        if desc:
            print(f"{tabs}{self.name} # {desc}", file=file)
        else:
            print(f"{tabs}{self.name}", file=file)

        for p in self.parameters:
            write_param(p, indent + 1, file)

        for name in sorted(self.children.keys()):
            self.children[name].write(file, indent + 1)


def export_oclif_cli(config):
    """Main entry point: export an oclif CLI's command tree to .fcmps on stdout."""
    if not command_cache.auto_setup(config.cli_name, config.binary):
        sys.exit(1)

    version = get_cli_version(config)

    print(f"Exporting {config.cli_name} {version} commands via oclif JSON...",
          file=sys.stderr)

    commands_json = get_commands_json(config)
    if commands_json is None:
        print(f"Error: failed to get {config.cli_name} commands --json",
              file=sys.stderr)
        sys.exit(1)

    root = CommandTree()
    command_count = 0

    for cmd in commands_json:
        if cmd.get('hidden', False):
            continue

        cmd_id = cmd.get('id', '')
        if not cmd_id:
            continue

        parts = cmd_id.split(config.separator)

        desc = cmd.get('description') or cmd.get('summary') or ''
        if '. ' in desc:
            desc = desc[:desc.index('. ') + 1]

        params = []
        flags = cmd.get('flags', {})
        if isinstance(flags, list):
            for f in flags:
                fname = f.get('name', '')
                if fname in config.skip_flags:
                    continue
                params.append(flag_to_param(fname, f))
        else:
            for fname, fdef in sorted(flags.items()):
                if fname in config.skip_flags:
                    continue
                params.append(flag_to_param(fname, fdef))

        root.add_command(parts, desc, params)
        command_count += 1

    print(f"Exported {command_count} commands", file=sys.stderr)

    print(f"# {config.schema_comment}", file=sys.stdout)
    print(f"# Generated from {config.cli_name} {version}", file=sys.stdout)
    print("", file=sys.stdout)
    print(f"{config.cli_name} # {config.root_description}", file=sys.stdout)

    for name in sorted(root.children.keys()):
        root.children[name].write(sys.stdout, indent=1)

    command_cache.save()
