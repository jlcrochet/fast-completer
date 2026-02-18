#!/usr/bin/env python3
"""
Shared Cobra CLI exporter for fast-completer.

Walks a Cobra-based CLI's command tree using the __complete API and writes
an .fcmps schema file. Each CLI provides a thin wrapper that calls
export_cobra_cli() with a CobraExportConfig.

Used by: kubectl, docker, helm, podman, pulumi (and gh, which has its own
copy with gh-specific dynamic completers).
"""

import re
import sys
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

import command_cache


@dataclass
class CobraExportConfig:
    """Configuration for a Cobra CLI export."""
    cli_name: str
    root_description: str
    schema_comment: str
    cli_path: Optional[str] = None  # path to binary (defaults to cli_name)
    dynamic_completers: Dict[Tuple[str, str], str] = field(default_factory=dict)
    inherited_skip_flags: Set[str] = field(default_factory=lambda: {'--help', '--version'})
    max_depth: int = 6
    timeout: int = 30
    value_keywords: Set[str] = field(
        default_factory=lambda: {'string', 'int', 'file', 'path', 'name', 'number'}
    )
    version_args: Tuple[str, ...] = ('--version',)
    version_regex: Optional[str] = None  # auto-derived from cli_name if None
    complete_command: str = '__complete'

    @property
    def binary(self):
        """Return the actual binary path to invoke."""
        return self.cli_path or self.cli_name


def run_command(*args, timeout=30):
    """Run a command and return (stdout, returncode)."""
    return command_cache.execute(*args, timeout=timeout)


def get_cli_version(config):
    """Get CLI version string."""
    output, _ = run_command(config.binary, *config.version_args)
    regex = config.version_regex or re.escape(config.cli_name) + r'[:\s]+.*?v?([\d.]+)'
    match = re.search(regex, output, re.IGNORECASE)
    if match:
        return match.group(1)
    # Try matching any version-like string
    match = re.search(r'v?([\d]+\.[\d]+\.[\d]+)', output)
    return match.group(1) if match else 'unknown'


def parse_cobra_completions(config, command_parts):
    """
    Use Cobra's __complete command to get completions.
    Returns list of (completion, description) tuples.
    """
    args = [config.binary, config.complete_command] + list(command_parts) + ['']
    output, rc = run_command(*args, timeout=config.timeout)

    if rc not in (0, 2) or not output:  # Cobra returns 0 or 2 for completions
        return []

    completions = []
    for line in output.strip().split('\n'):
        if line.startswith(':'):
            continue
        if '\t' in line:
            comp, desc = line.split('\t', 1)
            completions.append((comp, desc))
        elif line:
            completions.append((line, ''))

    return completions


def get_command_flags(config, command_parts):
    """Get flags for a command using __complete with -- prefix."""
    args = [config.binary, config.complete_command] + list(command_parts) + ['--']
    output, rc = run_command(*args, timeout=config.timeout)

    if rc not in (0, 2) or not output:
        return []

    flags = []
    for line in output.strip().split('\n'):
        if line.startswith(':'):
            continue
        if '\t' in line:
            flag, desc = line.split('\t', 1)
            if flag.startswith('-'):
                flags.append({'name': flag, 'summary': desc})
        elif line.startswith('-'):
            flags.append({'name': line, 'summary': ''})

    return flags


def get_subcommands(config, command_parts):
    """Get subcommands for a command group."""
    completions = parse_cobra_completions(config, command_parts)
    subcommands = []
    for comp, desc in completions:
        # Skip flags, directives, empty, activeHelp, and path completions
        if not comp or comp.startswith(('-', ':', '_')) or '/' in comp:
            continue
        # Must look like a valid command name (alphanumeric, hyphens, dots)
        if not re.fullmatch(r'[\w][\w.-]*', comp):
            continue
        subcommands.append({'name': comp, 'summary': desc})
    return subcommands


# Regex for parsing Cobra --help flag lines.
# Matches:  "  -s, --long TYPE   description"  or  "      --long TYPE   description"
# Group 1: short flag (e.g. "-s"), Group 2: long flag (e.g. "--long"),
# Group 3: type specifier if present (e.g. "string", "int").
_HELP_FLAG_RE = re.compile(
    r'^\s+'
    r'(?:(-\w),\s+)?'        # optional short flag
    r'(--[\w][\w.-]*)'        # long flag
    r'(?:\s+(\S+))?'          # optional type (string, int, etc.)
    r'\s{2,}'                 # gap before description
)


def parse_help_value_flags(config, command_parts):
    """
    Parse --help output to determine which flags take values.

    Cobra help reliably shows a type specifier (string, int, duration, etc.)
    after flags that take values, and nothing after boolean flags. Returns the
    set of long flag names (e.g. '--host') that take values.
    """
    args = [config.binary] + list(command_parts) + ['--help']
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return set()

    value_flags = set()
    for line in output.split('\n'):
        m = _HELP_FLAG_RE.match(line)
        if m and m.group(3):
            # Has a type specifier → takes a value
            value_flags.add(m.group(2))

    return value_flags


def build_flags_list(config, command_path, raw_flags, help_value_flags=None):
    """Convert raw flags to parameter format with short/long options."""
    params = []
    seen = set()

    for f in raw_flags:
        name = f['name']
        if name in seen or name in config.inherited_skip_flags:
            continue
        seen.add(name)

        param = {
            'name': name,
            'description': f['summary'],
        }

        # Determine if boolean: use help-parsed info if available, else heuristic
        is_value_flag = False
        if '=' in name:
            # Explicit value marker from __complete (e.g. gh)
            is_value_flag = True
        elif help_value_flags is not None:
            # Use parsed --help output (reliable for all Cobra CLIs)
            clean_name = name.rstrip('=')
            is_value_flag = clean_name in help_value_flags
        elif any(x in f['summary'].lower() for x in config.value_keywords):
            # Fallback: keyword heuristic
            is_value_flag = True

        if not is_value_flag:
            param['type'] = 'bool'

        # Check for dynamic completer
        completer_key = (command_path, name)
        if completer_key in config.dynamic_completers:
            param['completer'] = config.dynamic_completers[completer_key]

        params.append(param)

    return params


def walk_commands(config, command_parts=None, depth=0, seen=None, parent_descriptions=None):
    """
    Recursively discover all commands using __complete.

    Improved over the gh exporter: captures descriptions for group commands
    (not just leaves) by propagating descriptions from the parent's
    subcommand listing.
    """
    if command_parts is None:
        command_parts = []
    if seen is None:
        seen = set()
    if parent_descriptions is None:
        parent_descriptions = {}

    if depth > config.max_depth:
        return

    command_path = ' '.join(command_parts)

    if command_path in seen:
        return
    seen.add(command_path)

    subcommands = get_subcommands(config, command_parts)

    if subcommands:
        # This is a group command — emit it with its description and flags
        if command_path:
            raw_flags = get_command_flags(config, command_parts)
            help_value = parse_help_value_flags(config, command_parts)
            params = build_flags_list(config, command_path, raw_flags, help_value)

            desc = parent_descriptions.get(command_path, '')
            cmd = {
                'name': command_path,
                'description': desc,
                'parameters': params,
            }

            pos_key = (command_path, '')
            if pos_key in config.dynamic_completers:
                cmd['positional_completer'] = config.dynamic_completers[pos_key]

            yield cmd

        # Build description map for children
        child_descriptions = {}
        for sub in subcommands:
            child_path = f"{command_path} {sub['name']}".strip()
            child_descriptions[child_path] = sub['summary']

        for sub in subcommands:
            yield from walk_commands(
                config,
                command_parts + [sub['name']],
                depth + 1,
                seen,
                child_descriptions
            )
    else:
        # Leaf command
        if command_path:
            raw_flags = get_command_flags(config, command_parts)
            help_value = parse_help_value_flags(config, command_parts)
            params = build_flags_list(config, command_path, raw_flags, help_value)

            desc = parent_descriptions.get(command_path, '')
            cmd = {
                'name': command_path,
                'description': desc,
                'parameters': params,
            }

            pos_key = (command_path, '')
            if pos_key in config.dynamic_completers:
                cmd['positional_completer'] = config.dynamic_completers[pos_key]

            yield cmd


def escape_field(s):
    """Escape a field for schema output (replace tabs and newlines)."""
    if not s:
        return ''
    return s.replace('\t', ' ').replace('\n', ' ').replace('\r', '')


def write_param(p, indent=1, file=sys.stdout):
    """Output single param line in schema format."""
    name = p.get('name', '')

    long_opt = None
    short_opt = None

    if name.startswith('--'):
        long_opt = name
    elif name.startswith('-') and len(name) == 2:
        short_opt = name

    if not long_opt and not short_opt:
        return

    is_bool = (p.get('type') == 'bool' or not p.get('takes_value', True))

    if long_opt and short_opt:
        opt_spec = f"{long_opt}|{short_opt}"
    elif long_opt:
        opt_spec = long_opt
    else:
        opt_spec = short_opt

    type_field = ''
    if is_bool:
        type_field = '@bool'
    elif p.get('choices'):
        type_field = '(' + '|'.join(p['choices']) + ')'
    elif p.get('members'):
        keys = [m['key'] if isinstance(m, dict) else m for m in p['members']]
        type_field = '{' + '|'.join(keys) + '}'
    elif p.get('completer'):
        type_field = '`' + p['completer'] + '`'

    desc = escape_field(p.get('description') or p.get('summary') or '')
    tabs = '\t' * indent

    parts = [f"{tabs}{opt_spec}"]
    if type_field:
        parts.append(type_field)
    if desc:
        parts.append(f"# {desc}")
    print(' '.join(parts), file=file)


class CommandTree:
    """Tree structure for organizing commands by path."""

    def __init__(self, name='', description='', parameters=None):
        self.name = name
        self.description = description
        self.parameters = parameters or []
        self.positional_completer = None
        self.children = {}

    def add_command(self, path_parts, description='', parameters=None,
                    positional_completer=None):
        """Add a command at the given path."""
        if not path_parts:
            if description:
                self.description = description
            if parameters:
                self.parameters = parameters
            if positional_completer:
                self.positional_completer = positional_completer
            return

        first = path_parts[0]
        if first not in self.children:
            self.children[first] = CommandTree(first)
        self.children[first].add_command(
            path_parts[1:], description, parameters, positional_completer
        )

    def write(self, file, indent=1):
        """Write this node and its children."""
        tabs = '\t' * indent
        desc = escape_field(self.description)
        if desc:
            print(f"{tabs}{self.name} # {desc}", file=file)
        else:
            print(f"{tabs}{self.name}", file=file)

        # Write positional completer as a pseudo-param if present
        if self.positional_completer:
            completer_tabs = '\t' * (indent + 1)
            print(f"{completer_tabs}... `{self.positional_completer}`", file=file)

        # Write params for this node
        for p in self.parameters:
            write_param(p, indent=indent + 1, file=file)

        # Write children
        for name in sorted(self.children.keys()):
            self.children[name].write(file, indent + 1)


def write_schema(config, commands, global_params, version, file=sys.stdout):
    """Output schema in indentation-based format."""
    print(f"# {config.schema_comment}", file=file)
    print(f"# Generated from {config.cli_name} {version}", file=file)
    print("", file=file)

    # Root command
    print(f"{config.cli_name} # {config.root_description}", file=file)

    # Global params (under root command at indent 1)
    if global_params:
        for p in global_params:
            write_param(p, indent=1, file=file)

    # Build tree structure from flat command list
    root = CommandTree()
    for cmd in commands:
        parts = cmd['name'].split()
        root.add_command(
            parts,
            cmd.get('description', ''),
            cmd.get('parameters', []),
            cmd.get('positional_completer'),
        )

    # Write all top-level commands
    for name in sorted(root.children.keys()):
        root.children[name].write(file, indent=1)


def get_global_flags(config):
    """Get global flags that apply to all commands."""
    raw_flags = get_command_flags(config, [])
    help_value = parse_help_value_flags(config, [])

    global_params = []
    for f in raw_flags:
        name = f['name']
        clean_name = name.rstrip('=')

        # Determine takes_value using help info, then heuristics
        if '=' in name:
            takes_value = True
        elif help_value:
            takes_value = clean_name in help_value
        else:
            takes_value = any(
                x in f['summary'].lower() for x in config.value_keywords
            )

        param = {
            'name': name,
            'description': f['summary'],
            'takes_value': takes_value,
        }
        global_params.append(param)

    return global_params


def export_cobra_cli(config):
    """Main entry point: export a Cobra CLI's command tree to .fcmps on stdout."""
    if not command_cache.auto_setup(config.cli_name, config.binary):
        sys.exit(1)

    version = get_cli_version(config)

    print(
        f"Exporting {config.cli_name} {version} commands using Cobra {config.complete_command}...",
        file=sys.stderr,
    )

    test_completions = parse_cobra_completions(config, [])
    if not test_completions:
        print(
            f"Error: {config.cli_name} {config.complete_command} not working. "
            f"CLI may be too old or not Cobra-based.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Found {len(test_completions)} top-level commands", file=sys.stderr)

    commands = sorted(walk_commands(config), key=lambda x: x['name'])
    global_params = get_global_flags(config)

    print(f"Exported {len(commands)} commands", file=sys.stderr)

    write_schema(config, commands, global_params, version)

    command_cache.save()
