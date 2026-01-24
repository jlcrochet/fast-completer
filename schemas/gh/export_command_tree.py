#!/usr/bin/env python3
"""
Export GitHub CLI (gh) command tree to TSV for shell completion generation.

This script uses gh's built-in completion generation (Cobra framework) to extract
all commands, subcommands, and flags in a structured format.

Usage (requires gh CLI installed):
    python export_command_tree.py > gh.fcmps

Requirements:
    GitHub CLI must be installed: https://cli.github.com/
"""

import re
import subprocess
import sys


# Commands that provide dynamic completions for certain flags
# Maps (command_prefix, flag) -> completer command
DYNAMIC_COMPLETERS = {
    # Issue completions
    ('issue view', ''): 'issue list --json number --jq ".[].number"',
    ('issue close', ''): 'issue list --state open --json number --jq ".[].number"',
    ('issue reopen', ''): 'issue list --state closed --json number --jq ".[].number"',
    ('issue edit', ''): 'issue list --json number --jq ".[].number"',
    ('issue comment', ''): 'issue list --json number --jq ".[].number"',

    # PR completions
    ('pr view', ''): 'pr list --json number --jq ".[].number"',
    ('pr checkout', ''): 'pr list --state open --json headRefName --jq ".[].headRefName"',
    ('pr close', ''): 'pr list --state open --json number --jq ".[].number"',
    ('pr reopen', ''): 'pr list --state closed --json number --jq ".[].number"',
    ('pr merge', ''): 'pr list --state open --json number --jq ".[].number"',
    ('pr edit', ''): 'pr list --json number --jq ".[].number"',
    ('pr review', ''): 'pr list --state open --json number --jq ".[].number"',
    ('pr comment', ''): 'pr list --json number --jq ".[].number"',
    ('pr ready', ''): 'pr list --state open --draft --json number --jq ".[].number"',

    # Release completions
    ('release view', ''): 'release list --json tagName --jq ".[].tagName"',
    ('release delete', ''): 'release list --json tagName --jq ".[].tagName"',
    ('release download', ''): 'release list --json tagName --jq ".[].tagName"',
    ('release edit', ''): 'release list --json tagName --jq ".[].tagName"',

    # Run completions
    ('run view', ''): 'run list --json databaseId --jq ".[].databaseId"',
    ('run watch', ''): 'run list --json databaseId --jq ".[].databaseId"',
    ('run cancel', ''): 'run list --status in_progress --json databaseId --jq ".[].databaseId"',
    ('run rerun', ''): 'run list --json databaseId --jq ".[].databaseId"',

    # Workflow completions
    ('workflow view', ''): 'workflow list --json name --jq ".[].name"',
    ('workflow run', ''): 'workflow list --json name --jq ".[].name"',
    ('workflow enable', ''): 'workflow list --json name --jq ".[].name"',
    ('workflow disable', ''): 'workflow list --json name --jq ".[].name"',

    # Gist completions
    ('gist view', ''): 'gist list --json id --jq ".[].id"',
    ('gist edit', ''): 'gist list --json id --jq ".[].id"',
    ('gist delete', ''): 'gist list --json id --jq ".[].id"',
    ('gist clone', ''): 'gist list --json id --jq ".[].id"',

    # Label completions for issues/PRs
    ('issue create', '--label'): 'label list --json name --jq ".[].name"',
    ('issue edit', '--label'): 'label list --json name --jq ".[].name"',
    ('pr create', '--label'): 'label list --json name --jq ".[].name"',
    ('pr edit', '--label'): 'label list --json name --jq ".[].name"',

    # Codespace completions
    ('codespace delete', ''): 'codespace list --json name --jq ".[].name"',
    ('codespace stop', ''): 'codespace list --json name --jq ".[].name"',
    ('codespace ssh', ''): 'codespace list --json name --jq ".[].name"',
    ('codespace code', ''): 'codespace list --json name --jq ".[].name"',

    # Extension completions
    ('extension remove', ''): 'extension list',
    ('extension upgrade', ''): 'extension list',

    # Alias completions
    ('alias delete', ''): 'alias list',

    # Secret/variable completions
    ('secret delete', ''): 'secret list --json name --jq ".[].name"',
    ('variable delete', ''): 'variable list --json name --jq ".[].name"',
}


def run_command(*args, timeout=30):
    """Run a command and return stdout."""
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.returncode
    except subprocess.TimeoutExpired:
        print(f"Timeout running: {' '.join(args)}", file=sys.stderr)
        return "", 1
    except FileNotFoundError:
        return "", 1


def get_gh_version():
    """Get gh CLI version."""
    output, _ = run_command('gh', '--version')
    match = re.search(r'gh version ([\d.]+)', output)
    return match.group(1) if match else 'unknown'


def parse_cobra_completions(command_parts):
    """
    Use Cobra's __complete command to get completions programmatically.

    gh __complete <command parts...> ""

    Returns list of (completion, description) tuples.
    """
    args = ['gh', '__complete'] + list(command_parts) + ['']
    output, rc = run_command(*args)

    if rc != 0 or not output:
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


def get_command_flags(command_parts):
    """Get flags for a command using __complete with -- prefix."""
    args = ['gh', '__complete'] + list(command_parts) + ['--']
    output, rc = run_command(*args)

    if rc != 0 or not output:
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


def get_subcommands(command_parts):
    """Get subcommands for a command group."""
    completions = parse_cobra_completions(command_parts)
    subcommands = []
    for comp, desc in completions:
        if comp.startswith('-') or comp == '' or comp.startswith(':'):
            continue
        subcommands.append({'name': comp, 'summary': desc})
    return subcommands


def build_flags_list(command_path, raw_flags):
    """Convert raw flags to parameter format with short/long options."""
    params = []
    seen = set()

    for f in raw_flags:
        name = f['name']
        if name in seen:
            continue
        seen.add(name)

        param = {
            'name': name,
            'description': f['summary'],
        }

        # Check if it's a boolean flag (no = in completion)
        if '=' not in name and not any(x in f['summary'].lower() for x in ['string', 'int', 'file', 'path', 'name', 'number']):
            param['type'] = 'bool'

        # Check for dynamic completer
        completer_key = (command_path, name)
        if completer_key in DYNAMIC_COMPLETERS:
            param['completer'] = DYNAMIC_COMPLETERS[completer_key]

        params.append(param)

    return params


def walk_commands(command_parts=None, depth=0, max_depth=5, seen=None):
    """Recursively discover all leaf commands using __complete."""
    if command_parts is None:
        command_parts = []
    if seen is None:
        seen = set()

    if depth > max_depth:
        return

    command_path = ' '.join(command_parts)

    if command_path in seen:
        return
    seen.add(command_path)

    subcommands = get_subcommands(command_parts)

    if subcommands:
        for sub in subcommands:
            yield from walk_commands(
                command_parts + [sub['name']],
                depth + 1,
                max_depth,
                seen
            )
    else:
        if command_path:
            raw_flags = get_command_flags(command_parts)
            params = build_flags_list(command_path, raw_flags)

            cmd = {
                'name': command_path,
                'description': '',
                'parameters': params,
            }

            pos_key = (command_path, '')
            if pos_key in DYNAMIC_COMPLETERS:
                cmd['positional_completer'] = DYNAMIC_COMPLETERS[pos_key]

            yield cmd


def get_global_flags():
    """Get global flags that apply to all commands."""
    raw_flags = get_command_flags([])

    global_params = []
    for f in raw_flags:
        name = f['name']
        param = {
            'name': name,
            'description': f['summary'],
            'takes_value': '=' in name or any(x in f['summary'].lower() for x in ['string', 'int', 'file', 'path']),
        }
        global_params.append(param)

    return global_params


def escape_field(s):
    """Escape a field for TSV output (replace tabs and newlines)."""
    if not s:
        return ''
    return s.replace('\t', ' ').replace('\n', ' ').replace('\r', '')


def write_param(p, indent=1, file=sys.stdout):
    """Output single param line in new schema format."""
    name = p.get('name', '')

    # Extract long and short options
    long_opt = None
    short_opt = None

    if name.startswith('--'):
        long_opt = name
    elif name.startswith('-') and len(name) == 2:
        short_opt = name

    if not long_opt and not short_opt:
        return

    # Check if boolean
    is_bool = (p.get('type') == 'bool' or not p.get('takes_value', True))

    # Build option spec: --long|-s or --long or -s
    if long_opt and short_opt:
        opt_spec = f"{long_opt}|{short_opt}"
    elif long_opt:
        opt_spec = long_opt
    else:
        opt_spec = short_opt

    # Build type field
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
        self.children = {}

    def add_command(self, path_parts, description='', parameters=None):
        """Add a command at the given path."""
        if not path_parts:
            self.description = description
            self.parameters = parameters or []
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

        # Write params for this node
        for p in self.parameters:
            write_param(p, indent=indent + 1, file=file)

        # Write children
        for name in sorted(self.children.keys()):
            self.children[name].write(file, indent + 1)


def write_tsv(commands, global_params, version, file=sys.stdout):
    """Output schema in indentation-based format."""
    print("# GitHub CLI schema for fast-completer", file=file)
    print(f"# Generated from gh {version}", file=file)
    print("", file=file)

    # Root command
    print("gh # GitHub CLI", file=file)

    # Global params (under root command at indent 1)
    if global_params:
        for p in global_params:
            write_param(p, indent=1, file=file)

    # Build tree structure from flat command list
    root = CommandTree()
    for cmd in commands:
        parts = cmd['name'].split()
        root.add_command(parts, cmd.get('description', ''), cmd.get('parameters', []))

    # Write all top-level commands
    for name in sorted(root.children.keys()):
        root.children[name].write(file, indent=1)


def main():
    version = get_gh_version()
    if version == 'unknown':
        _, rc = run_command('gh', '--version')
        if rc != 0:
            print("Error: gh CLI not found. Install from https://cli.github.com/", file=sys.stderr)
            sys.exit(1)

    print(f"Exporting gh CLI {version} commands using Cobra __complete...", file=sys.stderr)

    test_completions = parse_cobra_completions([])
    if not test_completions:
        print("Error: gh __complete not working. gh CLI may be too old.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(test_completions)} top-level commands", file=sys.stderr)

    commands = sorted(walk_commands(), key=lambda x: x['name'])
    global_params = get_global_flags()

    print(f"Exported {len(commands)} commands", file=sys.stderr)

    write_tsv(commands, global_params, version)


if __name__ == '__main__':
    main()
