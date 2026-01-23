#!/usr/bin/env python3
"""
Export GitHub CLI (gh) command tree to JSON for shell completion generation.

This script uses gh's built-in completion generation (Cobra framework) to extract
all commands, subcommands, and flags in a structured format.

Usage (requires gh CLI installed):
    python export_command_tree.py > gh_commands.json

Requirements:
    GitHub CLI must be installed: https://cli.github.com/
"""

import json
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
    # Cobra's __complete returns completions for the next argument
    # Format: completion\tdescription
    # Last line is a directive (e.g., ":4" for ShellCompDirectiveNoFileComp)
    args = ['gh', '__complete'] + list(command_parts) + ['']
    output, rc = run_command(*args)

    if rc != 0 or not output:
        return []

    completions = []
    for line in output.strip().split('\n'):
        if line.startswith(':'):
            # Directive line, skip
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
        # Skip flags, help, and empty
        if comp.startswith('-') or comp in ('help', '') or comp.startswith(':'):
            continue
        subcommands.append({'name': comp, 'summary': desc})
    return subcommands


def build_flags_list(command_path, raw_flags):
    """Convert raw flags to parameter format with short/long options."""
    # Group flags by base name (handle -f, --flag pairs)
    params = []
    seen = set()

    for f in raw_flags:
        name = f['name']
        if name in seen:
            continue
        seen.add(name)

        param = {
            'name': name,
            'options': [name],
            'required': False,
            'description': f['summary'],
        }

        # Check if it's a boolean flag (no = in completion)
        # Cobra shows value-taking flags with description hints
        if '=' not in name and not any(x in f['summary'].lower() for x in ['string', 'int', 'file', 'path', 'name', 'number']):
            # Likely a boolean
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

    # Avoid cycles
    if command_path in seen:
        return
    seen.add(command_path)

    subcommands = get_subcommands(command_parts)

    if subcommands:
        # This is a group - recurse into subcommands
        for sub in subcommands:
            yield from walk_commands(
                command_parts + [sub['name']],
                depth + 1,
                max_depth,
                seen
            )
    else:
        # Leaf command
        if command_path:
            raw_flags = get_command_flags(command_parts)
            params = build_flags_list(command_path, raw_flags)

            cmd = {
                'name': command_path,
                'type': 'command',
                'description': '',
            }

            if params:
                cmd['parameters'] = params

            # Check for positional completer
            pos_key = (command_path, '')
            if pos_key in DYNAMIC_COMPLETERS:
                cmd['positional_completer'] = DYNAMIC_COMPLETERS[pos_key]

            yield cmd


def get_global_flags():
    """Get global flags that apply to all commands."""
    # Get flags from root level
    raw_flags = get_command_flags([])

    global_params = []
    for f in raw_flags:
        name = f['name']
        if name in ('--help', '-h'):
            continue
        param = {
            'name': name,
            'description': f['summary'],
            'takes_value': '=' in name or any(x in f['summary'].lower() for x in ['string', 'int', 'file', 'path']),
        }
        global_params.append(param)

    return global_params


def main():
    # Check if gh is available
    version = get_gh_version()
    if version == 'unknown':
        # Try running gh to see if it exists
        _, rc = run_command('gh', '--version')
        if rc != 0:
            print("Error: gh CLI not found. Install from https://cli.github.com/", file=sys.stderr)
            sys.exit(1)

    print(f"Exporting gh CLI {version} commands using Cobra __complete...", file=sys.stderr)

    # Test that __complete works
    test_completions = parse_cobra_completions([])
    if not test_completions:
        print("Error: gh __complete not working. gh CLI may be too old.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(test_completions)} top-level commands", file=sys.stderr)

    # Build schema
    schema = {
        'name': 'gh',
        'version': version,
        'generated_by': 'export_command_tree.py (Cobra __complete)',
        'commands': list(walk_commands()),
        'global_params': get_global_flags(),
    }

    # Sort
    schema['commands'].sort(key=lambda x: x['name'])
    schema['command_count'] = len(schema['commands'])

    print(f"Exported {schema['command_count']} commands", file=sys.stderr)

    # Output JSON
    print(json.dumps(schema, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
