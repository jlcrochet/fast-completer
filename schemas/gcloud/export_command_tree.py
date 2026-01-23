#!/usr/bin/env python
"""
Export gcloud CLI command tree to JSON for shell completion generation.

This script reads gcloud's static completion tree and converts it to
our schema format.

Usage:
    python export_command_tree.py > gcloud_commands.json

Requirements:
    Google Cloud SDK must be installed on the system. Unlike AWS/Azure CLIs,
    gcloud is not pip-installable - install via:
      - https://cloud.google.com/sdk/docs/install
      - apt: sudo apt install google-cloud-cli
      - brew: brew install google-cloud-sdk

    Set CLOUDSDK_ROOT_DIR if installed in a non-standard location.
"""

import json
import os
import sys


def find_gcloud_completions():
    """Find the gcloud static completions file."""
    # Common installation paths
    paths = [
        '/opt/google-cloud-cli/data/cli/gcloud_completions.py',
        '/opt/google-cloud-sdk/data/cli/gcloud_completions.py',
        os.path.expanduser('~/google-cloud-sdk/data/cli/gcloud_completions.py'),
        '/usr/share/google-cloud-sdk/data/cli/gcloud_completions.py',
        '/usr/lib/google-cloud-sdk/data/cli/gcloud_completions.py',
    ]

    # Also check CLOUDSDK_ROOT_DIR
    sdk_root = os.environ.get('CLOUDSDK_ROOT_DIR')
    if sdk_root:
        paths.insert(0, os.path.join(sdk_root, 'data/cli/gcloud_completions.py'))

    for path in paths:
        if os.path.exists(path):
            return path

    return None


def load_completion_tree(path):
    """Load the static completion tree from gcloud."""
    # Read the file and extract the STATIC_COMPLETION_CLI_TREE dict
    with open(path, 'r') as f:
        content = f.read()

    # Execute the Python file to get the dict
    namespace = {}
    exec(content, namespace)
    return namespace.get('STATIC_COMPLETION_CLI_TREE', {})


def convert_flags(flags_dict, command_path=''):
    """Convert gcloud flags dict to our parameters format."""
    params = []

    for flag_name, flag_value in sorted(flags_dict.items()):
        param = {
            'name': flag_name,
            'options': [flag_name],
            'required': False,
        }

        if flag_value == 'bool':
            param['type'] = 'bool'
        elif flag_value == 'value':
            pass  # Takes a value, no special handling
        elif flag_value == 'dynamic':
            pass  # Dynamic value, no choices
        elif isinstance(flag_value, list):
            param['choices'] = flag_value

        params.append(param)

    return params


def walk_commands(tree, path_parts=None, seen_groups=None):
    """Recursively walk the command tree and yield commands/groups."""
    if path_parts is None:
        path_parts = []
    if seen_groups is None:
        seen_groups = set()

    commands_dict = tree.get('commands', {})

    for name, subtree in sorted(commands_dict.items()):
        current_path = path_parts + [name]
        path_str = ' '.join(current_path)

        sub_commands = subtree.get('commands', {})
        sub_flags = subtree.get('flags', {})

        if sub_commands:
            # This is a group (has subcommands)
            # Yield group for every level of the hierarchy
            if path_str not in seen_groups:
                seen_groups.add(path_str)
                yield {
                    'name': path_str,
                    'type': 'group',
                }
            # Recurse into subcommands
            yield from walk_commands(subtree, current_path, seen_groups)
        else:
            # This is a leaf command
            cmd = {
                'name': path_str,
                'type': 'command',
            }
            if sub_flags:
                cmd['parameters'] = convert_flags(sub_flags, path_str)
            yield cmd


def main():
    completions_path = find_gcloud_completions()
    if not completions_path:
        sys.stderr.write("Error: Could not find gcloud static completions file.\n")
        sys.stderr.write("Make sure Google Cloud SDK is installed.\n")
        sys.exit(1)

    sys.stderr.write(f"Loading completions from: {completions_path}\n")
    sys.stderr.flush()

    tree = load_completion_tree(completions_path)

    # Build the schema
    schema = {
        'name': 'gcloud',
        'groups': [],
        'commands': [],
        'global_params': [],
    }

    # Convert global flags
    global_flags = tree.get('flags', {})
    for flag_name, flag_value in sorted(global_flags.items()):
        param = {
            'name': flag_name,
            'takes_value': flag_value != 'bool',
        }
        if isinstance(flag_value, list):
            param['choices'] = flag_value
        schema['global_params'].append(param)

    # Walk all commands
    # Note: groups must also be in 'commands' array for blob generator to create tree nodes
    for item in walk_commands(tree):
        if item['type'] == 'group':
            schema['groups'].append(item)
        schema['commands'].append(item)

    # Print stats to stderr first
    sys.stderr.write(f"Exported {len(schema['groups'])} groups, "
                     f"{len(schema['commands'])} commands, "
                     f"{len(schema['global_params'])} global params\n")
    sys.stderr.flush()

    # Output JSON to stdout
    print(json.dumps(schema, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
