#!/usr/bin/env python
"""
Export gcloud CLI command tree to schema format for shell completion generation.

This script reads gcloud's static completion tree and converts it to
our schema format.

Usage:
    python export_command_tree.py > gcloud.fcmps

Requirements:
    Google Cloud SDK must be installed on the system. Unlike AWS/Azure CLIs,
    gcloud is not pip-installable - install via:
      - https://cloud.google.com/sdk/docs/install
      - apt: sudo apt install google-cloud-cli
      - brew: brew install google-cloud-sdk

    Set CLOUDSDK_ROOT_DIR if installed in a non-standard location.
"""

import os
import sys


def find_gcloud_completions():
    """Find the gcloud static completions file."""
    paths = [
        '/opt/google-cloud-cli/data/cli/gcloud_completions.py',
        '/opt/google-cloud-sdk/data/cli/gcloud_completions.py',
        os.path.expanduser('~/google-cloud-sdk/data/cli/gcloud_completions.py'),
        '/usr/share/google-cloud-sdk/data/cli/gcloud_completions.py',
        '/usr/lib/google-cloud-sdk/data/cli/gcloud_completions.py',
    ]

    sdk_root = os.environ.get('CLOUDSDK_ROOT_DIR')
    if sdk_root:
        paths.insert(0, os.path.join(sdk_root, 'data/cli/gcloud_completions.py'))

    for path in paths:
        if os.path.exists(path):
            return path

    return None


def load_completion_tree(path):
    """Load the static completion tree from gcloud."""
    with open(path, 'r') as f:
        content = f.read()

    namespace = {}
    exec(content, namespace)
    return namespace.get('STATIC_COMPLETION_CLI_TREE', {})


def escape_field(s):
    """Escape a field for schema output (replace tabs and newlines)."""
    if not s:
        return ''
    return s.replace('\t', ' ').replace('\n', ' ').replace('\r', '')


def convert_flags(flags_dict):
    """Convert gcloud flags dict to our parameters format."""
    params = []

    for flag_name, flag_value in sorted(flags_dict.items()):
        if not flag_name.startswith('--'):
            continue

        param = {
            'name': flag_name,
        }

        if flag_value == 'bool':
            param['type'] = 'bool'
        elif flag_value == 'value':
            pass  # Takes a value, no special handling
        elif flag_value == 'dynamic':
            pass  # Skip - requires Python introspection, not actionable
        elif isinstance(flag_value, list):
            param['choices'] = flag_value

        params.append(param)

    return params


def walk_commands(tree, path_parts=None):
    """Recursively walk the command tree and yield leaf commands."""
    if path_parts is None:
        path_parts = []

    commands_dict = tree.get('commands', {})

    for name, subtree in sorted(commands_dict.items()):
        current_path = path_parts + [name]
        path_str = ' '.join(current_path)

        sub_commands = subtree.get('commands', {})
        sub_flags = subtree.get('flags', {})

        if sub_commands:
            yield from walk_commands(subtree, current_path)
        else:
            cmd = {
                'name': path_str,
                'parameters': convert_flags(sub_flags) if sub_flags else [],
            }
            yield cmd


def write_param(p, indent=1, file=sys.stdout):
    """Output single param line in new schema format."""
    name = p.get('name', '')
    if not name.startswith('-'):
        return

    # Check if boolean
    is_bool = p.get('type') == 'bool'

    # Build option spec
    opt_spec = name

    # Build type field
    type_field = ''
    if is_bool:
        type_field = '@bool'
    elif p.get('choices'):
        type_field = '(' + '|'.join(str(c) for c in p['choices']) + ')'
    elif p.get('members'):
        type_field = '{' + '|'.join(p['members']) + '}'
    elif p.get('completer'):
        type_field = '`' + p['completer'] + '`'

    desc = escape_field(p.get('summary') or p.get('description') or '')
    tabs = '\t' * indent

    parts = [f"{tabs}{opt_spec}"]
    if type_field:
        parts.append(type_field)
    if desc:
        parts.append(f"# {desc}")
    print(' '.join(parts), file=file)


class CommandTree:
    """Tree structure for organizing commands by path."""

    def __init__(self, name='', parameters=None):
        self.name = name
        self.parameters = parameters or []
        self.children = {}

    def add_command(self, path_parts, parameters=None):
        """Add a command at the given path."""
        if not path_parts:
            self.parameters = parameters or []
            return

        first = path_parts[0]
        if first not in self.children:
            self.children[first] = CommandTree(first)
        self.children[first].add_command(path_parts[1:], parameters)

    def write(self, file, indent=1):
        """Write this node and its children."""
        tabs = '\t' * indent
        # gcloud completions don't have descriptions
        print(f"{tabs}{self.name}", file=file)

        # Write params for this node
        for p in self.parameters:
            write_param(p, indent=indent + 1, file=file)

        # Write children
        for name in sorted(self.children.keys()):
            self.children[name].write(file, indent + 1)


def write_schema(commands, global_params, file=sys.stdout):
    """Output schema in indentation-based format."""
    print("# gcloud CLI schema for fast-completer", file=file)
    print("", file=file)

    # Root command
    print("gcloud # Google Cloud CLI", file=file)

    # Global params (under root command at indent 1)
    if global_params:
        for p in global_params:
            write_param(p, indent=1, file=file)

    # Build tree structure from flat command list
    root = CommandTree()
    for cmd in commands:
        parts = cmd['name'].split()
        root.add_command(parts, cmd.get('parameters', []))

    # Write all top-level commands
    for name in sorted(root.children.keys()):
        root.children[name].write(file, indent=1)


def main():
    completions_path = find_gcloud_completions()
    if not completions_path:
        sys.stderr.write("Error: Could not find gcloud static completions file.\n")
        sys.stderr.write("Make sure Google Cloud SDK is installed.\n")
        sys.exit(1)

    sys.stderr.write(f"Loading completions from: {completions_path}\n")
    sys.stderr.flush()

    tree = load_completion_tree(completions_path)

    commands = list(walk_commands(tree))

    # Convert global flags
    global_flags = tree.get('flags', {})
    global_params = []
    for flag_name, flag_value in sorted(global_flags.items()):
        if not flag_name.startswith('--'):
            continue
        param = {
            'name': flag_name,
        }
        if flag_value == 'bool':
            param['type'] = 'bool'
        elif isinstance(flag_value, list):
            param['choices'] = flag_value
        global_params.append(param)

    sys.stderr.write(f"Exported {len(commands)} commands, "
                     f"{len(global_params)} global params\n")
    sys.stderr.flush()

    write_schema(commands, global_params)


if __name__ == '__main__':
    main()
