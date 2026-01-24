#!/usr/bin/env python
"""
Export Azure CLI command tree to schema format for shell completion generation.

This script loads the full Azure CLI command table and exports all commands,
subcommands, and their arguments in a structured schema format.

Usage (requires azure-cli and its dependencies installed):
    python export_command_tree.py > az.fcmps
"""

import argparse
import datetime
import math
import sys
import time
from os.path import expanduser
from unittest.mock import patch

# Monkey-patch for Python 3.12+ compatibility (time.clock was removed)
if not hasattr(time, 'clock'):
    time.clock = time.perf_counter

USER_HOME = expanduser('~')

# --help is not useful for completions, filter it out
SKIP_PARAMS = frozenset(['--help -h'])


def escape_field(s):
    """Escape a field for schema output (replace tabs and newlines)."""
    if not s:
        return ''
    return s.replace('\t', ' ').replace('\n', ' ').replace('\r', '')


def extract_global_params(cli_ctx):
    """Extract global parameters from CLI's global parser."""
    from knack.parser import CLICommandParser

    global_parser = CLICommandParser.create_global_parser(cli_ctx=cli_ctx)
    global_params = []

    for action in global_parser._actions:
        if action.dest == 'help' or not action.option_strings:
            continue

        long_opt = None
        for opt in action.option_strings:
            if opt.startswith('--'):
                if not long_opt or len(opt) > len(long_opt):
                    long_opt = opt

        if not long_opt:
            continue

        param = {
            'name': long_opt,
            'description': action.help or '',
        }

        takes_value = not isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction))
        param['takes_value'] = takes_value

        if action.choices:
            param['choices'] = list(action.choices)

        global_params.append(param)

    return sorted(global_params, key=lambda x: x['name'])


def create_cli():
    """Create and initialize the Azure CLI instance."""
    from azure.cli.core import MainCommandsLoader, AzCli
    from azure.cli.core.commands import AzCliCommandInvoker
    from azure.cli.core.parser import AzCliCommandParser
    from azure.cli.core._help import AzCliHelp

    return AzCli(
        cli_name='az',
        commands_loader_cls=MainCommandsLoader,
        invocation_cls=AzCliCommandInvoker,
        parser_cls=AzCliCommandParser,
        help_cls=AzCliHelp
    )


def load_all_help(cli_ctx):
    """Load all commands and return help files."""
    from azure.cli.core.file_util import create_invoker_and_load_cmds_and_args, get_all_help
    import logging
    logging.getLogger().setLevel(logging.ERROR)

    with patch('getpass.getuser', return_value='user'):
        create_invoker_and_load_cmds_and_args(cli_ctx)

    return get_all_help(cli_ctx, skip=True)


def extract_parameter(param):
    """Extract parameter information from a help parameter object."""
    if param.name in SKIP_PARAMS:
        return None

    options = param.name.split() if param.name else []

    # Find long option
    long_opt = None
    short_opt = None
    for opt in options:
        if opt.startswith('--'):
            if not long_opt or len(opt) > len(long_opt):
                long_opt = opt
        elif opt.startswith('-') and len(opt) == 2:
            short_opt = opt

    if not long_opt:
        return None

    short_summary = param.short_summary or ''
    possible_values_index = short_summary.find(' Possible values include')
    if possible_values_index >= 0:
        short_summary = short_summary[:possible_values_index]
    short_summary = short_summary.strip()

    info = {
        'name': long_opt,
        'short': short_opt,
        'summary': short_summary,
    }

    param_type = getattr(param, 'type', None)
    if param_type == 'bool':
        info['type'] = 'bool'

    choices = getattr(param, 'choices', None)
    if choices:
        info['choices'] = sorted([str(x) for x in choices])

    value_sources = getattr(param, 'value_sources', None)
    if value_sources:
        source_commands = []
        for vs in value_sources:
            try:
                cmd = vs["link"]["command"]
                cmd = cmd.strip('`').strip()
                if cmd.startswith('az '):
                    cmd = cmd[3:]
                if '--output' not in cmd and '-o' not in cmd:
                    cmd = f"{cmd} --output tsv"
                source_commands.append(cmd)
            except (KeyError, TypeError):
                pass
        if source_commands:
            info['completer'] = source_commands[0] if len(source_commands) == 1 else source_commands[0]

    return info


def extract_command(help_file):
    """Extract command or group information from a help file."""
    from azure.cli.core._help import CliCommandHelpFile

    is_command = isinstance(help_file, CliCommandHelpFile)
    command_name = help_file.command if help_file.command else 'az'

    if not is_command:
        return None

    info = {
        'name': command_name,
        'summary': getattr(help_file, 'short_summary', '') or '',
        'parameters': [],
    }

    if hasattr(help_file, 'parameters') and help_file.parameters:
        from azure.cli.core._help import ArgumentGroupRegistry

        group_registry = ArgumentGroupRegistry(
            [p.group_name for p in help_file.parameters if p.group_name]
        )

        sorted_params = sorted(
            help_file.parameters,
            key=lambda p: (
                group_registry.get_group_priority(p.group_name),
                str(not p.required),
                p.name
            )
        )

        for param in sorted_params:
            param_info = extract_parameter(param)
            if param_info:
                info['parameters'].append(param_info)

    return info


def write_param(p, indent=1, file=sys.stdout):
    """Output single param line in new schema format."""
    name = p.get('name', '')
    if not name.startswith('-'):
        return

    short_opt = p.get('short') or ''

    # Check if boolean
    is_bool = (p.get('type') == 'bool' or not p.get('takes_value', True))

    # Build option spec: --long|-s or --long or -s
    if name.startswith('--') and short_opt:
        opt_spec = f"{name}|{short_opt}"
    else:
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
        completer = p['completer']
        if isinstance(completer, list):
            completer = completer[0]
        type_field = '`' + completer + '`'

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


def write_schema(commands, global_params, version, file=sys.stdout):
    """Output schema in indentation-based format."""
    print("# Azure CLI schema for fast-completer", file=file)
    print(f"# Generated from azure-cli {version}", file=file)
    print("", file=file)

    # Root command
    print("az # Azure CLI", file=file)

    # Global params (under root command at indent 1)
    if global_params:
        for p in global_params:
            write_param(p, indent=1, file=file)

    # Build tree structure from flat command list
    root = CommandTree()
    for cmd in commands:
        parts = cmd['name'].split()
        root.add_command(parts, cmd.get('summary', ''), cmd.get('parameters', []))

    # Write all top-level commands
    for name in sorted(root.children.keys()):
        root.children[name].write(file, indent=1)


def build_command_tree(help_files, cli_ctx):
    """Build structured command tree from help files."""
    commands = []

    for help_file in help_files:
        info = extract_command(help_file)
        if info:
            commands.append(info)

    try:
        from azure.cli.core import __version__ as cli_version
    except ImportError:
        cli_version = 'unknown'

    global_params = extract_global_params(cli_ctx)

    # Build set of global param long options for filtering from command params
    global_param_names = {gp['name'] for gp in global_params}

    # Filter global params from command parameters
    for cmd in commands:
        cmd['parameters'] = [
            p for p in cmd['parameters']
            if p.get('name') not in global_param_names
        ]

    return sorted(commands, key=lambda x: x['name']), global_params, cli_version


def main():
    import logging
    logging.getLogger().setLevel(logging.ERROR)

    print("Loading Azure CLI...", file=sys.stderr)
    cli_ctx = create_cli()

    print("Loading command table and arguments...", file=sys.stderr)
    help_files = load_all_help(cli_ctx)

    print(f"Processing {len(help_files)} help entries...", file=sys.stderr)
    commands, global_params, version = build_command_tree(help_files, cli_ctx)

    print(f"Exported {len(commands)} commands", file=sys.stderr)

    write_schema(commands, global_params, version)


if __name__ == '__main__':
    main()
