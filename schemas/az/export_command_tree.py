#!/usr/bin/env python
"""
Export Azure CLI command tree to JSON for shell completion generation.

This script loads the full Azure CLI command table and exports all commands,
subcommands, and their arguments in a structured JSON format.

Usage (requires azure-cli and its dependencies installed):
    python export_command_tree.py > az_commands.json
"""

import argparse
import datetime
import json
import logging
import sys
from os.path import expanduser
from unittest.mock import patch


class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles non-serializable types."""

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        if isinstance(obj, datetime.date):
            return obj.isoformat()
        if hasattr(obj, '__dict__'):
            return str(obj)
        return super().default(obj)


USER_HOME = expanduser('~')

# --help is not useful for completions, filter it out
SKIP_PARAMS = frozenset(['--help -h'])


def extract_global_params(cli_ctx):
    """Extract global parameters from CLI's global parser."""
    from knack.parser import CLICommandParser

    global_parser = CLICommandParser.create_global_parser(cli_ctx=cli_ctx)
    global_params = []

    for action in global_parser._actions:
        if action.dest == 'help' or not action.option_strings:
            continue

        # Find long option
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

        # Determine if it takes a value (store_true/store_false don't take values)
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

    with patch('getpass.getuser', return_value='user'):
        create_invoker_and_load_cmds_and_args(cli_ctx)

    return get_all_help(cli_ctx, skip=True)


def extract_parameter(param):
    """Extract parameter information from a help parameter object."""
    if param.name in SKIP_PARAMS:
        return None

    options = param.name.split() if param.name else []

    # Clean up short_summary - remove "Possible values include" suffix
    short_summary = param.short_summary or ''
    possible_values_index = short_summary.find(' Possible values include')
    if possible_values_index >= 0:
        short_summary = short_summary[:possible_values_index]
    short_summary = short_summary.strip()

    info = {
        'name': param.name,
        'options': options,
        'required': getattr(param, 'required', False),
        'summary': short_summary,
    }

    param_type = getattr(param, 'type', None)
    if param_type and param_type != 'string':
        info['type'] = param_type

    long_summary = getattr(param, 'long_summary', None)
    if long_summary and long_summary != short_summary:
        info['description'] = long_summary

    choices = getattr(param, 'choices', None)
    if choices:
        info['choices'] = sorted([str(x) for x in choices])

    default = getattr(param, 'default', None)
    if default and default != argparse.SUPPRESS:
        try:
            if isinstance(default, str) and default.startswith(USER_HOME):
                default = default.replace(USER_HOME, '~').replace('\\', '/')
        except Exception:
            pass
        info['default'] = default

    group_name = getattr(param, 'group_name', None)
    if group_name:
        info['group'] = group_name

    value_sources = getattr(param, 'value_sources', None)
    if value_sources:
        source_commands = []
        for vs in value_sources:
            try:
                source_commands.append(vs["link"]["command"])
            except (KeyError, TypeError):
                pass
        if source_commands:
            info['value_sources'] = source_commands

    if getattr(param, 'deprecate_info', None):
        info['deprecated'] = True
    if getattr(param, 'preview_info', None):
        info['preview'] = True
    if getattr(param, 'experimental_info', None):
        info['experimental'] = True

    return info


def extract_command(help_file):
    """Extract command or group information from a help file."""
    from azure.cli.core._help import CliCommandHelpFile, ArgumentGroupRegistry

    is_command = isinstance(help_file, CliCommandHelpFile)
    command_name = help_file.command if help_file.command else 'az'

    info = {
        'name': command_name,
        'type': 'command' if is_command else 'group',
        'summary': getattr(help_file, 'short_summary', '') or '',
    }

    long_summary = getattr(help_file, 'long_summary', None)
    if long_summary:
        info['description'] = long_summary

    deprecate_info = getattr(help_file, 'deprecate_info', None)
    if deprecate_info:
        info['deprecated'] = True
        try:
            info['deprecation_message'] = deprecate_info._get_message(deprecate_info)
        except Exception:
            pass

    if is_command and hasattr(help_file, 'parameters') and help_file.parameters:
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

        parameters = []
        for param in sorted_params:
            param_info = extract_parameter(param)
            if param_info:
                parameters.append(param_info)

        if parameters:
            info['parameters'] = parameters

    examples = getattr(help_file, 'examples', [])
    if examples:
        info['examples'] = [
            {
                'summary': getattr(ex, 'short_summary', '') or getattr(ex, 'name', ''),
                'command': (getattr(ex, 'command', '') or getattr(ex, 'text', '')).replace('\\', ''),
            }
            for ex in examples
            if getattr(ex, 'command', None) or getattr(ex, 'text', None)
        ]

    return info


def build_command_tree(help_files, cli_ctx):
    """Build structured command tree from help files."""
    commands = []
    groups = []

    for help_file in help_files:
        info = extract_command(help_file)
        if info['type'] == 'command':
            commands.append(info)
        else:
            groups.append(info)

    # Get Azure CLI version
    try:
        from azure.cli.core import __version__ as cli_version
    except ImportError:
        cli_version = 'unknown'

    # Extract global params from CLI's global parser
    global_params = extract_global_params(cli_ctx)

    # Build set of global param long options for filtering from command params
    global_param_names = {gp['name'] for gp in global_params}

    # Filter global params from command parameters
    for cmd in commands:
        if 'parameters' in cmd:
            cmd['parameters'] = [
                p for p in cmd['parameters']
                if not any(opt in global_param_names for opt in p.get('options', []))
            ]

    return {
        'version': cli_version,
        'cli': 'az',
        'generated_by': 'export_command_tree.py',
        'group_count': len(groups),
        'command_count': len(commands),
        'global_params': global_params,
        'groups': sorted(groups, key=lambda x: x['name']),
        'commands': sorted(commands, key=lambda x: x['name']),
    }


def main():
    logging.getLogger().setLevel(logging.ERROR)

    print("Loading Azure CLI...", file=sys.stderr)
    cli_ctx = create_cli()

    print("Loading command table and arguments...", file=sys.stderr)
    help_files = load_all_help(cli_ctx)

    print(f"Processing {len(help_files)} help entries...", file=sys.stderr)
    tree = build_command_tree(help_files, cli_ctx)

    print(f"Exported {tree['group_count']} groups and {tree['command_count']} commands", file=sys.stderr)

    print(json.dumps(tree, indent=2, ensure_ascii=False, cls=JSONEncoder))


if __name__ == '__main__':
    main()
