#!/usr/bin/env python
"""
Export AWS CLI command tree to schema format for shell completion generation.

This script loads AWS CLI's botocore service models and exports all commands,
subcommands, and their arguments in a structured schema format.

For services with high-level custom commands (like s3 cp, s3 sync), those are
extracted from the CLI driver instead of botocore service models.

Usage (requires AWS CLI v2 installed via official installer, not PyPI):
    python3 export_command_tree.py > aws.fcmps

Note: AWS CLI v2 is NOT available on PyPI. Install it via:
    - Official installer: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
    - Package manager: brew install awscli, apt install awscli, etc.
"""

import json
import os
import re
import sys

# AWS CLI v2 embeds botocore inside the awscli package
try:
    from awscli import botocore
    from awscli.botocore import session as botocore_session
except ImportError:
    # Fallback for standalone botocore
    import botocore
    import botocore.session as botocore_session

import awscli.clidriver


def camel_to_kebab(name):
    """Convert CamelCase to kebab-case."""
    s = re.sub(r'(?<!^)(?=[A-Z])', '-', name)
    return s.lower()


def strip_html(text):
    """Remove HTML tags and clean up text."""
    if not text:
        return ''
    text = re.sub(r'<[^>]+>', '', text)
    text = text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
    text = text.replace('&quot;', '"').replace('&#39;', "'")
    text = ' '.join(text.split())
    return text.strip()


def escape_field(s):
    """Escape a field for schema output (replace tabs and newlines)."""
    if not s:
        return ''
    return s.replace('\t', ' ').replace('\n', ' ').replace('\r', '')


def get_global_params():
    """Extract global parameters from AWS CLI's cli.json."""
    global_params = []

    try:
        import awscli
        awscli_dir = os.path.dirname(awscli.__file__)
        cli_json_path = os.path.join(awscli_dir, 'data', 'cli.json')

        if os.path.exists(cli_json_path):
            with open(cli_json_path) as f:
                cli_data = json.load(f)

            for name, opt in cli_data.get('options', {}).items():
                param = {
                    'name': f'--{name}',
                    'description': strip_html(opt.get('help', '')),
                }

                action = opt.get('action', '')
                takes_value = action not in ('store_true', 'store_false', 'version')
                param['takes_value'] = takes_value

                if opt.get('choices'):
                    param['choices'] = opt['choices']

                global_params.append(param)
    except Exception as e:
        print(f"Warning: Could not load cli.json: {e}", file=sys.stderr)

    return sorted(global_params, key=lambda x: x['name'])


def extract_structure_members(shape, depth=0):
    """Extract member names from a structure shape, recursively up to depth 1."""
    members = []
    if not hasattr(shape, 'members'):
        return members

    for member_name, member_shape in shape.members.items():
        key = camel_to_kebab(member_name)
        members.append(key)

    return members


def extract_param(name, shape, required_members):
    """Extract parameter information from a botocore shape."""
    option_name = f'--{camel_to_kebab(name)}'

    doc = strip_html(shape.documentation) if shape.documentation else ''

    param = {
        'name': option_name,
        'required': name in required_members,
        'summary': doc,
    }

    type_name = shape.type_name
    if type_name == 'boolean':
        param['type'] = 'bool'

    if hasattr(shape, 'enum') and shape.enum:
        param['choices'] = list(shape.enum)

    if type_name == 'structure':
        members = extract_structure_members(shape)
        if members:
            param['members'] = members
    elif type_name == 'list' and hasattr(shape, 'member'):
        member_shape = shape.member
        if member_shape.type_name == 'structure':
            members = extract_structure_members(member_shape)
            if members:
                param['members'] = members

    return param


def extract_operation(service_name, op_name, op_model):
    """Extract command information from a botocore operation model."""
    cmd_name = camel_to_kebab(op_name)
    full_name = f'{service_name} {cmd_name}'

    doc = strip_html(op_model.documentation) if op_model.documentation else ''

    cmd = {
        'name': full_name,
        'summary': doc,
        'parameters': [],
    }

    if op_model.input_shape and hasattr(op_model.input_shape, 'members'):
        required = set(op_model.input_shape.required_members) if hasattr(op_model.input_shape, 'required_members') else set()

        for param_name, shape in op_model.input_shape.members.items():
            param = extract_param(param_name, shape, required)
            cmd['parameters'].append(param)

        cmd['parameters'].sort(key=lambda p: (not p.get('required', False), p['name']))

    return cmd


def extract_service(session, service_name):
    """Extract all commands for a service."""
    commands = []

    try:
        service_model = session.get_service_model(service_name)

        for op_name in service_model.operation_names:
            try:
                op_model = service_model.operation_model(op_name)
                cmd = extract_operation(service_name, op_name, op_model)
                commands.append(cmd)
            except Exception as e:
                print(f"Warning: Failed to extract {service_name}.{op_name}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Failed to load service {service_name}: {e}", file=sys.stderr)

    return commands


def extract_custom_service(driver, service_name):
    """Extract commands from CLI driver for services with custom high-level commands."""
    commands = []

    cmd_table = driver._get_command_table()
    if service_name not in cmd_table:
        return commands

    service_cmd = cmd_table[service_name]
    if not hasattr(service_cmd, 'subcommand_table'):
        return commands

    for subcmd_name in service_cmd.subcommand_table:
        subcmd = service_cmd.subcommand_table[subcmd_name]
        full_name = f'{service_name} {subcmd_name}'

        desc = ''
        if hasattr(subcmd, 'DESCRIPTION') and subcmd.DESCRIPTION:
            raw_desc = subcmd.DESCRIPTION
            # Handle _FromFile objects that need to be read
            if hasattr(raw_desc, 'read'):
                raw_desc = raw_desc.read() if callable(raw_desc.read) else str(raw_desc)
            elif not isinstance(raw_desc, str):
                raw_desc = str(raw_desc)
            desc = strip_html(raw_desc)

        cmd = {
            'name': full_name,
            'summary': desc,
            'parameters': [],
        }

        # Extract parameters from ARG_TABLE
        if hasattr(subcmd, 'ARG_TABLE') and subcmd.ARG_TABLE:
            for arg in subcmd.ARG_TABLE:
                # Skip positional arguments
                if arg.get('positional_arg'):
                    continue

                arg_name = arg.get('name', '')
                if not arg_name:
                    continue

                param = {
                    'name': f'--{arg_name}',
                    'summary': strip_html(arg.get('help_text', '')),
                }

                # Check if it's a boolean flag
                action = arg.get('action', '')
                if action in ('store_true', 'store_false'):
                    param['type'] = 'bool'

                # Check for choices
                if arg.get('choices'):
                    param['choices'] = list(arg['choices'])

                cmd['parameters'].append(param)

        commands.append(cmd)

    return commands


# Services that have custom high-level commands in the CLI
# These should be extracted from the CLI driver instead of botocore
CUSTOM_SERVICES = {'s3'}


def write_param(p, indent=1, file=sys.stdout):
    """Output single param line in new schema format."""
    name = p.get('name', '')
    if not name.startswith('-'):
        return

    # Check if boolean
    is_bool = (p.get('type') == 'bool' or not p.get('takes_value', True))

    # Build option spec (AWS CLI doesn't have short options typically)
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


def write_schema(commands, global_params, version, file=sys.stdout):
    """Output schema in indentation-based format."""
    print("# AWS CLI schema for fast-completer", file=file)
    print(f"# Generated from awscli {version}", file=file)
    print("", file=file)

    # Root command
    print("aws # Amazon Web Services CLI", file=file)

    # Global params (under root command at indent 1)
    if global_params:
        for p in global_params:
            write_param(p, indent=1, file=file)

    # Build tree structure from flat command list
    # Commands are like "s3 cp", "s3 ls", "ec2 describe-instances"
    # Group by service (first word)
    services = {}
    for cmd in commands:
        parts = cmd['name'].split(' ', 1)
        service = parts[0]
        operation = parts[1] if len(parts) > 1 else None
        if service not in services:
            services[service] = []
        if operation:
            services[service].append({
                'name': operation,
                'summary': cmd.get('summary', ''),
                'parameters': cmd.get('parameters', [])
            })

    # Output services and their operations
    for service in sorted(services.keys()):
        ops = services[service]
        print(f"\t{service}", file=file)
        for op in sorted(ops, key=lambda x: x['name']):
            desc = escape_field(op.get('summary') or '')
            if desc:
                print(f"\t\t{op['name']} # {desc}", file=file)
            else:
                print(f"\t\t{op['name']}", file=file)
            for p in op.get('parameters', []):
                write_param(p, indent=3, file=file)


def build_command_tree():
    """Build complete command tree from botocore service models and CLI driver."""
    session = botocore_session.Session()
    driver = awscli.clidriver.create_clidriver()

    services = session.get_available_services()
    print(f"Found {len(services)} AWS services", file=sys.stderr)

    all_commands = []

    # Extract custom high-level commands (e.g., s3 cp, s3 sync)
    for service_name in CUSTOM_SERVICES:
        print(f"Extracting custom commands for {service_name}", file=sys.stderr)
        custom_commands = extract_custom_service(driver, service_name)
        all_commands.extend(custom_commands)
        print(f"  Found {len(custom_commands)} high-level commands", file=sys.stderr)

    for i, service_name in enumerate(sorted(services)):
        if (i + 1) % 50 == 0:
            print(f"Processing service {i + 1}/{len(services)}: {service_name}", file=sys.stderr)

        # Skip services that have custom commands (they're extracted above)
        if service_name in CUSTOM_SERVICES:
            continue

        service_commands = extract_service(session, service_name)
        all_commands.extend(service_commands)

    try:
        from awscli import __version__ as cli_version
    except ImportError:
        cli_version = 'unknown'

    global_params = get_global_params()

    return sorted(all_commands, key=lambda x: x['name']), global_params, cli_version


def main():
    print("Loading AWS CLI service models...", file=sys.stderr)

    commands, global_params, version = build_command_tree()

    print(f"Exported {len(commands)} commands", file=sys.stderr)

    write_schema(commands, global_params, version)


if __name__ == '__main__':
    main()
