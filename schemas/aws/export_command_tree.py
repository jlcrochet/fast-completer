#!/usr/bin/env python
"""
Export AWS CLI command tree to JSON for shell completion generation.

This script loads AWS CLI's botocore service models and exports all commands,
subcommands, and their arguments in a structured JSON format.

Usage (requires awscli installed):
    python export_command_tree.py > aws_commands.json
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


def camel_to_kebab(name):
    """Convert CamelCase to kebab-case.

    Examples:
        ImageId -> image-id
        BlockDeviceMappings -> block-device-mappings
        S3BucketName -> s3-bucket-name
    """
    # Insert hyphen before uppercase letters (but not at start)
    s = re.sub(r'(?<!^)(?=[A-Z])', '-', name)
    return s.lower()


def strip_html(text):
    """Remove HTML tags and clean up text."""
    if not text:
        return ''
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Decode common HTML entities
    text = text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
    text = text.replace('&quot;', '"').replace('&#39;', "'")
    # Collapse whitespace
    text = ' '.join(text.split())
    return text.strip()


def get_global_params():
    """Extract global parameters from AWS CLI's cli.json."""
    global_params = []

    # Find cli.json in awscli package
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

                # Determine if it takes a value
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
        member_info = {'key': key}

        # For nested structures at depth 0, recurse one level
        if depth == 0 and member_shape.type_name == 'structure' and hasattr(member_shape, 'members'):
            nested = extract_structure_members(member_shape, depth=1)
            if nested:
                member_info['members'] = nested

        members.append(member_info)

    return members


def extract_param(name, shape, required_members):
    """Extract parameter information from a botocore shape."""
    option_name = f'--{camel_to_kebab(name)}'

    # Get documentation
    doc = strip_html(shape.documentation) if shape.documentation else ''
    # Truncate long descriptions
    if len(doc) > 200:
        doc = doc[:197] + '...'

    param = {
        'name': option_name,
        'options': [option_name],
        'required': name in required_members,
        'summary': doc,
    }

    # Map botocore types to simple types
    type_name = shape.type_name
    if type_name not in ('string', 'integer', 'boolean', 'timestamp'):
        param['type'] = type_name

    # Boolean params don't take values
    if type_name == 'boolean':
        param['type'] = 'bool'

    # Extract enum choices
    if hasattr(shape, 'enum') and shape.enum:
        param['choices'] = list(shape.enum)

    # Extract structure members for completion
    if type_name == 'structure':
        members = extract_structure_members(shape)
        if members:
            param['members'] = members
    elif type_name == 'list' and hasattr(shape, 'member'):
        # For lists, get the member shape's structure if applicable
        member_shape = shape.member
        if member_shape.type_name == 'structure':
            members = extract_structure_members(member_shape)
            if members:
                param['members'] = members

    return param


def extract_operation(service_name, op_name, op_model):
    """Extract command information from a botocore operation model."""
    # Convert operation name: RunInstances -> run-instances
    cmd_name = camel_to_kebab(op_name)
    full_name = f'{service_name} {cmd_name}'

    # Get documentation
    doc = strip_html(op_model.documentation) if op_model.documentation else ''
    if len(doc) > 200:
        doc = doc[:197] + '...'

    cmd = {
        'name': full_name,
        'type': 'command',
        'summary': doc,
    }

    # Extract parameters from input shape
    params = []
    if op_model.input_shape and hasattr(op_model.input_shape, 'members'):
        required = set(op_model.input_shape.required_members) if hasattr(op_model.input_shape, 'required_members') else set()

        for param_name, shape in op_model.input_shape.members.items():
            param = extract_param(param_name, shape, required)
            params.append(param)

    if params:
        # Sort: required first, then alphabetically
        params.sort(key=lambda p: (not p.get('required', False), p['name']))
        cmd['parameters'] = params

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


def build_command_tree():
    """Build complete command tree from botocore service models."""
    session = botocore_session.Session()

    # Get all available services
    services = session.get_available_services()
    print(f"Found {len(services)} AWS services", file=sys.stderr)

    all_commands = []
    groups = []

    for i, service_name in enumerate(sorted(services)):
        if (i + 1) % 50 == 0:
            print(f"Processing service {i + 1}/{len(services)}: {service_name}", file=sys.stderr)

        service_commands = extract_service(session, service_name)

        if service_commands:
            # Add service as a group
            try:
                service_model = session.get_service_model(service_name)
                service_doc = strip_html(service_model.documentation) if hasattr(service_model, 'documentation') and service_model.documentation else ''
                if len(service_doc) > 200:
                    service_doc = service_doc[:197] + '...'
            except:
                service_doc = ''

            groups.append({
                'name': service_name,
                'type': 'group',
                'summary': service_doc,
            })

            all_commands.extend(service_commands)

    # Get CLI version
    try:
        from awscli import __version__ as cli_version
    except ImportError:
        cli_version = 'unknown'

    # Get global params
    global_params = get_global_params()

    return {
        'version': cli_version,
        'cli': 'aws',
        'generated_by': 'export_command_tree.py',
        'group_count': len(groups),
        'command_count': len(all_commands),
        'global_params': global_params,
        'groups': groups,
        'commands': sorted(all_commands, key=lambda x: x['name']),
    }


def main():
    print("Loading AWS CLI service models...", file=sys.stderr)

    tree = build_command_tree()

    print(f"Exported {tree['group_count']} groups and {tree['command_count']} commands", file=sys.stderr)

    print(json.dumps(tree, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
