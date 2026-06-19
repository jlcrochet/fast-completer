#!/usr/bin/env python3
"""Export gws command tree for fast-completer."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import command_cache
from helptext_exporter import (
    CommandTree,
    HelptextExportConfig,
    escape_field,
    get_cli_version,
    parse_flags,
    run_command,
    walk_commands,
    write_param,
)


ROOT_COMMANDS = (
    (
        ('schema',),
        'Inspect request/response schema for a method',
        [
            {'name': '--resolve-refs', 'type': 'bool', 'description': 'Inline $ref schemas recursively'},
        ],
    ),
    (
        ('mcp',),
        'Start the MCP server over stdio',
        None,
    ),
    (
        ('generate-skills',),
        'Generate SKILL.md files from API metadata',
        [
            {'name': '--output-dir', 'takes_value': True, 'description': 'Output directory for generated skills'},
            {'name': '--filter', 'takes_value': True, 'description': 'Substring filter for selected skills'},
        ],
    ),
    (
        ('auth',),
        'Authenticate and manage credentials',
        [],
    ),
    (
        ('auth', 'login'),
        'Authenticate via OAuth2 (opens browser)',
        [
            {'name': '--account', 'takes_value': True, 'description': 'Associate credentials with a specific account'},
            {'name': '--readonly', 'type': 'bool', 'description': 'Request read-only scopes'},
            {'name': '--full', 'type': 'bool', 'description': 'Request all scopes including pubsub and cloud-platform'},
            {'name': '--scopes', 'takes_value': True, 'description': 'Comma-separated custom OAuth scopes'},
            {'name': '--services', 'short': '-s', 'takes_value': True, 'description': 'Comma-separated services for scope picker'},
        ],
    ),
    (
        ('auth', 'setup'),
        'Configure GCP project and OAuth client (requires gcloud)',
        [
            {'name': '--project', 'takes_value': True, 'description': 'Use a specific GCP project'},
        ],
    ),
    (
        ('auth', 'status'),
        'Show current authentication state',
        [],
    ),
    (
        ('auth', 'export'),
        'Print decrypted credentials to stdout',
        [
            {'name': '--unmasked', 'type': 'bool', 'description': 'Include sensitive fields in clear text'},
        ],
    ),
    (
        ('auth', 'logout'),
        'Clear saved credentials and token cache',
        [
            {'name': '--account', 'takes_value': True, 'description': 'Logout a specific account (default: all accounts)'},
        ],
    ),
    (
        ('auth', 'list'),
        'List all registered accounts',
        [],
    ),
    (
        ('auth', 'default'),
        'Set the default account',
        [
            {'name': '--account', 'takes_value': True, 'description': 'Account to set as default'},
        ],
    ),
)


def parse_root_services(config):
    """Parse the SERVICES: section from `gws --help`."""
    output, _ = run_command(config.binary, '--help', timeout=config.timeout)
    if not output:
        return []

    services = []
    in_services = False
    line_re = re.compile(r'^\s{4,}([a-z0-9][a-z0-9-]*)\s{2,}(.+)$')

    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r'^SERVICES:\s*$', stripped, re.IGNORECASE):
            in_services = True
            continue
        if not in_services:
            continue
        if not stripped:
            continue
        if re.match(r'^[A-Z][A-Z ]+:$', stripped):
            break

        m = line_re.match(line)
        if not m:
            continue

        name = m.group(1)
        desc_raw = m.group(2).strip()
        desc = re.sub(r'\s*\(also:\s*[^)]*\)\s*$', '', desc_raw).strip()
        services.append((name, desc))

        alias_match = re.search(r'\(also:\s*([^)]+)\)', desc_raw)
        if alias_match:
            aliases = [a.strip() for a in alias_match.group(1).split(',') if a.strip()]
            for alias in aliases:
                services.append((alias, f"Alias for {name}"))

    deduped = []
    seen = set()
    for name, desc in services:
        if name in seen:
            continue
        seen.add(name)
        deduped.append((name, desc))
    return deduped


def main():
    config = HelptextExportConfig(
        cli_name='gws',
        root_description='Google Workspace CLI',
        schema_comment='Google Workspace CLI schema for fast-completer',
        inherited_skip_flags={'--help', '-h', '--version', '-V'},
        max_depth=8,
        timeout=20,
    )

    if not command_cache.auto_setup(config.cli_name, config.binary):
        sys.exit(1)

    version = get_cli_version(config)
    services = parse_root_services(config)
    print(f'Found {len(services)} services/aliases', file=sys.stderr)

    # Build command tree from service command surfaces.
    commands = []
    for service_name, _ in services:
        commands.extend(walk_commands(config, command_parts=[service_name]))
    commands.sort(key=lambda x: x['name'])
    print(f'Exported {len(commands)} service commands', file=sys.stderr)

    print(f'# {config.schema_comment}')
    print(f'# Generated from gws {version}')
    print()
    print('gws # Google Workspace CLI')

    # Global flags accepted before service resolution.
    write_param({
        'name': '--account',
        'description': 'Use a specific authenticated account',
    }, 1, sys.stdout)
    write_param({
        'name': '--api-version',
        'description': 'Override the API version (for example: v2, v3)',
    }, 1, sys.stdout)

    root = CommandTree()

    for path, desc, params in ROOT_COMMANDS:
        effective_params = params
        if effective_params is None:
            effective_params = parse_flags(config, list(path))
        root.add_command(list(path), desc, effective_params)

    for cmd in commands:
        root.add_command(
            cmd['name'].split(),
            cmd.get('description', ''),
            cmd.get('parameters', []),
        )

    for service_name, desc in services:
        child = root.children.get(service_name)
        if child and not child.description:
            child.description = desc

    for name in sorted(root.children):
        child = root.children[name]
        tabs = '\t'
        desc = escape_field(child.description)
        if desc:
            print(f'{tabs}{child.name} # {desc}')
        else:
            print(f'{tabs}{child.name}')
        for p in child.parameters:
            write_param(p, 2, sys.stdout)
        for sub_name in sorted(child.children):
            child.children[sub_name].write(sys.stdout, indent=2)

    command_cache.save()


if __name__ == '__main__':
    main()
