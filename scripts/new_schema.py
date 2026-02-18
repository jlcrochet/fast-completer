#!/usr/bin/env python3
"""Generate boilerplate schema directory for a new CLI.

Usage:
    python scripts/new_schema.py <framework> <cli_name> "<description>"

Frameworks:
    cobra      - Go CLIs using Cobra (kubectl, docker, helm, ...)
    oclif      - Node.js CLIs using oclif (heroku, sf, netlify, ...)
    clap       - Rust CLIs using clap (cargo, rg, fd, bat, ...)
    hashicorp  - HashiCorp CLIs (terraform, vault, consul, ...)
    helptext   - Generic help-text parser (git, npm, pip, ...)
    systemd    - systemd tools (journalctl, systemctl, ...)

Examples:
    python scripts/new_schema.py cobra kubectl "Kubernetes CLI"
    python scripts/new_schema.py clap rg "Recursively search for a regex pattern" --flat
    python scripts/new_schema.py oclif heroku "Heroku CLI"
    python scripts/new_schema.py hashicorp vault "Secret management"

Options:
    --flat          No subcommands (clap/helptext only: rg, fd, bat, eza, ...)
    --separator C   oclif command ID separator (default: ":")
"""

import argparse
import os
import sys

FRAMEWORKS = {
    'cobra': {
        'module': 'cobra_exporter',
        'config_class': 'CobraExportConfig',
        'entry_point': 'export_cobra_cli',
    },
    'oclif': {
        'module': 'oclif_exporter',
        'config_class': 'OclifExportConfig',
        'entry_point': 'export_oclif_cli',
    },
    'clap': {
        'module': 'helptext_exporter',
        'config_class': 'HelptextExportConfig',
        'entry_point': 'export_helptext_cli',
    },
    'hashicorp': {
        'module': 'helptext_exporter',
        'config_class': 'HelptextExportConfig',
        'entry_point': 'export_helptext_cli',
    },
    'helptext': {
        'module': 'helptext_exporter',
        'config_class': 'HelptextExportConfig',
        'entry_point': 'export_helptext_cli',
    },
    'systemd': {
        'module': 'helptext_exporter',
        'config_class': 'HelptextExportConfig',
        'entry_point': 'export_helptext_cli',
    },
}

EXPORT_TEMPLATE = '''\
#!/usr/bin/env python3
"""Export {cli_name} command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from {module} import {config_class}, {entry_point}

def main():
    {entry_point}({config_class}(
        cli_name='{cli_name}',
        root_description='{description}',
        schema_comment='{cli_title} CLI schema for fast-completer',
{extra_config}\
    ))

if __name__ == '__main__':
    main()
'''

PYPROJECT_TEMPLATE = '''\
[project]
name = "{cli_name}-schema-export"
version = "0.1.0"
description = "Export {cli_title} command tree for fast-completer"
requires-python = ">=3.8"

[project.scripts]
export-{cli_name} = "export_command_tree:main"
'''


def build_extra_config(framework, flat=False, separator=None):
    """Build framework-specific config lines."""
    lines = []
    if framework == 'clap':
        lines.append("        help_flag='-h',")
        if flat:
            lines.append("        subcommand_strategy='none',")
    elif framework == 'hashicorp':
        lines.append("        flag_style='hashicorp',")
        lines.append("        help_flag='-help',")
        lines.append("        inherited_skip_flags={'-help', '-version'},")
    elif framework == 'helptext':
        if flat:
            lines.append("        subcommand_strategy='none',")
    elif framework == 'systemd':
        lines.append("        flag_style='systemd',")
        lines.append("        inherited_skip_flags={'-h', '--help', '--version'},")
        if flat:
            lines.append("        subcommand_strategy='none',")
    elif framework == 'oclif':
        if separator and separator != ':':
            lines.append(f"        separator='{separator}',")
    if lines:
        return '\n'.join(lines) + '\n'
    return ''


def main():
    parser = argparse.ArgumentParser(
        description='Generate boilerplate schema directory for a new CLI')
    parser.add_argument('framework', choices=FRAMEWORKS.keys(),
                        help='CLI framework type')
    parser.add_argument('cli_name', help='CLI binary name (e.g. kubectl)')
    parser.add_argument('description', help='Short CLI description')
    parser.add_argument('--flat', action='store_true',
                        help='No subcommands (clap/helptext only)')
    parser.add_argument('--separator', default=':',
                        help='oclif command ID separator (default: ":")')
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    schema_dir = os.path.join(project_root, 'schemas', args.cli_name)

    if os.path.exists(schema_dir):
        existing = os.listdir(schema_dir)
        if 'export_command_tree.py' in existing:
            print(f"Error: {schema_dir}/export_command_tree.py already exists",
                  file=sys.stderr)
            sys.exit(1)

    os.makedirs(schema_dir, exist_ok=True)

    fw = FRAMEWORKS[args.framework]
    cli_title = args.cli_name.capitalize()
    extra = build_extra_config(args.framework, args.flat, args.separator)

    export_content = EXPORT_TEMPLATE.format(
        cli_name=args.cli_name,
        cli_title=cli_title,
        description=args.description,
        module=fw['module'],
        config_class=fw['config_class'],
        entry_point=fw['entry_point'],
        extra_config=extra,
    )

    pyproject_content = PYPROJECT_TEMPLATE.format(
        cli_name=args.cli_name,
        cli_title=cli_title,
    )

    export_path = os.path.join(schema_dir, 'export_command_tree.py')
    pyproject_path = os.path.join(schema_dir, 'pyproject.toml')

    with open(export_path, 'w') as f:
        f.write(export_content)
    with open(pyproject_path, 'w') as f:
        f.write(pyproject_content)

    print(f"Created {os.path.relpath(export_path, project_root)}")
    print(f"Created {os.path.relpath(pyproject_path, project_root)}")
    print()
    print(f"To generate the schema:")
    print(f"  python {os.path.relpath(export_path, project_root)} > schemas/{args.cli_name}/{args.cli_name}.fcmps")
    print(f"  ./fast-completer --generate-blob schemas/{args.cli_name}/{args.cli_name}.fcmps")


if __name__ == '__main__':
    main()
