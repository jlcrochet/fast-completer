#!/usr/bin/env python3
"""Export pulumi command tree for fast-completer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli


def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='pulumi',
        root_description='Infrastructure as code',
        schema_comment='Pulumi CLI schema for fast-completer',
        version_regex=r'v?([\d.]+)',
    ))


if __name__ == '__main__':
    main()
