#!/usr/bin/env python3
"""Export kubectl command tree for fast-completer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli


def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='kubectl',
        root_description='Kubernetes CLI',
        schema_comment='Kubernetes CLI schema for fast-completer',
        inherited_skip_flags={'--help'},
        version_regex=r'Client Version:\s*v?([\d.]+)',
    ))


if __name__ == '__main__':
    main()
