#!/usr/bin/env python3
"""Export flyctl command tree for fast-completer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli


def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='flyctl',
        root_description='Fly.io CLI',
        schema_comment='Fly.io CLI schema for fast-completer',
        version_regex=r'v?([\d]+\.[\d]+\.[\d]+)',
    ))


if __name__ == '__main__':
    main()
