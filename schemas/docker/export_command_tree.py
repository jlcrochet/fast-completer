#!/usr/bin/env python3
"""Export docker command tree for fast-completer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli


def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='docker',
        root_description='Docker CLI',
        schema_comment='Docker CLI schema for fast-completer',
        version_regex=r'Docker version\s*([\d.]+)',
    ))


if __name__ == '__main__':
    main()
