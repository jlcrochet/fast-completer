#!/usr/bin/env python3
"""Export xz command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='xz',
        root_description='Compress or decompress .xz files',
        schema_comment='Xz CLI schema for fast-completer',
        help_flag='-H',
        subcommand_strategy='none',
    ))

if __name__ == '__main__':
    main()
