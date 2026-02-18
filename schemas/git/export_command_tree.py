#!/usr/bin/env python3
"""Export git command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='git',
        root_description='Distributed version control',
        schema_comment='git CLI schema for fast-completer',
        subcommand_strategy='help_all',
        help_all_args=('help', '-a'),
        help_flag='-h',
        max_depth=2,
    ))

if __name__ == '__main__':
    main()
