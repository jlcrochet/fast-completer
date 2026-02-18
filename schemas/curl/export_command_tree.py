#!/usr/bin/env python3
"""Export curl command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='curl',
        root_description='Transfer data with URLs',
        schema_comment='Curl CLI schema for fast-completer',
        help_flag='-h all',
        subcommand_strategy='none',
    ))

if __name__ == '__main__':
    main()
