#!/usr/bin/env python3
"""Export yarn command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='yarn',
        root_description='JavaScript package manager',
        schema_comment='Yarn CLI schema for fast-completer',
        subcommand_strategy='help_text',
        flag_style='standard',
    ))

if __name__ == '__main__':
    main()
