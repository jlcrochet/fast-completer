#!/usr/bin/env python3
"""Export bacon command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='bacon',
        root_description='Rust background checker',
        schema_comment='Bacon CLI schema for fast-completer',
        help_flag='--help',
        subcommand_strategy='none',
    ))

if __name__ == '__main__':
    main()
