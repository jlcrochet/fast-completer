#!/usr/bin/env python3
"""Export tar command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='tar',
        root_description='GNU tape archiver',
        schema_comment='Tar CLI schema for fast-completer',
        subcommand_strategy='none',
    ))

if __name__ == '__main__':
    main()
