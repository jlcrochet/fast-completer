#!/usr/bin/env python3
"""Export watchexec command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='watchexec',
        root_description='Execute commands on file changes',
        schema_comment='Watchexec CLI schema for fast-completer',
        help_flag='-h',
        subcommand_strategy='none',
    ))

if __name__ == '__main__':
    main()
