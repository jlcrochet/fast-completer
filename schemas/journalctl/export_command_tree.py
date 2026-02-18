#!/usr/bin/env python3
"""Export journalctl command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='journalctl',
        root_description='Query the systemd journal',
        schema_comment='Journalctl CLI schema for fast-completer',
        subcommand_strategy='none',
        flag_style='systemd',
        inherited_skip_flags={'-h', '--help', '--version'},
    ))

if __name__ == '__main__':
    main()
