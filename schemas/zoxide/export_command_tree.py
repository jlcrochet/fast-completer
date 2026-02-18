#!/usr/bin/env python3
"""Export zoxide command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='zoxide',
        root_description='A smarter cd command',
        schema_comment='zoxide CLI schema for fast-completer',
        help_flag='-h',
    ))

if __name__ == '__main__':
    main()
