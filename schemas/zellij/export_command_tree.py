#!/usr/bin/env python3
"""Export zellij command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='zellij',
        root_description='Terminal multiplexer',
        schema_comment='Zellij CLI schema for fast-completer',
        help_flag='-h',
    ))

if __name__ == '__main__':
    main()
