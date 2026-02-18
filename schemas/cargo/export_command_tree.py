#!/usr/bin/env python3
"""Export cargo command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='cargo',
        root_description='Rust package manager',
        schema_comment='Cargo CLI schema for fast-completer',
        help_flag='-h',
    ))

if __name__ == '__main__':
    main()
