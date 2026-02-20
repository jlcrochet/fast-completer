#!/usr/bin/env python3
"""Export zig command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='zig',
        root_description='Zig language compiler and toolchain',
        schema_comment='Zig CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
