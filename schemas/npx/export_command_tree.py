#!/usr/bin/env python3
"""Export npx command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='npx',
        root_description='Execute npm package binaries',
        schema_comment='Npx CLI schema for fast-completer',
        subcommand_strategy='none',
        flag_style='npm_bracket',
        inherited_skip_flags={'--help', '-h', '--version', '-v'},
    ))

if __name__ == '__main__':
    main()
