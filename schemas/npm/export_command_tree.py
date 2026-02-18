#!/usr/bin/env python3
"""Export npm command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='npm',
        root_description='Node.js package manager',
        schema_comment='npm CLI schema for fast-completer',
        subcommand_strategy='npm_l',
        flag_style='npm_bracket',
        inherited_skip_flags={'--help', '-h', '--version', '-v'},
    ))

if __name__ == '__main__':
    main()
