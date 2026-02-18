#!/usr/bin/env python3
"""Export starship command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='starship',
        root_description='Cross-shell prompt',
        schema_comment='Starship CLI schema for fast-completer',
        help_flag='-h',
    ))

if __name__ == '__main__':
    main()
