#!/usr/bin/env python3
"""Export just command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='just',
        root_description='Command runner',
        schema_comment='Just CLI schema for fast-completer',
        help_flag='-h',
    ))

if __name__ == '__main__':
    main()
