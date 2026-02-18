#!/usr/bin/env python3
"""Export Twilio CLI command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='twilio',
        root_description='Twilio CLI',
        schema_comment='Twilio CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
