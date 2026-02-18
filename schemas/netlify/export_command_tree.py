#!/usr/bin/env python3
"""Export Netlify CLI command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='netlify',
        root_description='Netlify CLI',
        schema_comment='Netlify CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
