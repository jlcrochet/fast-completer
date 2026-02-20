#!/usr/bin/env python3
"""Export wrangler command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='wrangler',
        root_description='Cloudflare Workers CLI',
        schema_comment='Wrangler CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
