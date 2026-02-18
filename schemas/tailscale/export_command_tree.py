#!/usr/bin/env python3
"""Export tailscale command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='tailscale',
        root_description='Tailscale VPN CLI',
        schema_comment='Tailscale CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
