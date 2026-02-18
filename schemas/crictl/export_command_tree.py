#!/usr/bin/env python3
"""Export crictl command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='crictl',
        root_description='Container runtime interface CLI',
        schema_comment='Crictl CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
