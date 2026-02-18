#!/usr/bin/env python3
"""Export krew command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli

def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='krew',
        root_description='kubectl plugin manager',
        schema_comment='Krew CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
