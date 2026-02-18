#!/usr/bin/env python3
"""Export oras command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli

def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='oras',
        root_description='OCI registry client',
        schema_comment='Oras CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
