#!/usr/bin/env python3
"""Export Heroku CLI command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from oclif_exporter import OclifExportConfig, export_oclif_cli

def main():
    export_oclif_cli(OclifExportConfig(
        cli_name='heroku',
        root_description='Heroku CLI',
        schema_comment='Heroku CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
