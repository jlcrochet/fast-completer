#!/usr/bin/env python3
"""Export Salesforce CLI command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from oclif_exporter import OclifExportConfig, export_oclif_cli

def main():
    export_oclif_cli(OclifExportConfig(
        cli_name='sf',
        root_description='Salesforce CLI',
        schema_comment='Salesforce CLI schema for fast-completer',
        separator=' ',
    ))

if __name__ == '__main__':
    main()
