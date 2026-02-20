#!/usr/bin/env python3
"""Export cdk command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='cdk',
        root_description='AWS Cloud Development Kit CLI',
        schema_comment='AWS CDK CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
