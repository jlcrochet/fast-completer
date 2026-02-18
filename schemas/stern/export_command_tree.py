#!/usr/bin/env python3
"""Export stern command tree for fast-completer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli


def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='stern',
        root_description='Multi-pod log tailing',
        schema_comment='stern CLI schema for fast-completer',
        subcommand_strategy='none',
    ))


if __name__ == '__main__':
    main()
