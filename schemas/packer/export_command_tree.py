#!/usr/bin/env python3
"""Export packer command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='packer',
        root_description='HashiCorp Packer',
        schema_comment='Packer CLI schema for fast-completer',
        flag_style='hashicorp',
        help_flag='-help',
        inherited_skip_flags={'-help', '-version'},
    ))

if __name__ == '__main__':
    main()
