#!/usr/bin/env python3
"""Export dotnet command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from helptext_exporter import HelptextExportConfig, export_helptext_cli

def main():
    export_helptext_cli(HelptextExportConfig(
        cli_name='dotnet',
        root_description='.NET CLI',
        schema_comment='Dotnet CLI schema for fast-completer',
        inherited_skip_flags={'--help', '-h', '-?'},
    ))

if __name__ == '__main__':
    main()
