#!/usr/bin/env python3
"""Export oc (OpenShift) command tree for fast-completer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli


def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='oc',
        root_description='OpenShift CLI',
        schema_comment='OpenShift CLI schema for fast-completer',
        inherited_skip_flags={'--help'},
    ))


if __name__ == '__main__':
    main()
