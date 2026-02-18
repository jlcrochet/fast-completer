#!/usr/bin/env python3
"""Export istioctl command tree for fast-completer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli


def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='istioctl',
        root_description='Istio service mesh CLI',
        schema_comment='istioctl CLI schema for fast-completer',
    ))


if __name__ == '__main__':
    main()
