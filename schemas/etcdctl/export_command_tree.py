#!/usr/bin/env python3
"""Export etcdctl command tree for fast-completer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli

def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='etcdctl',
        root_description='etcd client',
        schema_comment='Etcdctl CLI schema for fast-completer',
    ))

if __name__ == '__main__':
    main()
