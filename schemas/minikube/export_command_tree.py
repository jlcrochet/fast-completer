#!/usr/bin/env python3
"""Export minikube command tree for fast-completer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from cobra_exporter import CobraExportConfig, export_cobra_cli


def main():
    export_cobra_cli(CobraExportConfig(
        cli_name='minikube',
        root_description='Local Kubernetes',
        schema_comment='minikube CLI schema for fast-completer',
    ))


if __name__ == '__main__':
    main()
