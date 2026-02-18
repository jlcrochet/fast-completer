#!/usr/bin/env python3
"""Capture help text for all locally available CLIs.

Runs each schema's exporter with --capture to save help_cache.json files.
Only processes CLIs that are found on PATH. Generates .fcmps files too.

Usage:
    python scripts/capture_all.py              # capture all available CLIs
    python scripts/capture_all.py kubectl helm # capture specific CLIs only
"""

import shutil
import subprocess
import sys
from pathlib import Path


def get_cli_name(exporter_path):
    """Extract cli_name from an export script."""
    import re
    text = exporter_path.read_text()
    m = re.search(r"cli_name=['\"]([^'\"]+)['\"]", text)
    return m.group(1) if m else None


def main():
    root = Path(__file__).resolve().parent.parent
    schemas_dir = root / 'schemas'

    # Get list of CLIs to process
    requested = set(sys.argv[1:]) if len(sys.argv) > 1 else None

    results = {'captured': [], 'skipped': [], 'failed': []}

    for schema_dir in sorted(schemas_dir.iterdir()):
        if not schema_dir.is_dir():
            continue

        name = schema_dir.name
        if requested and name not in requested:
            continue

        exporter = schema_dir / 'export_command_tree.py'
        if not exporter.exists():
            continue

        cli_name = get_cli_name(exporter)
        if not cli_name:
            continue

        if not shutil.which(cli_name):
            if not requested:
                results['skipped'].append(name)
                continue
            print(f"  {name}: {cli_name} not found", file=sys.stderr)
            results['failed'].append(name)
            continue

        schema_file = schema_dir / f'{name}.fcmps'
        print(f"Capturing {name}...", file=sys.stderr)

        try:
            result = subprocess.run(
                [sys.executable, str(exporter), '--capture'],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0 and result.stdout.strip():
                schema_file.write_text(result.stdout)
                lines = result.stdout.count('\n')
                print(f"  {name}: {lines} lines", file=sys.stderr)
                results['captured'].append(name)
            else:
                print(f"  {name}: FAILED", file=sys.stderr)
                if result.stderr:
                    for line in result.stderr.strip().split('\n')[-3:]:
                        print(f"    {line}", file=sys.stderr)
                results['failed'].append(name)
        except subprocess.TimeoutExpired:
            print(f"  {name}: TIMEOUT", file=sys.stderr)
            results['failed'].append(name)

    print(f"\nCaptured: {len(results['captured'])}", file=sys.stderr)
    if results['skipped']:
        print(f"Skipped (not installed): {len(results['skipped'])}", file=sys.stderr)
    if results['failed']:
        print(f"Failed: {', '.join(results['failed'])}", file=sys.stderr)


if __name__ == '__main__':
    main()
