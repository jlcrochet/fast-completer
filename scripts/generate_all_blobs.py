#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def run(cmd, cwd=None, stdout=None):
    try:
        subprocess.run(cmd, cwd=cwd, check=True, stdout=stdout)
    except subprocess.CalledProcessError as exc:
        if stdout is not None:
            print(f"Command failed: {' '.join(cmd)}", file=sys.stderr)
        raise SystemExit(exc.returncode) from exc


def refresh_schema(schema_dir: Path, schema_file: Path, exporter: Path, use_uv: bool) -> None:
    if not exporter.exists():
        print(f"No exporter found for {schema_dir.name}; using existing schema if present.", file=sys.stderr)
        return

    print(f"Refreshing schema for {schema_dir.name}")
    if use_uv:
        run(["uv", "sync"], cwd=schema_dir)
        with schema_file.open("w", encoding="utf-8") as out:
            run(["uv", "run", "python", str(exporter)], cwd=schema_dir, stdout=out)
    else:
        if (schema_dir / "pyproject.toml").exists():
            print(f"uv not found; falling back to python3 for {schema_dir.name}", file=sys.stderr)
        with schema_file.open("w", encoding="utf-8") as out:
            run(["python3", str(exporter)], cwd=schema_dir, stdout=out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate blobs for every schema under ./schemas",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Rebuild *.fcmps by running export_command_tree.py first.",
    )
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parents[1]
    schemas_dir = root_dir / "schemas"

    fast_completer = root_dir / "fast-completer"
    if not fast_completer.is_file():
        print("fast-completer binary not found; run 'make' first.", file=sys.stderr)
        return 1

    schema_dirs = sorted([p for p in schemas_dir.iterdir() if p.is_dir()])
    if not schema_dirs:
        print("No schema directories found under ./schemas", file=sys.stderr)
        return 1

    uv_available = shutil.which("uv") is not None

    for schema_dir in schema_dirs:
        name = schema_dir.name
        schema_file = schema_dir / f"{name}.fcmps"
        exporter = schema_dir / "export_command_tree.py"

        if args.refresh:
            use_uv = uv_available and (schema_dir / "pyproject.toml").exists()
            refresh_schema(schema_dir, schema_file, exporter, use_uv)

        if not schema_file.exists():
            print(f"Schema not found: {schema_file}", file=sys.stderr)
            return 1

        print(f"Generating blob for {schema_file}")
        run([str(fast_completer), "--generate-blob", str(schema_file)], cwd=root_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
