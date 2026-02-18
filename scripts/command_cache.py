#!/usr/bin/env python3
"""
Command output caching for offline schema generation.

Allows exporter scripts to generate .fcmps schemas without the actual CLI
installed by replaying cached command outputs. Each CLI's cache is stored
as a JSON file in its schema directory (schemas/<cli>/help_cache.json).

Usage modes:
  - Live (default when CLI is available): runs commands directly, no caching
  - Capture (--capture flag): runs commands and saves outputs to cache file
  - Offline (CLI not found, cache exists): replays from cache file

The exporter frameworks (helptext_exporter, cobra_exporter, oclif_exporter)
call auto_setup() at startup, which picks the right mode automatically.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

_cache_data = None
_cache_path = None
_capture_mode = False


def setup(cache_path, capture=False):
    """Initialize the command cache.

    Args:
        cache_path: Path to the help_cache.json file.
        capture: If True, run commands live and record outputs.
                 If False, replay from existing cache (offline mode).
    """
    global _cache_data, _cache_path, _capture_mode
    _cache_path = Path(cache_path)
    _capture_mode = capture
    if capture:
        _cache_data = {}
    elif _cache_path.exists():
        with open(_cache_path) as f:
            _cache_data = json.load(f)


def save():
    """Write captured command outputs to disk. No-op if not in capture mode."""
    if _capture_mode and _cache_path and _cache_data:
        _cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(_cache_path, 'w') as f:
            json.dump(_cache_data, f, indent=2, sort_keys=True)
        count = len(_cache_data)
        print(f"Saved {count} cached responses to {_cache_path}", file=sys.stderr)


def is_active():
    """True if cache is set up (either capturing or replaying)."""
    return _cache_data is not None


def execute(*args, timeout=30, merge_stderr=False):
    """Run a command with transparent caching.

    When cache is not set up: runs the command directly (live mode).
    When in offline mode: returns cached output (or empty on cache miss).
    When in capture mode: runs the command and records the output.

    Args:
        *args: Command and arguments to run.
        timeout: Timeout in seconds.
        merge_stderr: If True, fall back to stderr when stdout is empty
                      (used by helptext_exporter since some CLIs print help to stderr).
    """
    key = ' '.join(str(a) for a in args)

    # Offline mode: return cached result
    if _cache_data is not None and not _capture_mode:
        entry = _cache_data.get(key)
        if entry:
            return entry.get('stdout', ''), entry.get('returncode', 1)
        return "", 1

    # Live execution
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if merge_stderr:
            stdout = result.stdout or result.stderr
        else:
            stdout = result.stdout
        rc = result.returncode
    except subprocess.TimeoutExpired:
        print(f"Timeout running: {' '.join(str(a) for a in args)}", file=sys.stderr)
        stdout, rc = "", 1
    except FileNotFoundError:
        stdout, rc = "", 1

    # Capture mode: record result
    if _capture_mode and _cache_data is not None:
        _cache_data[key] = {'stdout': stdout, 'returncode': rc}

    return stdout, rc


def get_schema_dir(cli_name):
    """Get the schema directory for a CLI based on project structure."""
    return Path(__file__).resolve().parent.parent / 'schemas' / cli_name


def auto_setup(cli_name, binary=None):
    """Auto-configure cache based on CLI availability and --capture flag.

    Call this at the start of an export. It checks:
    1. If --capture is passed: sets up capture mode (requires CLI).
    2. If CLI is available: returns True (live mode, no caching).
    3. If CLI is missing but cache exists: sets up offline mode.
    4. Otherwise: returns False (can't proceed).

    Returns True if the export can proceed, False otherwise.
    """
    schema_dir = get_schema_dir(cli_name)
    cache_path = schema_dir / 'help_cache.json'
    binary = binary or cli_name

    if '--capture' in sys.argv:
        if not shutil.which(binary):
            print(
                f"Error: {cli_name} not found (required for --capture)",
                file=sys.stderr,
            )
            return False
        setup(cache_path, capture=True)
        return True

    if shutil.which(binary):
        # CLI available — run live, no caching
        return True

    if cache_path.exists():
        # CLI not available — use cached help text
        setup(cache_path, capture=False)
        print(f"Using cached help text for {cli_name}", file=sys.stderr)
        return True

    print(
        f"Error: {cli_name} not found and no cache at {cache_path}",
        file=sys.stderr,
    )
    return False
