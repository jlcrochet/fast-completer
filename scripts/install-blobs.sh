#!/bin/sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="${FAST_COMPLETER_CACHE:-${HOME}/.cache/fast-completer}"
mkdir -p "$CACHE_DIR"
cp "$SCRIPT_DIR"/blobs/*.fcmpb "$CACHE_DIR/"
echo "Installed blobs to $CACHE_DIR"
