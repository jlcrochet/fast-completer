#!/bin/sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="${FAST_COMPLETER_CACHE:-${HOME}/.cache/fast-completer}"

# Parse arguments
only_blobs=""
exclude_blobs=""
while [ $# -gt 0 ]; do
    case "$1" in
        --only)
            shift
            [ $# -gt 0 ] || { echo "Error: --only requires a blob name" >&2; exit 1; }
            only_blobs="$only_blobs $1"
            shift
            ;;
        --exclude)
            shift
            [ $# -gt 0 ] || { echo "Error: --exclude requires a blob name" >&2; exit 1; }
            exclude_blobs="$exclude_blobs $1"
            shift
            ;;
        *)
            echo "Error: unknown option '$1'" >&2
            echo "Usage: install-blobs.sh [--only <name>]... [--exclude <name>]..." >&2
            exit 1
            ;;
    esac
done

mkdir -p "$CACHE_DIR"

src="$SCRIPT_DIR/blobs"
count=0
if [ -n "$only_blobs" ]; then
    for name in $only_blobs; do
        if [ -f "$src/${name}.fcmpb" ]; then
            cp "$src/${name}.fcmpb" "$CACHE_DIR/"
            count=$((count + 1))
        else
            echo "Warning: blob not found: ${name}.fcmpb" >&2
        fi
    done
elif [ -n "$exclude_blobs" ]; then
    for blob in "$src"/*.fcmpb; do
        [ -f "$blob" ] || continue
        name="$(basename "$blob" .fcmpb)"
        skip=false
        for ex in $exclude_blobs; do
            [ "$name" = "$ex" ] && skip=true
        done
        if [ "$skip" = false ]; then
            cp "$blob" "$CACHE_DIR/"
            count=$((count + 1))
        fi
    done
else
    cp "$src"/*.fcmpb "$CACHE_DIR/"
    count=$(ls -1 "$src"/*.fcmpb 2>/dev/null | wc -l)
fi

echo "Installed $count blob(s) to $CACHE_DIR"
