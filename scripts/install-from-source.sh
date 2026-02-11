#!/bin/sh
set -e

REPO="https://github.com/jlcrochet/fast-completer.git"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Cloning fast-completer..."
git clone --depth 1 "$REPO" "$TMPDIR/fast-completer"

echo "Building..."
make -C "$TMPDIR/fast-completer"

echo "Installing binary..."
make -C "$TMPDIR/fast-completer" install

echo "Generating blobs..."
for schema in "$TMPDIR/fast-completer/schemas"/*/*.fcmps; do
    [ -f "$schema" ] || continue
    "$TMPDIR/fast-completer/fast-completer" --generate-blob "$schema"
done

# Set up bash completions
BASHRC="$HOME/.bashrc"
MARKER="# fast-completer shell completions"

if [ -f "$BASHRC" ] && grep -qF "$MARKER" "$BASHRC"; then
    echo "Bash completions already configured in $BASHRC"
else
    cat >> "$BASHRC" << 'BASH_COMPLETIONS'

# fast-completer shell completions
_fast_completer() {
    mapfile -t COMPREPLY < <(fast-completer -q bash "${COMP_WORDS[@]}")
}
_fc_cache="${FAST_COMPLETER_CACHE:-$HOME/.cache/fast-completer}"
for blob in "$_fc_cache"/*.fcmpb; do
    [[ -f "$blob" ]] && complete -o nosort -F _fast_completer "$(basename "$blob" .fcmpb)"
done
unset _fc_cache
BASH_COMPLETIONS
    echo "Added bash completions to $BASHRC"
fi

CACHE_DIR="${FAST_COMPLETER_CACHE:-$HOME/.cache/fast-completer}"
echo ""
echo "Done!"
echo "  Binary installed to ~/.local/bin/fast-completer"
echo "  Blobs installed to $CACHE_DIR/"
echo "  Bash completions configured in $BASHRC"
echo ""
echo "To activate completions in your current shell, run:"
echo "  source $BASHRC"
