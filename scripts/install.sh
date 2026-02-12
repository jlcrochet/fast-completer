#!/bin/sh
set -e

GITHUB_REPO="jlcrochet/fast-completer"
MARKER="# fast-completer shell completions"

# Parse arguments: --shell <name> for completions
shells=""
while [ $# -gt 0 ]; do
    case "$1" in
        --shell)
            shift
            [ $# -gt 0 ] || { echo "Error: --shell requires an argument" >&2; exit 1; }
            case "$1" in
                none) ;;
                bash|zsh|fish) shells="$shells $1" ;;
                *) echo "Error: unsupported shell '$1' (supported: bash, zsh, fish, none)" >&2; exit 1 ;;
            esac
            shift
            ;;
        *)
            echo "Error: unknown option '$1'" >&2; exit 1
            ;;
    esac
done

# Detect platform
OS=$(uname -s)
ARCH=$(uname -m)
case "$OS-$ARCH" in
    Linux-x86_64)   ARTIFACT="fast-completer-linux-x86_64" ;;
    Darwin-arm64)   ARTIFACT="fast-completer-macos-arm64" ;;
    Darwin-x86_64)  ARTIFACT="fast-completer-macos-x86_64" ;;
    *) echo "Error: unsupported platform $OS $ARCH" >&2; exit 1 ;;
esac

URL="https://github.com/$GITHUB_REPO/releases/latest/download/${ARTIFACT}.zip"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ARTIFACT}.zip..."
curl -fsSL -o "$TMPDIR/release.zip" "$URL"

echo "Extracting..."
unzip -q "$TMPDIR/release.zip" -d "$TMPDIR/release"

# Install binary
BINDIR="$HOME/.local/bin"
mkdir -p "$BINDIR"
cp "$TMPDIR/release/fast-completer" "$BINDIR/"
chmod +x "$BINDIR/fast-completer"

# Install blobs
CACHE_DIR="${FAST_COMPLETER_CACHE:-$HOME/.cache/fast-completer}"
mkdir -p "$CACHE_DIR"
cp "$TMPDIR/release/blobs/"*.fcmpb "$CACHE_DIR/"

# Shell completion setup
setup_bash() {
    BASHRC="$HOME/.bashrc"
    if [ -f "$BASHRC" ] && grep -qF "$MARKER" "$BASHRC"; then
        echo "Bash completions already configured in $BASHRC"
        return
    fi
    cat >> "$BASHRC" << 'EOF'

# fast-completer shell completions
_fast_completer() {
    mapfile -t COMPREPLY < <(fast-completer -q bash "${COMP_WORDS[@]}")
}
_fc_cache="${FAST_COMPLETER_CACHE:-$HOME/.cache/fast-completer}"
for blob in "$_fc_cache"/*.fcmpb; do
    [[ -f "$blob" ]] && complete -o nosort -F _fast_completer "$(basename "$blob" .fcmpb)"
done
unset _fc_cache
EOF
    echo "Added bash completions to $BASHRC"
}

setup_zsh() {
    ZSHRC="$HOME/.zshrc"
    if [ -f "$ZSHRC" ] && grep -qF "$MARKER" "$ZSHRC"; then
        echo "Zsh completions already configured in $ZSHRC"
        return
    fi
    cat >> "$ZSHRC" << 'EOF'

# fast-completer shell completions
_fast_completer() {
    local -a completions
    completions=("${(@f)$(fast-completer -q zsh "${words[@]}")}")
    compadd -V unsorted -d completions -a completions
}
_fc_cache="${FAST_COMPLETER_CACHE:-$HOME/.cache/fast-completer}"
for blob in "$_fc_cache"/*.fcmpb(N); do
    compdef _fast_completer "${blob:t:r}"
done
unset _fc_cache
EOF
    echo "Added zsh completions to $ZSHRC"
}

setup_fish() {
    FISH_CONF="$HOME/.config/fish/conf.d/fast-completer.fish"
    if [ -f "$FISH_CONF" ]; then
        echo "Fish completions already configured in $FISH_CONF"
        return
    fi
    mkdir -p "$(dirname "$FISH_CONF")"
    cat > "$FISH_CONF" << 'EOF'
# fast-completer shell completions
function _fast_completer
    fast-completer -q fish (commandline -opc)
end

set -l _fc_cache (if set -q FAST_COMPLETER_CACHE; echo $FAST_COMPLETER_CACHE; else; echo ~/.cache/fast-completer; end)
for blob in $_fc_cache/*.fcmpb
    set -l cmd (basename $blob .fcmpb)
    complete -c $cmd -e
    complete -c $cmd -k -a "(_fast_completer)"
end
EOF
    echo "Added fish completions to $FISH_CONF"
}

reload_cmds=""
for shell in $shells; do
    case "$shell" in
        bash) setup_bash; reload_cmds="$reload_cmds  source ~/.bashrc\n" ;;
        zsh)  setup_zsh;  reload_cmds="$reload_cmds  source ~/.zshrc\n" ;;
        fish) setup_fish;  reload_cmds="$reload_cmds  source ~/.config/fish/conf.d/fast-completer.fish\n" ;;
    esac
done

echo ""
echo "Done!"
echo "  Binary installed to $BINDIR/fast-completer"
echo "  Blobs installed to $CACHE_DIR/"
if [ -n "$reload_cmds" ]; then
    echo ""
    echo "To activate completions in your current shell, run:"
    printf "$reload_cmds"
fi
