# fast-completer

A universal fast native shell completion provider for CLI tools.

This project provides a single native C binary that can provide completions for any CLI tool by reading from a binary blob file. Unlike tool-specific completers, the same binary works with AWS CLI, Azure CLI, or any other tool with a generated blob.

## Usage

```
fast-completer <blob> <output> <spans...>
```

The last span triggers completions: `""` for subcommands + flags, `-` or `--*` for flags only, `abc...` for matching subcommands. Run `fast-completer --help` for full usage information.

Parameters are sorted with required options first, then optional ones (alphabetically within each group).

### Output Formats

**Shell formats:**

| Format | Description |
|--------|-------------|
| `bash` | One value per line (alias: `lines`) |
| `zsh` | value:description (colon-separated) |
| `fish` | value\tdescription (tab-separated, alias: `tsv`) |
| `pwsh` | PowerShell tab-separated format |
| `nushell` | MessagePack array of maps (alias: `msgpack`) |

**Generic formats:**

| Format | Description |
|--------|-------------|
| `lines` | One value per line |
| `tsv` | value\tdescription (tab-separated) |
| `json` | JSON array of `{"value": ..., "description": ...}` objects |
| `json-tuple` | JSON array of `[value, description]` tuples |
| `msgpack` | MessagePack array of `{"value": ..., "description": ...}` maps |
| `msgpack-tuple` | MessagePack array of `[value, description]` tuples |

## Installation

### Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](../../releases/latest):

| Platform | File |
|----------|------|
| Linux (x86_64) | `fast-completer-linux-x86_64` |
| macOS (Apple Silicon) | `fast-completer-macos-arm64` |
| macOS (Intel) | `fast-completer-macos-x86_64` |
| Windows (x86_64) | `fast-completer-windows-x86_64.exe` |

Download and move to a directory in your PATH:

```bash
# Linux / macOS
chmod +x fast-completer-*
mv fast-completer-* ~/.local/bin/fast-completer

# Windows (PowerShell)
Move-Item fast-completer-windows-x86_64.exe $env:LOCALAPPDATA\Programs\fast-completer.exe
```

### From Source

Works on Linux, macOS, and Windows. Requires a C compiler and the vendor submodules:

```bash
git submodule update --init
```

#### Linux / macOS

```bash
make
make install   # installs to ~/.local/bin
```

Or with a custom location:
```bash
make install PREFIX=/usr/local   # installs to /usr/local/bin
```

#### Windows (MinGW/MSYS2)

```bash
make
make install   # installs to %LOCALAPPDATA%\Programs
```

#### Windows (MSVC)

Open a Developer Command Prompt and run:
```cmd
cl /O2 /Fe:fast-completer.exe fast-completer.c generate_blob.c vendor\cjson\cJSON.c vendor\libyaml\src\api.c vendor\libyaml\src\reader.c vendor\libyaml\src\scanner.c vendor\libyaml\src\parser.c vendor\libyaml\src\loader.c /Ivendor\libyaml\include /DHAVE_CONFIG_H
```

Then copy `fast-completer.exe` to a directory in your PATH, such as:
- `%LOCALAPPDATA%\Programs\` (create if needed, add to PATH)
- `%USERPROFILE%\bin\` (create if needed, add to PATH)

## Generating Blob Files

Blob files contain the completion data for a specific CLI tool. Generate them from a JSON or YAML schema:

```bash
# Auto-save to cache directory (~/.cache/fast-completer/<name>.bin)
fast-completer --generate-blob aws.json

# Or specify output path explicitly
fast-completer --generate-blob aws.json /custom/path/aws.bin
```

The schema must have a `"name"` (or `"cli"`) property specifying the CLI name. This determines the blob filename when auto-saving to cache.

### Example Schemas

The `schemas/` directory contains pre-generated schemas and export scripts for popular CLIs:

| CLI | Schema | Requirements |
|-----|--------|--------------|
| AWS CLI | `schemas/aws/aws_commands.json` | `awscli` package |
| Azure CLI | `schemas/az/az_commands.json` | `azure-cli` package |

To use the included schemas:

```bash
fast-completer --generate-blob schemas/aws/aws_commands.json
fast-completer --generate-blob schemas/az/az_commands.json
```

To regenerate schemas from the latest CLI version:

```bash
# AWS (requires awscli installed)
cd schemas/aws
python export_command_tree.py > aws_commands.json

# Azure (requires azure-cli installed)
cd schemas/az
python export_command_tree.py > az_commands.json
```

The export scripts introspect the installed CLI to extract all commands, parameters, and descriptions. Run them after updating your CLI to get completions for new commands.

### Inspecting Blobs

Use `dump_blob.py` to inspect and validate blob files:

```bash
# Show header and summary
python dump_blob.py commands.bin

# Find commands matching a pattern
python dump_blob.py commands.bin --find "s3.*copy"

# Show a specific command by path
python dump_blob.py commands.bin --command "s3 cp"

# Show a range of commands
python dump_blob.py commands.bin --range commands:0:20
```

## Shell Integration

Completions are returned pre-sorted. Where possible, disable the shell's sorting to preserve the order.

### Bash

Add to your `~/.bashrc`:

```bash
_aws_completer() {
    mapfile -t COMPREPLY < <(fast-completer aws bash "${COMP_WORDS[@]}")
}
complete -o nosort -F _aws_completer aws  # -o nosort requires bash 4.4+

_az_completer() {
    mapfile -t COMPREPLY < <(fast-completer az bash "${COMP_WORDS[@]}")
}
complete -o nosort -F _az_completer az
```

### Zsh

Add to your `~/.zshrc`:

```zsh
_aws_completer() {
    local -a completions
    completions=("${(@f)$(fast-completer aws zsh "${words[@]}")}")
    compadd -V unsorted -d completions -a completions  # -V preserves order
}
compdef _aws_completer aws

_az_completer() {
    local -a completions
    completions=("${(@f)$(fast-completer az zsh "${words[@]}")}")
    compadd -V unsorted -d completions -a completions
}
compdef _az_completer az
```

### Fish

Add to your `~/.config/fish/config.fish`:

```fish
complete -c aws -e  # clear existing completions
complete -c aws -k -a "(fast-completer aws fish (commandline -opc))"  # -k preserves order

complete -c az -e
complete -c az -k -a "(fast-completer az fish (commandline -opc))"
```

### Elvish

Add to your `~/.config/elvish/rc.elv`:

```elvish
set edit:completion:arg-completer[aws] = {|@words|
    fast-completer aws tsv $@words | from-lines | each {|line|
        var parts = (str:split "\t" $line)
        edit:complex-candidate $parts[0] &display-suffix=' '$parts[1]
    }
}
```

### Nushell

Add to your config:

```nu
let aws_completer = {|spans|
    ^fast-completer aws nushell ...$spans | from msgpack
}

let az_completer = {|spans|
    ^fast-completer az nushell ...$spans | from msgpack
}

let external_completer = {|spans|
    match $spans.0 {
        aws => $aws_completer
        az => $az_completer
    } | do $in $spans
}

$env.config.completions.external = {
    enable: true
    completer: $external_completer
}
```

### PowerShell

Add to your profile:

```pwsh
Register-ArgumentCompleter -Native -CommandName aws -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $spans = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
    fast-completer aws pwsh @spans | ForEach-Object {
        $parts = $_ -split "`t"
        [System.Management.Automation.CompletionResult]::new($parts[0], $parts[1], $parts[2], $parts[3])
    }
}
```

## Binary Blob Format

The blob format is designed for zero-copy memory-mapped access:

| Section | Description |
|---------|-------------|
| Header (68 bytes) | Magic (`FCMP`), version, counts, offsets |
| String table | VLQ length-prefixed, deduplicated strings |
| Commands array | Fixed-size command structs (16 bytes each) |
| Params array | Fixed-size param structs (13 bytes each) |
| Choices data | Null-terminated uint32 offset arrays |
| Members data | Null-terminated uint32 offset arrays |
| Global params | Param structs for global options |
| Root command | Single command struct for the CLI root |

All integers are little-endian. The binary uses `mmap()` (or `MapViewOfFile` on Windows) to map the blob directly into memory with no parsing overhead.

## Limitations

- Only outputs long options (e.g., `--instance-type`, not short options)
- Does not support dynamic completers (e.g., completing resource names from your cloud account)
- Structure member completion only provides top-level keys (e.g., `ebs=`, `device-name=`); nested members are not yet supported

## How It Works

1. `generate_blob.c` - Converts a JSON command tree to a binary blob file
2. `dump_blob.py` - Inspects and validates blob files (for debugging)
3. `fast-completer.c` - Native binary that memory-maps the blob and provides completions

The blob-based approach offers several advantages over compiled-in data:
- **Single binary**: One `fast-completer` binary works with any CLI tool
- **Easy updates**: Update completion data by replacing the blob file, no recompilation needed
- **Fast startup**: Memory-mapped I/O means near-zero initialization overhead
- **Cross-platform**: Works on Linux, macOS, and Windows
