# fast-completer

A universal fast native shell completion provider for CLI tools.

This project provides a single native C binary that can provide completions for any CLI tool by reading from a binary blob file. Unlike tool-specific completers, the same binary works with AWS CLI, Azure CLI, or any other tool with a generated blob.

## Table of Contents

- [Usage](#usage)
  - [Output Formats](#output-formats)
- [Installation](#installation)
  - [Pre-built Binaries](#pre-built-binaries)
  - [From Source](#from-source)
- [Cache Directory](#cache-directory)
- [Generating Blob Files](#generating-blob-files)
  - [Example Schemas](#example-schemas)
  - [Inspecting Blobs](#inspecting-blobs)
- [Schema Format](#schema-format)
  - [Top-level Properties](#top-level-properties)
  - [Groups](#groups)
  - [Commands](#commands)
  - [Parameters](#parameters)
  - [Global Parameters](#global-parameters)
- [Binary Blob Format](#binary-blob-format)
- [Shell Integration](#shell-integration)
  - [Bash](#bash)
  - [Zsh](#zsh)
  - [Fish](#fish)
  - [Elvish](#elvish)
  - [Nushell](#nushell)
  - [PowerShell](#powershell)
- [Limitations](#limitations)
- [How It Works](#how-it-works)

## Usage

```
fast-completer <format> <spans...>
```

The CLI name is derived from the first span and used to look up the blob in the cache directory. The last span triggers completions: `""` for subcommands + flags, `-` or `--*` for flags only, `abc...` for matching subcommands. Run `fast-completer --help` for full usage information.

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
cl /O3 /Fe:fast-completer.exe fast-completer.c generate_blob.c vendor\cjson\cJSON.c vendor\libyaml\src\api.c vendor\libyaml\src\reader.c vendor\libyaml\src\scanner.c vendor\libyaml\src\parser.c vendor\libyaml\src\loader.c /Ivendor\libyaml\include /DHAVE_CONFIG_H
```

Then copy `fast-completer.exe` to a directory in your PATH, such as:
- `%LOCALAPPDATA%\Programs\` (create if needed, add to PATH)
- `%USERPROFILE%\bin\` (create if needed, add to PATH)

## Cache Directory

Blobs are stored in and loaded from a cache directory:

| Platform | Default Location |
|----------|------------------|
| Linux/macOS | `~/.cache/fast-completer/` |
| Windows | `%LOCALAPPDATA%\fast-completer\` |

Set `FAST_COMPLETER_CACHE` to override the default location:

```bash
export FAST_COMPLETER_CACHE=~/my-completions
```

## Generating Blob Files

Blob files contain the completion data for a specific CLI tool. Generate them from a JSON or YAML schema:

```bash
# Auto-save to cache directory
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

## Schema Format

Schemas are JSON or YAML files that describe a CLI's command structure. The `schemas/` directory contains examples for AWS and Azure CLIs.

### Top-level Properties

| Property | Required | Description |
|----------|----------|-------------|
| `name` or `cli` | Yes | CLI name (e.g., `"aws"`). Determines the blob filename. |
| `version` | No | CLI version string |
| `global_params` | No | Array of parameters available to all commands |
| `groups` | No | Array of command groups (subcommand namespaces) |
| `commands` | Yes | Array of command definitions |

### Groups

Groups are subcommand namespaces (e.g., `aws s3`, `az storage`):

```json
{
  "name": "s3",
  "type": "group",
  "summary": "Amazon S3 commands"
}
```

### Commands

Commands are the leaf nodes that perform actions:

```json
{
  "name": "s3 cp",
  "type": "command",
  "summary": "Copies a file or object to/from S3",
  "parameters": [...]
}
```

The `name` is the full command path with spaces (e.g., `"ec2 run-instances"`).

### Parameters

Parameters define the flags and options for a command:

```json
{
  "name": "--instance-type",
  "options": ["--instance-type"],
  "required": false,
  "summary": "The instance type",
  "choices": ["t2.micro", "t2.small", "t2.medium"]
}
```

| Property | Required | Description |
|----------|----------|-------------|
| `name` | Yes | Primary option name (e.g., `"--instance-type"`) |
| `options` | No | Array of option aliases |
| `required` | No | Whether the parameter is required (default: false) |
| `summary` | No | Short description for completion display |
| `description` | No | Longer description |
| `type` | No | Type hint (`"bool"` for flags that don't take values) |
| `choices` | No | Array of valid values for completion |
| `members` | No | For structure/list types, array of `{"key": "..."}` member names |

Parameters with `type: "bool"` or names starting with `--no-` are treated as flags (no value required).

### Global Parameters

Global parameters appear in `global_params` and are available to all commands:

```json
{
  "name": "--region",
  "description": "The region to use",
  "takes_value": true,
  "choices": ["us-east-1", "us-west-2", "eu-west-1"]
}
```

| Property | Required | Description |
|----------|----------|-------------|
| `name` | Yes | Option name (e.g., `"--region"`) |
| `description` | No | Description for completion display |
| `takes_value` | No | Whether the option takes a value (default: true) |
| `choices` | No | Array of valid values |

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

## Shell Integration

Completions are returned pre-sorted. Where possible, disable the shell's sorting to preserve the order.

### Bash

Add to your `~/.bashrc`:

```bash
_fast_completer() {
    mapfile -t COMPREPLY < <(fast-completer bash "${COMP_WORDS[@]}")
}

# Register for specific commands
complete -o nosort -F _fast_completer aws az  # -o nosort requires bash 4.4+

# Or register for all installed blobs
_fc_cache="${FAST_COMPLETER_CACHE:-$HOME/.cache/fast-completer}"
for blob in "$_fc_cache"/*.bin; do
    [[ -f "$blob" ]] && complete -o nosort -F _fast_completer "$(basename "$blob" .bin)"
done
```

### Zsh

Add to your `~/.zshrc`:

```zsh
_fast_completer() {
    local -a completions
    completions=("${(@f)$(fast-completer zsh "${words[@]}")}")
    compadd -V unsorted -d completions -a completions  # -V preserves order
}

# Register for specific commands
compdef _fast_completer aws az

# Or register for all installed blobs
_fc_cache="${FAST_COMPLETER_CACHE:-$HOME/.cache/fast-completer}"
for blob in "$_fc_cache"/*.bin(N); do
    compdef _fast_completer "${blob:t:r}"
done
```

### Fish

Add to your `~/.config/fish/config.fish`:

```fish
# Register for specific commands
for cmd in aws az
    complete -c $cmd -e  # clear existing completions
    complete -c $cmd -k -a "(fast-completer fish (commandline -opc))"  # -k preserves order
end

# Or register for all installed blobs
set -l _fc_cache (if set -q FAST_COMPLETER_CACHE; echo $FAST_COMPLETER_CACHE; else; echo ~/.cache/fast-completer; end)
for blob in $_fc_cache/*.bin
    set -l cmd (basename $blob .bin)
    complete -c $cmd -e
    complete -c $cmd -k -a "(fast-completer fish (commandline -opc))"
end
```

### Elvish

Add to your `~/.config/elvish/rc.elv`:

```elvish
var fast-completer~ = {|@words|
    fast-completer tsv $@words | from-lines | each {|line|
        var parts = (str:split "\t" $line)
        edit:complex-candidate $parts[0] &display-suffix=' '$parts[1]
    }
}

# Register for specific commands
for cmd [aws az] {
    set edit:completion:arg-completer[$cmd] = $fast-completer~
}
```

### Nushell

Add to your config:

```nu
let fc_completer = {|spans|
    ^fast-completer nushell ...$spans | from msgpack
}

# Check if a blob exists for the command
def has-fc-blob [cmd: string] {
    let cache = ($env.FAST_COMPLETER_CACHE? | default ($env.HOME | path join ".cache/fast-completer"))
    ($cache | path join $"($cmd).bin" | path exists)
}

let external_completer = {|spans|
    if (has-fc-blob $spans.0) {
        do $fc_completer $spans
    } else {
        null  # fall back to default completion
    }
}

$env.config.completions.external = {
    enable: true
    completer: $external_completer
}
```

### PowerShell

Add to your profile:

```pwsh
$fcCompleter = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $spans = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
    fast-completer pwsh @spans | ForEach-Object {
        $parts = $_ -split "`t"
        [System.Management.Automation.CompletionResult]::new($parts[0], $parts[1], $parts[2], $parts[3])
    }
}

# Register for specific commands
Register-ArgumentCompleter -Native -CommandName aws, az -ScriptBlock $fcCompleter

# Or register for all installed blobs
$fcCache = if ($env:FAST_COMPLETER_CACHE) { $env:FAST_COMPLETER_CACHE } else { "$env:LOCALAPPDATA\fast-completer" }
Get-ChildItem "$fcCache\*.bin" -ErrorAction SilentlyContinue | ForEach-Object {
    Register-ArgumentCompleter -Native -CommandName $_.BaseName -ScriptBlock $fcCompleter
}
```

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
