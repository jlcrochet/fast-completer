# fast-completer

A universal fast native shell completion provider for CLI tools.

This project provides a single native C binary that can provide completions for any CLI tool by reading from a binary blob file. Unlike tool-specific completers, the same binary works with AWS CLI, Azure CLI, or any other tool with a generated blob.

## Table of Contents

- [Performance](#performance)
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
- [TODO](#todo)
- [How It Works](#how-it-works)

## Performance

Some large CLIs ship with slow completion scripts. fast-completer provides a faster alternative by memory-mapping a pre-compiled binary blob instead of invoking the CLI on every tab press.

| CLI | Native Completer | fast-completer | Speedup |
|-----|------------------|----------------|---------|
| AWS CLI | 34 ms | 0.5 ms | **~70x faster** |
| Azure CLI | 190 ms | 0.3 ms | **~600x faster** |
| gcloud CLI | 500 ms | 0.3 ms | **~1700x faster** |

These CLIs use Python-based completers (argcomplete), which have significant startup overhead.

<details>
<summary>Benchmark methodology</summary>

Benchmarks were run using [hyperfine](https://github.com/sharkdp/hyperfine) with 3 warmup runs:

```bash
# AWS CLI
hyperfine --warmup 3 \
    'COMP_LINE="aws s3 " COMP_POINT=7 aws_completer' \
    './fast-completer bash aws s3 ""'

# Azure CLI
hyperfine --warmup 3 \
    '{ COMP_LINE="az storage " COMP_POINT=11 _ARGCOMPLETE=1 az 2>/dev/null; } 8>&1' \
    './fast-completer bash az storage ""'

# gcloud CLI
hyperfine --warmup 3 \
    'bash -c '\''COMP_LINE="gcloud compute " COMP_POINT=15 _ARGCOMPLETE=1 gcloud 8>&1 2>/dev/null'\''' \
    './fast-completer bash gcloud compute ""'
```

</details>

## Usage

```
fast-completer [options] <format> <spans...>
```

The CLI name is derived from the first span and used to look up the blob in the cache directory. The last span triggers completions: `""` for subcommands + flags, `-` or `--*` for flags only, `abc...` for matching subcommands. Run `fast-completer --help` for full usage information.

Parameters are sorted with required options first, then optional ones (alphabetically within each group).

### Output Formats

**Shell formats:**

| Format | Description |
|--------|-------------|
| `bash` | One value per line, no descriptions (alias: `lines`) |
| `zsh` | value:description (colon-separated) |
| `fish` | value\tdescription (tab-separated, alias: `tsv`) |
| `pwsh` | PowerShell tab-separated format |

Use the `lines` format when you only need values without descriptions.

**Options:**

| Option | Description |
|--------|-------------|
| `--add-space` | Append trailing space to completion values |
| `--full-commands` | Complete full leaf command paths instead of next level |
| `--quiet`, `-q` | Suppress error messages if blob not found (for fallback scripts) |

By default, command completion shows the next level of subcommands (e.g., `aws ""` shows `s3`, `ec2`, etc.). Use `--full-commands` to show full leaf command paths instead (e.g., `s3 cp`, `s3 ls`, `ec2 describe-instances`).

The `--add-space` option is useful for shells that don't automatically add a space after completions. Prefer shell-specific configuration when available (e.g., `complete -S ' '` in bash).

The `--quiet` option suppresses all error output, making it suitable for fallback completion setups where you want to try fast-completer first and fall back to another completer if no blob exists.

**Generic formats:**

| Format | Description |
|--------|-------------|
| `lines` | One value per line |
| `tsv` | value\tdescription (tab-separated) |
| `json` | JSON array of `{"value": ..., "description": ...}` objects |

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
cl /O2 /Fe:fast-completer.exe fast-completer.c generate_blob.c
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

Blob files contain the completion data for a specific CLI tool. Generate them from a JSON schema:

```bash
# Auto-save to cache directory
fast-completer --generate-blob aws.json

# Or specify output path explicitly
fast-completer --generate-blob aws.json /custom/path/aws.bin
```

The schema must have a `"name"` (or `"cli"`) property specifying the CLI name. This determines the blob filename when auto-saving to cache.

### Generation Options

| Option | Description |
|--------|-------------|
| `--no-descriptions` | Omit descriptions entirely (smallest blob) |
| `--long-descriptions` | Include full descriptions (default is first sentence) |
| `--big-endian` | Generate big-endian blob (for cross-compilation) |

```bash
# First sentence descriptions (default)
fast-completer --generate-blob aws.json

# Full descriptions
fast-completer --generate-blob --long-descriptions aws.json

# No descriptions
fast-completer --generate-blob --no-descriptions aws.json
```

| CLI | Default | Long | None |
|-----|---------|------|------|
| AWS | 5.8 MB | 8.7 MB | 2.3 MB |
| Azure | 1.8 MB | 2.2 MB | 1.1 MB |

The blob header includes a flag indicating whether descriptions are present. This flag is set automatically if the schema has no descriptions (like gcloud), so the completer skips description lookups for all output formats.

### Example Schemas

The `schemas/` directory contains pre-generated schemas and export scripts for popular CLIs:

| CLI | Schema | Requirements |
|-----|--------|--------------|
| AWS CLI | `schemas/aws/aws_commands.json` | `awscli` pip package |
| Azure CLI | `schemas/az/az_commands.json` | `azure-cli` pip package |
| gcloud CLI | `schemas/gcloud/gcloud_commands.json` | Google Cloud SDK (system install) |
| GitHub CLI | `schemas/gh/gh_commands.json` | `gh` CLI (system install) |

To use the included schemas:

```bash
fast-completer --generate-blob schemas/aws/aws_commands.json
fast-completer --generate-blob schemas/az/az_commands.json
fast-completer --generate-blob schemas/gcloud/gcloud_commands.json
fast-completer --generate-blob schemas/gh/gh_commands.json
```

To regenerate schemas from the latest CLI version:

```bash
# AWS (requires awscli)
cd schemas/aws
uv sync && uv run python export_command_tree.py > aws_commands.json

# Azure (requires azure-cli)
cd schemas/az
uv sync && uv run python export_command_tree.py > az_commands.json

# gcloud (requires google-cloud-sdk installed on the system)
cd schemas/gcloud
python export_command_tree.py > gcloud_commands.json

# GitHub CLI (requires gh installed: brew install gh, apt install gh, etc.)
cd schemas/gh
python export_command_tree.py > gh_commands.json
```

Each schema directory has a `pyproject.toml` for `uv` to manage dependencies. Run `uv sync` once to install dependencies, then `uv run python` to run the export script.

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

Schemas are JSON files that describe a CLI's command structure. The `schemas/` directory contains examples for AWS, Azure, and gcloud CLIs.

### Top-level Properties

| Property | Required | Description |
|----------|----------|-------------|
| `name` or `cli` | Yes | CLI name (e.g., `"aws"`). Determines the blob filename. |
| `version` | No | CLI version string |
| `global_params` | No | Array of parameters available to all commands |
| `commands` | Yes | Array of command definitions |

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

The `name` is the full command path with spaces (e.g., `ec2 run-instances`).

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
| `completer` | No | Subcommand to execute for dynamic completions (see below) |

Parameters with `type: "bool"` or names starting with `--no-` are treated as flags (no value required).

#### Dynamic Completers

The `completer` property enables dynamic completion by executing a CLI subcommand at completion time. The value is appended to the CLI name and executed, with each line of stdout becoming a completion option.

```json
{
  "name": "--kubernetes-version",
  "summary": "Version of Kubernetes to use",
  "completer": "aks get-versions"
}
```

When the user requests completions for `--kubernetes-version`, fast-completer runs `az aks get-versions` and uses the output lines as completion values. This is useful for values that change over time (versions, resource names, regions, etc.).

The completer command runs with a 2-second timeout. If the command takes longer or fails, no completions are shown for that parameter.

Note: The special value `"dynamic"` is ignored (treated as no completer). This allows schemas to mark parameters as dynamically completed without specifying a command, useful when the completion source requires authentication or complex logic not suitable for shell execution.

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

The blob format is designed for zero-copy memory-mapped access with minimal page faults:

| Section | Description |
|---------|-------------|
| Header (64 bytes) | Magic (`FCMP`), version, flags, counts, offsets |
| String table (hot) | Command names, parameter names, choices |
| String table (cold) | Descriptions (rarely accessed) |
| Commands array | Fixed-size command structs (18 bytes each) |
| Params array | Fixed-size param structs (17 bytes each) |
| Choices data | Count-prefixed uint32 offset arrays |
| Members data | Count-prefixed uint32 offset arrays |
| Global params | Param structs for global options |
| Root command | Single command struct for the CLI root |

### Design Methodology

The format prioritizes fast lookups over compact size:

**Fixed-size structs for O(1) indexing.** Commands (18 bytes) and params (17 bytes) use fixed sizes so any entry can be accessed by offset calculation rather than linear scanning. String data is stored separately in a string table, referenced by 32-bit offsets.

**VLQ length-prefixed strings.** Each string is prefixed with its length encoded as a 1-2 byte variable-length quantity (VLQ). This allows reading string length without scanning for a null terminator, enabling efficient buffer size calculation.

**Hot/cold string table separation.** The string table is split into two regions: "hot" data (command names, parameter names, choices) and "cold" data (descriptions). Since most completions display only names, the hot region stays in cache while description pages are only faulted in when needed. For the AWS CLI blob, this puts 81% of string data (descriptions) in the cold region.

**Subtree clustering for command names.** Command names are written in pre-order traversal, so each service's commands are contiguous in the string table. When completing `aws s3 ...`, all S3 command names are adjacent in memory, minimizing page faults. This trades some string deduplication (~1% larger blob) for better locality.

**Deduplication where it helps.** Choices and members lists are deduplicated via hash lookup, since many parameters share the same option sets. Parameter names and descriptions are also deduplicated since they repeat across commands.

### Header Flags

- `0x01` - Big-endian byte order
- `0x02` - No descriptions (set by `--no-descriptions` or auto-detected)

### Choices/Members Format

Variable-length count prefix (u8 if count < 255, else 0xFF + u16), followed by uint32 string table offsets. Identical lists are deduplicated to save space.

### Memory Mapping

All integers are little-endian by default. The binary uses `mmap()` (or `MapViewOfFile` on Windows) to map the blob directly into memory. The OS handles paging, so only accessed regions incur I/O. Combined with hot/cold separation, a typical completion touches only a few kilobytes of a multi-megabyte blob.

## Shell Integration

Completions are returned pre-sorted. Where possible, disable the shell's sorting to preserve the order.

### Bash

Add to your `~/.bashrc`:

```bash
_fast_completer() {
    mapfile -t COMPREPLY < <(fast-completer -q bash "${COMP_WORDS[@]}")
    # Optional: fall back to carapace
    [[ ${#COMPREPLY[@]} -eq 0 ]] && mapfile -t COMPREPLY < <(carapace "${COMP_WORDS[0]}" bash "${COMP_WORDS[@]}")
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
    completions=("${(@f)$(fast-completer -q zsh "${words[@]}")}")
    # Optional: fall back to carapace
    if [[ ${#completions[@]} -eq 0 ]]; then
        completions=("${(@f)$(carapace "${words[1]}" zsh "${words[@]}")}")
    fi
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
function _fast_completer
    set -l results (fast-completer -q fish (commandline -opc))
    if test (count $results) -eq 0
        # Optional: fall back to carapace
        carapace (commandline -opc)[1] fish (commandline -opc)
    else
        printf '%s\n' $results
    end
end

# Register for specific commands
for cmd in aws az
    complete -c $cmd -e  # clear existing completions
    complete -c $cmd -k -a "(_fast_completer)"  # -k preserves order
end

# Or register for all installed blobs
set -l _fc_cache (if set -q FAST_COMPLETER_CACHE; echo $FAST_COMPLETER_CACHE; else; echo ~/.cache/fast-completer; end)
for blob in $_fc_cache/*.bin
    set -l cmd (basename $blob .bin)
    complete -c $cmd -e
    complete -c $cmd -k -a "(_fast_completer)"
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

Nushell doesn't add trailing spaces after external completions, so use `--add-space` to append them.

```nu
$env.config.completions.external = {
    enable: true
    completer: {|spans|
        match $spans.0 {
            az | aws | gcloud | gh => {
                let completions = ^fast-completer --add-space --full-commands tsv ...$spans
                if ($completions | is-not-empty) {
                    $completions | lines | split column -n 2 "\t" value description
                }
            }
            # Optional: fall back to carapace
            _ => {
                let completions = ^carapace $cmd nushell ...$spans
                if ($completions | is-not-empty) {
                    $completions | from json
                }
            }
        }
    }
}
```

### PowerShell

Add to your profile:

```pwsh
$fcCompleter = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $spans = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
    $results = fast-completer -q pwsh @spans
    # Optional: fall back to carapace
    if (-not $results) {
        $results = carapace $spans[0] powershell @spans
    }
    $results | ForEach-Object {
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

- Structure member completion only provides top-level keys (e.g., `ebs=`, `device-name=`); nested members are not yet supported

## TODO

- Add schemas for other large CLIs (e.g., `kubectl`)
- Check schemas for value types: if it's something like "path" or "directory", we may be able to provide completions for those

## How It Works

1. `generate_blob.c` - Converts a JSON command tree to a binary blob file
2. `dump_blob.py` - Inspects and validates blob files (for debugging)
3. `fast-completer.c` - Native binary that memory-maps the blob and provides completions

The blob-based approach offers several advantages over compiled-in data:
- **Single binary**: One `fast-completer` binary works with any CLI tool
- **Easy updates**: Update completion data by replacing the blob file, no recompilation needed
- **Fast startup**: Memory-mapped I/O means near-zero initialization overhead
- **Cross-platform**: Works on Linux, macOS, and Windows
