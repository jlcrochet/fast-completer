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
  - [Parameters](#parameters)
  - [Dynamic Completers](#dynamic-completers)
  - [Example](#example)
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

**Parameter ordering:** Parameters are listed with the most specific first -— a command's own parameters appear before inherited parameters from parent commands, which appear before global parameters. This means the most relevant options are shown first when completing deeply nested commands.

### Output Formats

**Shell formats:**

| Format | Description |
|--------|-------------|
| `bash` | One value per line, no descriptions (alias: `lines`) |
| `zsh` | value:description (colon-separated) |
| `fish` | value\tdescription (tab-separated, alias: `tsv`) |
| `pwsh` | PowerShell tab-separated format |

**Generic formats:**

| Format | Description |
|--------|-------------|
| `lines` | One value per line |
| `tsv` | value\tdescription (tab-separated) |
| `json` | JSON array of `{"value": ..., "description": ...}` objects |

Use the `lines` format when you only need values without descriptions.

**Options:**

| Option | Description |
|--------|-------------|
| `--add-space` | Append trailing space to completion values |
| `--full-commands` | Complete full leaf command paths instead of next level |
| `--quiet`, `-q` | Silently exit if blob not found (for fallback scripts) |

By default, command completion shows the next level of subcommands (e.g., `aws ""` shows `s3`, `ec2`, etc.). Use `--full-commands` to show full leaf command paths instead (e.g., `s3 cp`, `s3 ls`, `ec2 describe-instances`).

The `--add-space` option is useful for shells that don't automatically add a space after completions. Prefer shell-specific configuration when available (e.g., `complete -S ' '` in bash).

The `--quiet` option silently exits if the blob doesn't exist, making it suitable for fallback completion setups. Unexpected errors (invalid blob format, version mismatch, etc.) still print to help diagnose issues. Use `--check` to test if a blob exists before attempting completions.

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

Works on Linux, macOS, and Windows. Requires a C compiler.

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
cl /O2 /Fe:fast-completer.exe src\\fast-completer.c src\\generate_blob.c compat\\getopt.c
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

Blob files contain the completion data for a specific CLI tool. Generate them from a schema file:

```bash
# Auto-save to cache directory
fast-completer --generate-blob aws.fcmps

# Or specify output path explicitly
fast-completer --generate-blob aws.fcmps /custom/path/aws.fcmpb
```

The CLI name is derived from the first command in the schema (the root command). This determines the blob filename when auto-saving to cache.

Generate blobs for all schemas at once:

```bash
./scripts/generate_all_blobs.py
./scripts/generate_all_blobs.py --refresh
```

The `--refresh` flag runs each schema's `export_command_tree.py` first. If `pyproject.toml` is present and `uv` is installed, the script uses `uv sync` and `uv run python`; otherwise it falls back to `python3`.

### Generation Options

| Option | Description |
|--------|-------------|
| `--short-descriptions` | First sentence only (default) |
| `--long-descriptions` | Include full descriptions |
| `--no-descriptions` | Omit descriptions entirely (smallest blob) |
| `--description-length <n>` | Truncate descriptions to n characters |
| `--big-endian` | Generate big-endian blob (for cross-compilation) |

Description options can be combined: `--long-descriptions --description-length 200` includes full descriptions but truncates any exceeding 200 characters. If multiple description mode options are given, the last one wins.

```bash
# First sentence descriptions (default)
fast-completer --generate-blob aws.fcmps

# Same as default, but explicit
fast-completer --generate-blob --short-descriptions aws.fcmps

# Full descriptions
fast-completer --generate-blob --long-descriptions aws.fcmps

# No descriptions
fast-completer --generate-blob --no-descriptions aws.fcmps
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
| AWS CLI | `schemas/aws/aws.fcmps` | AWS CLI v2 (official installer, not PyPI) |
| Azure CLI | `schemas/az/az.fcmps` | `azure-cli` pip package |
| gcloud CLI | `schemas/gcloud/gcloud.fcmps` | Google Cloud SDK (system install) |
| GitHub CLI | `schemas/gh/gh.fcmps` | `gh` CLI (system install) |

To use the included schemas:

```bash
fast-completer --generate-blob schemas/aws/aws.fcmps
fast-completer --generate-blob schemas/az/az.fcmps
fast-completer --generate-blob schemas/gcloud/gcloud.fcmps
fast-completer --generate-blob schemas/gh/gh.fcmps
```

To regenerate schemas from the latest CLI version:

```bash
# AWS (requires AWS CLI v2 installed via official installer)
cd schemas/aws
python3 export_command_tree.py > aws.fcmps

# Azure (requires azure-cli pip package)
cd schemas/az
uv sync && uv run python export_command_tree.py > az.fcmps

# gcloud (requires google-cloud-sdk installed on the system)
cd schemas/gcloud
python3 export_command_tree.py > gcloud.fcmps

# GitHub CLI (requires gh installed: brew install gh, apt install gh, etc.)
cd schemas/gh
python3 export_command_tree.py > gh.fcmps
```

Some schema directories have a `pyproject.toml` for `uv` to manage pip dependencies (Azure CLI). For others, the CLI must be installed on the system (AWS CLI v2, gcloud, gh).

The export scripts introspect the installed CLI to extract all commands, parameters, and descriptions. Run them after updating your CLI to get completions for new commands.

### Inspecting Blobs

Use `scripts/dump_blob.py` to inspect and validate blob files:

```bash
# Show header and summary
python scripts/dump_blob.py commands.fcmpb

# Find commands matching a pattern
python scripts/dump_blob.py commands.fcmpb --find "s3.*copy"

# Show a specific command by path
python scripts/dump_blob.py commands.fcmpb --command "s3 cp"

# Show a range of commands
python scripts/dump_blob.py commands.fcmpb --range commands:0:20
```

## Schema Format

Schemas use an indentation-based format (`.fcmps` extension). Leading tabs determine the command hierarchy.

### General Rules

- **Indentation determines hierarchy**: leading tabs set nesting depth
- Lines starting with `#` (outside of delimiters) are comments or descriptions
- Empty lines are ignored
- Fields are separated by spaces; `#` introduces the description
- Lines starting with `--` or `-` are parameter definitions
- The first depth-0 command is the root (CLI name and description)
- **No leading spaces allowed** — use tabs only for indentation

### Structure

```
<root-command> # description     ← First depth-0 line = CLI name
	--global-param @bool # description  (root params inherit to all subcommands)
	<subcommand> # description
		--param|-s @bool # description
		<sub-subcommand> # description
			--param (choice1|choice2) # description
```

### Parameters

Parameter lines are indented under their parent command:

```
<tabs><option-spec> [type-specifier] [# description]
```

**Option spec formats:**
- `--long|-s` — long option with short alias
- `--long` — long option only
- `-s` — short option only
- `--opt|-o|--alias` — multiple aliases (first short and first long are used)

**Type specifiers** (optional):
- `@bool` — boolean flag (doesn't take a value)
- `(val1|val2|val3)` — choices (pipe-separated, in parentheses)
- `{key1|key2}` — members for key=value completion
- `` `command` `` — dynamic completer (see below)
- No specifier — takes a value with no specific choices

**Description** (optional):
- `# description text` — everything after `#` (outside delimiters) is the description

### Parameter Inheritance

Parameters defined on a command group are automatically inherited by all descendant commands. For example, if `s3` has `--endpoint-url`, then `s3 cp`, `s3 ls`, and all other `s3` subcommands will also have `--endpoint-url` available.

When completing, parameters are listed in order of specificity:
1. The command's own parameters (most specific)
2. Parent command's parameters
3. Grandparent's parameters
4. ...continuing up to the root command's parameters (least specific)

This ensures the most relevant options appear first when completing deeply nested commands.

### Dynamic Completers

The `` `command` `` syntax enables dynamic completion by executing a command at completion time. The command is appended to the CLI name and executed, with each line of stdout becoming a completion option.

Example:
```
		--kubernetes-version `aks get-versions` # Version of Kubernetes
```

When the user requests completions for `--kubernetes-version`, fast-completer runs `az aks get-versions` and uses the output lines as completion values.

The completer command runs with a 2-second timeout. If the command takes longer or fails, no completions are shown for that parameter.

### Validation Rules

The generator enforces these rules:
- **Leading spaces forbidden**: Use tabs only (error on leading space)
- **Single root command**: Only one depth-0 command allowed
- **Incremental nesting**: Indentation can only increase by 1 level at a time
- **Decreasing depth allowed**: Can jump back any number of levels

### Editor Support

A [tree-sitter grammar](https://github.com/jlcrochet/tree-sitter-fcmps) is available for syntax highlighting in editors that support tree-sitter.

### Example

```
# AWS CLI schema for fast-completer
# Generated from awscli 2.x

aws # Amazon Web Services CLI
	--output (json|text|table) # The formatting style
	--debug @bool # Turn on debug logging
	--region # The region to use
	--profile # Use a specific profile
	s3 # Amazon S3 operations
		--endpoint-url # Override S3 endpoint URL
		cp # Copy objects between buckets
			--recursive|-r @bool # Recursive copy
			--storage-class (STANDARD|REDUCED_REDUNDANCY) # Storage class
			--acl (private|public-read) # Canned ACL to apply
		ls # List buckets or objects
			--human-readable|-h @bool # Display sizes in human readable format
	ec2 # Elastic Compute Cloud
		describe-instances # Describe EC2 instances
			--instance-ids # Instance IDs to describe
```

In this example:
- `--output`, `--debug`, `--region`, `--profile` are on the root `aws` command (available everywhere)
- `--endpoint-url` is on `s3` and inherited by `s3 cp`, `s3 ls`, etc.
- `--recursive`, `--storage-class`, `--acl` are specific to `s3 cp`
- When completing `aws s3 cp --`, options appear in order: `--recursive`, `--storage-class`, `--acl`, `--endpoint-url`, then globals

## Binary Blob Format

The blob format (`.fcmpb`) is designed for zero-copy memory-mapped access with minimal page faults. All integers are little-endian by default (use `--big-endian` for cross-compilation).

### Layout

| Section | Size | Description |
|---------|------|-------------|
| Header | 56 bytes | Magic (`FCMP`), version, flags, counts, section offsets |
| String table | variable | VLQ length-prefixed strings, hot data first (names, choices), cold data last (descriptions) |
| Commands | 20 bytes each | Fixed-size structs with name/description offsets, param/subcommand indices |
| Params | 20 bytes each | Fixed-size structs with name/short/description/choices offsets, flags |
| Choices | variable | Count-prefixed arrays of string table offsets (4-byte header, deduplicated) |
| Members | variable | Count-prefixed arrays of string table offsets (4-byte header, deduplicated) |
| Root command | 20 bytes | CLI root with global params and top-level subcommands |

### Design

- **Fixed-size structs** enable O(1) indexing by offset calculation
- **Hot/cold string separation** keeps names in cache while descriptions page in only when needed (81% of AWS CLI string data is cold)
- **Subtree clustering** writes command names in pre-order so related commands are contiguous in memory
- **Deduplication** for choices, members, and repeated strings

### Header Flags

| Flag | Description |
|------|-------------|
| `0x01` | Big-endian byte order |
| `0x02` | No descriptions (auto-detected or `--no-descriptions`) |

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
for blob in "$_fc_cache"/*.fcmpb; do
    [[ -f "$blob" ]] && complete -o nosort -F _fast_completer "$(basename "$blob" .fcmpb)"
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
for blob in "$_fc_cache"/*.fcmpb(N); do
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
for blob in $_fc_cache/*.fcmpb
    set -l cmd (basename $blob .fcmpb)
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
Get-ChildItem "$fcCache\*.fcmpb" -ErrorAction SilentlyContinue | ForEach-Object {
    Register-ArgumentCompleter -Native -CommandName $_.BaseName -ScriptBlock $fcCompleter
}
```

## Limitations

- Structure member completion only provides top-level keys (e.g., `ebs=`, `device-name=`); nested members are not yet supported

## TODO

- Add schemas for other large CLIs (e.g., `kubectl`)
- Check schemas for value types: if it's something like "path" or "directory", we may be able to provide completions for those

## How It Works

1. `src/generate_blob.c` - Converts a schema file to a binary blob file
2. `scripts/dump_blob.py` - Inspects and validates blob files (for debugging)
3. `src/fast-completer.c` - Native binary that memory-maps the blob and provides completions

The blob-based approach offers several advantages over compiled-in data:
- **Single binary**: One `fast-completer` binary works with any CLI tool
- **Easy updates**: Update completion data by replacing the blob file, no recompilation needed
- **Fast startup**: Memory-mapped I/O means near-zero initialization overhead
- **Cross-platform**: Works on Linux, macOS, and Windows
