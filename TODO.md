# TODO: Helptext-based CLI Schemas

CLIs that need the `helptext_exporter.py` module (parsing `--help` output).
Listed roughly by implementation difficulty — easiest first.

## Completed

- [x] **curl** — 268 flags, `help_flag='-h all'`, `subcommand_strategy='none'`
- [x] **journalctl** — 62 flags, `flag_style='systemd'`, `subcommand_strategy='none'`
- [x] **systemctl** — 51 flags, `flag_style='systemd'`, flat (commands not subcommands)
- [x] **dotnet** — 245 commands, standard helptext parser
- [x] **wget** — 145 flags, standard helptext
- [x] **gpg** — 63 flags, standard helptext
- [x] **ss** — 41 flags, standard helptext
- [x] **tar** — 138 flags, standard helptext
- [x] **zstd** — 37 flags, standard helptext
- [x] **xz** — 12 flags, standard helptext
- [x] **strace** — 33 flags, standard helptext
- [x] **htop** — 13 flags, `flag_style='systemd'`
- [x] **deno** — 465 lines, 26 commands, clap framework with `help_flag='-h'`
- [x] **bun** — 731 lines, 65 commands, helptext framework
- [x] **poetry** — 188 lines, 47 commands, custom exporter (Symfony Console)
- [x] **conda** — 515 lines, 52 commands, custom exporter (argparse with nested subparsers)

## Skipped

- **cmake** — Too custom a format (`=` separator, `-W` prefix flags, multi-line continuations)

## Needs research (not installed locally)

### ansible / ansible-playbook
- **Impact**: Very widely used config management
- **Format**: Python argparse
- **Strategy**: `subcommand_strategy='none'` (flat), `flag_style='standard'`
- **Notes**: `ansible` itself is flat (no subcommands). The many "modules" are
  not subcommands. `ansible-playbook`, `ansible-galaxy`, `ansible-vault` are
  separate binaries that could each get a schema.

### brew
- **Impact**: Essential macOS package manager
- **Format**: Custom Ruby-based help
- **Strategy**: Needs format investigation (likely `helptext` with tweaks)
- **Notes**: `brew commands` lists all commands. Each has `brew <cmd> --help`.
  macOS-only, can't test on this machine.

### flutter
- **Impact**: Large mobile dev framework
- **Format**: Dart-based, standard `--help` format
- **Strategy**: Probably `helptext` + `flag_style='standard'`
- **Notes**: Has many subcommands (build, run, test, doctor, etc.)

### nix
- **Impact**: Growing package manager, large subcommand tree
- **Format**: Custom C++
- **Strategy**: Needs format investigation
- **Notes**: `nix` (new CLI) vs `nix-env`/`nix-build` (legacy). The new CLI
  has a large subcommand tree.
