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

### flutter
- **Impact**: Large mobile dev framework
- **Format**: Dart-based, standard `--help` format
- **Strategy**: Probably `helptext` + `flag_style='standard'`
- **Notes**: Has many subcommands (build, run, test, doctor, etc.)
