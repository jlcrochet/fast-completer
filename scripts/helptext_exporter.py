#!/usr/bin/env python3
"""
Shared help-text CLI exporter for fast-completer.

Parses --help output from CLIs to extract commands and flags, and writes
an .fcmps schema file. Supports multiple help-text formats via configurable
parsing strategies.

Formats supported:
  - clap (Rust): cargo, rustup, rg, fd, bat, eza, delta, zoxide, starship
  - git: git (similar to clap but with --[no-] and section headers)
  - pip: pip (similar to clap)
  - hashicorp: terraform, vault, consul, nomad, packer (single-dash flags)
  - npm: npm, pnpm (bracket-style options from `npm -l`)
"""

import re
import sys
from dataclasses import dataclass, field
from typing import Optional, Set, Tuple

import command_cache


@dataclass
class HelptextExportConfig:
    """Configuration for a help-text based CLI export."""
    cli_name: str
    root_description: str
    schema_comment: str

    # Path to the CLI binary (defaults to cli_name, i.e. found via PATH)
    cli_path: Optional[str] = None

    # How to discover subcommands
    # 'help_text': parse <cli> <help_flag> for Commands: section
    # 'help_all': run <cli> <help_all_args> (e.g. git help -a)
    # 'npm_l': run <cli> -l (npm-specific structured output)
    # 'none': no subcommands (flat CLI like rg, fd)
    subcommand_strategy: str = 'help_text'
    help_all_args: Tuple[str, ...] = ()

    # How to get help for a subcommand (string or tuple for multi-word flags)
    help_flag: str = '--help'

    # Flag parsing style
    # 'standard': -s, --long <VALUE>  description (clap, git, pip)
    # 'hashicorp': -flag  description / -flag=<value>  description
    # 'npm_bracket': [--flag] [--flag <value>] [-s|--long] from npm -l
    flag_style: str = 'standard'

    # Version
    version_args: Tuple[str, ...] = ('--version',)
    version_regex: Optional[str] = None

    # Filtering
    inherited_skip_flags: Set[str] = field(
        default_factory=lambda: {'--help', '-h', '--version', '-V'}
    )
    max_depth: int = 4
    timeout: int = 10

    @property
    def binary(self):
        """Return the actual binary path to invoke."""
        return self.cli_path or self.cli_name


def _help_args(help_flag):
    """Normalize help_flag to a list of arguments."""
    if isinstance(help_flag, (tuple, list)):
        return list(help_flag)
    return help_flag.split()


def run_command(*args, timeout=10):
    """Run a command and return (stdout, returncode)."""
    return command_cache.execute(*args, timeout=timeout, merge_stderr=True)


def get_cli_version(config):
    """Get CLI version string."""
    output, _ = run_command(config.binary, *config.version_args)
    regex = config.version_regex or r'v?([\d]+\.[\d]+\.[\d]+)'
    match = re.search(regex, output)
    return match.group(1) if match else 'unknown'


# --- Subcommand discovery strategies ---

def discover_subcommands_from_help(config, command_parts):
    """Parse <cli> [cmd...] --help for a Commands: section."""
    args = [config.binary] + list(command_parts) + _help_args(config.help_flag)
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return []

    subcommands = []
    in_commands = False
    non_command_sections = {
        'options',
        'usage',
        'arguments',
        'flags',
        'positional arguments',
        'optional arguments',
        'description',
        'examples',
        'remarks',
        'environment variables',
        'path-to-application',
        'runtime-options',
        'sdk-options',
        'additional arguments',
        'switches',
    }

    # Command entry regex: name[, alias]... followed by gap and description.
    # Captures all names (e.g. "build, b" or "i, install") then picks longest.
    # Also handles oclif "$ name" prefix format (e.g. "  $ deploy  Deploy site").
    # Some CLIs use helper commands prefixed with "+" (e.g. "+upload").
    cmd_name_re = r'\+?[\w][+\w.-]*'
    _CMD_RE = re.compile(
        rf'^\s{{2,}}\$?\s*({cmd_name_re}(?:,\s+{cmd_name_re})*)\s{{2,}}(.+)'
    )

    for line in output.split('\n'):
        stripped = line.strip()

        # Detect start of commands section
        if re.match(
            r'^(Commands|Subcommands|Available Commands|Available commands|Services):?\s*$',
            stripped,
            re.IGNORECASE,
        ) or re.match(
            r'^(Main |Other |Additional )?([Cc]ommands|[Ss]ervices):?\s*$',
            stripped,
            re.IGNORECASE,
        ):
            in_commands = True
            continue

        # Non-indented section header ending with ":" (category headers)
        if stripped and not stripped[0].isspace() and stripped.endswith(':') and not stripped.startswith('-'):
            if re.match(r'^[A-Z][\w\s\'"-]+:$', stripped, re.IGNORECASE):
                header = stripped[:-1].strip().lower()
                header = re.sub(r'\s+', ' ', header)

                # Explicit non-command sections always end command parsing.
                if header in non_command_sections:
                    in_commands = False
                    continue

                # Headers that mention commands restart/continue command parsing.
                if re.search(r'\b(commands?|services?)\b', header):
                    in_commands = True
                    continue

                # If already in a commands section, treat as an intra-section
                # category header. Otherwise ignore.
                if in_commands:
                    continue

        # Blank line — keep going (sections may be separated by blank lines)
        if in_commands and not stripped:
            continue

        if in_commands and stripped and not stripped.startswith('-'):
            m = _CMD_RE.match(line)
            if m:
                # Pick the longest name from comma-separated list
                names = [n.strip() for n in m.group(1).split(',')]
                name = max(names, key=len)
                # Skip placeholder entries like "..."
                if re.fullmatch(cmd_name_re, name):
                    subcommands.append({
                        'name': name,
                        'summary': m.group(2).strip()
                    })
            elif re.match(rf'^\s{{2,8}}({cmd_name_re})\s*$', line):
                # Command with no description (limit indent to avoid
                # picking up continuation lines from multi-line descriptions)
                name = line.strip()
                if re.fullmatch(cmd_name_re, name):
                    subcommands.append({'name': name, 'summary': ''})
            elif not re.match(r'^\s', line):
                # Non-indented line = end of commands section
                in_commands = False

    return subcommands


def discover_subcommands_git(config, command_parts):
    """Parse git help -a for the full command list."""
    if command_parts:
        # For git subcommands, fall back to help_text
        return discover_subcommands_from_help(config, command_parts)

    args = [config.binary] + list(config.help_all_args)
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return []

    subcommands = []
    in_commands = False

    for line in output.split('\n'):
        stripped = line.strip()

        # Skip headers like "Main Porcelain Commands"
        if re.match(r'^[A-Z][\w\s]+$', stripped):
            in_commands = True
            continue

        if in_commands and stripped:
            m = re.match(r'^\s+([\w][\w.-]*)\s{2,}(.+)', line)
            if m:
                subcommands.append({
                    'name': m.group(1),
                    'summary': m.group(2).strip()
                })

        if not stripped:
            if in_commands:
                continue  # Blank lines between sections

    return subcommands


def discover_subcommands_npm_l(config, command_parts):
    """Parse npm -l output for commands and their options."""
    if command_parts:
        return []  # npm doesn't have nested subcommands generally

    args = [config.binary, '-l']
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return []

    subcommands = []
    # npm -l format: "    command-name    description\n"
    # Each entry is followed by Usage:, Options:, etc.
    current_cmd = None
    for line in output.split('\n'):
        # Match top-level command entry: "    name          description"
        m = re.match(r'^    (\w[\w-]*)\s{2,}(.+)', line)
        if m and not line.startswith('        '):
            name = m.group(1)
            # Skip if it's a section header within a command block
            if name not in ('Usage', 'Options', 'Run', 'alias', 'aliases'):
                current_cmd = name
                subcommands.append({
                    'name': name,
                    'summary': m.group(2).strip()
                })

    return subcommands


def discover_subcommands(config, command_parts):
    """Dispatch to the appropriate subcommand discovery strategy."""
    if config.subcommand_strategy == 'help_text':
        return discover_subcommands_from_help(config, command_parts)
    elif config.subcommand_strategy == 'help_all':
        return discover_subcommands_git(config, command_parts)
    elif config.subcommand_strategy == 'npm_l':
        return discover_subcommands_npm_l(config, command_parts)
    elif config.subcommand_strategy == 'none':
        return []
    return []


# --- Flag parsing strategies ---

# Standard flag regex: matches clap, git, pip formats (single-line)
# "  -s, --long <VALUE>  description" or "      --long  description"
_STD_LONG_FLAG = r'--(?:\[no-\])?[\w][\w.-]*'
_STD_VALUE = r'(?:\[?=?\s*<?([^>\]\s]+)>?\]?)?'

_STD_FLAG_RE = re.compile(
    r'^\s+'
    r'(?:(-\w),\s+)?'            # optional short flag
    rf'({_STD_LONG_FLAG})'        # long flag
    rf'{_STD_VALUE}'              # optional value placeholder
    r'\s{2,}'                     # gap before description
)

# Multi-line variant: flag on its own line, description on the next
# "  -s, --long <VALUE>" or "      --long"
_STD_FLAG_MULTILINE_RE = re.compile(
    r'^\s{2,}'
    r'(?:(-\w),\s+)?'            # optional short flag
    rf'({_STD_LONG_FLAG})'        # long flag
    rf'{_STD_VALUE}'              # optional value placeholder
    r'\s*$'                       # end of line (no description)
)

# Alias-list variants used by some CLIs (notably dotnet):
# "  -d|--diagnostics  desc"
# "  -?, -h, --help  desc"
# "  -v, -verbosity <LEVEL>  desc"
# "  --add-source, --nuget-source  desc"
_STD_FLAG_ALIASES_RE = re.compile(
    r'^\s+'
    r'((?:--?[\w?][\w.-]*)(?:\s*(?:,|\|)\s*--?[\w?][\w.-]*)+)'
    r'(?:\s+<?([^>\s]+)>?)?'
    r'\s{2,}'
)

# Multi-line variant: alias list on one line, description on next line
_STD_FLAG_ALIASES_MULTILINE_RE = re.compile(
    r'^\s{2,}'
    r'((?:--?[\w?][\w.-]*)(?:\s*(?:,|\|)\s*--?[\w?][\w.-]*)+)'
    r'(?:\s+<?([^>\s]+)>?)?'
    r'\s*$'
)

# Nushell flag format: "  -s, --long <type>: description"
_NU_FLAG_RE = re.compile(
    r'^\s+'
    r'(?:(-\w),\s+)?'            # optional short flag
    r'(--[\w][\w.-]*)'           # long flag
    r'(?:\s+<([^>]+)>)?'         # optional <type>
    r':\s+'                       # colon separator
)

# systemd flag regex: "  -M --machine=CONTAINER  description" or "     --system  description"
# Space-separated short+long, =VALUE format
_SYSTEMD_FLAG_RE = re.compile(
    r'^\s*'
    r'(?:(-\w)\s+)?'             # optional short flag (space, no comma)
    r'(--[\w][\w.-]*)'           # long flag
    r'(?:\[?=([^\s\]]+)\]?)?'   # optional =VALUE placeholder
    r'\s+'                       # gap before description
)

# systemd short-only flag: "  -I  description"
_SYSTEMD_SHORT_RE = re.compile(
    r'^\s+'
    r'(-\w)'                     # short flag only (needs indent to avoid false positives)
    r'\s{2,}'                    # gap before description
)

# HashiCorp flag regex: single-dash flags
# "  -flag  description" or "  -flag=<value>  description"
_HASHI_FLAG_RE = re.compile(
    r'^\s+'
    r'(-[\w][\w.-]*)'            # flag (single dash)
    r'(?:=<?(\w+)>?)?'          # optional =value
    r'(?:\s+(\S+))?'            # optional type word
    r'\s{2,}'                   # gap before description
)

# npm bracket flag regex from "npm -l" output
# "[--flag]" "[--flag <value>]" "[-s|--flag]"
_NPM_FLAG_RE = re.compile(
    r'\[(?:(-\w)\|)?(--[\w][\w.-]*)(?:\s+<([^>]+)>)?\]'
)


def _normalize_flag_alias(flag):
    """Normalize a parsed flag token from help output.

    Some CLIs (notably clap-based) render repeatable flags as
    `--verbose...`. The trailing ellipsis is not part of the actual option
    token, so strip it before writing schemas. Git renders flags that can be
    negated as `--[no-]flag`; the positive spelling is the canonical option
    token for completion.
    """
    if flag and flag.startswith('--[no-]'):
        flag = '--' + flag[len('--[no-]'):]
    if flag and flag.endswith('...'):
        return flag[:-3]
    return flag


def _is_negatable_flag(flag):
    return bool(flag and flag.startswith('--[no-]'))


def _negative_flag_alias(flag):
    if not _is_negatable_flag(flag):
        return None
    return '--no-' + flag[len('--[no-]'):]


def _pick_primary_aliases(alias_spec):
    """Choose canonical short/long aliases from a comma/pipe list."""
    aliases = [
        _normalize_flag_alias(a.strip())
        for a in re.split(r'[|,]', alias_spec)
        if a.strip()
    ]

    short_candidates = []
    double_dash_longs = []
    single_dash_longs = []

    for alias in aliases:
        if not alias.startswith('-'):
            continue

        # Treat exactly one-character options ("-h", "-v", "-?") as short.
        if len(alias) == 2:
            short_candidates.append(alias)
            continue

        if alias.startswith('--'):
            double_dash_longs.append(alias)
        else:
            single_dash_longs.append(alias)

    short = None
    if short_candidates:
        # Prefer human-friendly short aliases over "-?" when both are present.
        preferred = [s for s in short_candidates if s != '-?']
        short = preferred[0] if preferred else short_candidates[0]

    # Prefer full double-dash names, picking the most descriptive alias.
    long = None
    if double_dash_longs:
        long = max(double_dash_longs, key=len)
    elif single_dash_longs:
        long = max(single_dash_longs, key=len)

    return short, long


def _append_standard_flag(flags, config, short, long, value_type, desc):
    """Append parsed standard-style flag(s), expanding Git --[no-] aliases."""
    raw_long = long
    short = _normalize_flag_alias(short)
    long = _normalize_flag_alias(long)

    if long in config.inherited_skip_flags:
        return
    if short and short in config.inherited_skip_flags:
        return

    flag = {'name': long, 'description': desc}
    if short:
        flag['short'] = short
    if value_type:
        flag['takes_value'] = True
        # Check for choices in description: [possible values: a, b, c]
        choices_m = re.search(r'\[possible values:\s*([^\]]+)\]', desc)
        if choices_m:
            flag['choices'] = [
                c.strip() for c in choices_m.group(1).split(',')
            ]
    else:
        flag['type'] = 'bool'

    flags.append(flag)

    negative = _negative_flag_alias(raw_long)
    if negative and negative not in config.inherited_skip_flags:
        flags.append({
            'name': negative,
            'description': f"opposite of {long}",
            'type': 'bool',
        })


def parse_flags_standard(config, command_parts):
    """Parse standard --help flag format (clap, git, pip).

    Handles three formats:
    - Single-line: "  -s, --long <VALUE>  description"
    - Multi-line:  "  -s, --long <VALUE>" (description on next line)
    - Nushell:     "  -s, --long <type>: description"
    """
    args = [config.binary] + list(command_parts) + _help_args(config.help_flag)
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return []

    flags = []
    lines = output.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]

        # Try single-line format first
        m = _STD_FLAG_RE.match(line)
        if m:
            short, long, value_type = m.group(1), m.group(2), m.group(3)
            desc_start = m.end()
            desc = line[desc_start:].strip() if desc_start < len(line) else ''
            i += 1
        else:
            # Try alias-list format: "-d|--diagnostics" or "-v, -verbosity"
            m = _STD_FLAG_ALIASES_RE.match(line)
            if m:
                short, long = _pick_primary_aliases(m.group(1))
                value_type = m.group(2)
                short = _normalize_flag_alias(short)
                long = _normalize_flag_alias(long)
                if not long and short:
                    long, short = short, None
                if not long:
                    i += 1
                    continue
                desc_start = m.end()
                desc = line[desc_start:].strip() if desc_start < len(line) else ''
                i += 1
            else:
                # Try Nushell format: "  -s, --long <type>: description"
                m = _NU_FLAG_RE.match(line)
                if m:
                    short, long = m.group(1), m.group(2)
                    value_type = m.group(3)
                    desc_start = m.end()
                    desc = line[desc_start:].strip() if desc_start < len(line) else ''
                    # Nushell types: "string", "int", "path" indicate value
                    if value_type and value_type not in ('', 'switch'):
                        value_type = value_type  # keep it to signal takes_value
                    elif value_type == 'switch':
                        value_type = None  # switch = bool
                    i += 1
                else:
                    # Try multi-line format: flag on this line, description on next
                    m = _STD_FLAG_MULTILINE_RE.match(line)
                    if m:
                        short, long, value_type = m.group(1), m.group(2), m.group(3)
                        # Grab description from next indented line(s)
                        desc = ''
                        if i + 1 < len(lines):
                            next_line = lines[i + 1]
                            next_stripped = next_line.strip()
                            # Description line is more deeply indented
                            if next_stripped and next_line.startswith('    '):
                                desc = next_stripped
                        i += 1
                    else:
                        # Try multi-line alias-list format
                        m = _STD_FLAG_ALIASES_MULTILINE_RE.match(line)
                        if m:
                            short, long = _pick_primary_aliases(m.group(1))
                            value_type = m.group(2)
                            short = _normalize_flag_alias(short)
                            long = _normalize_flag_alias(long)
                            if not long and short:
                                long, short = short, None
                            if not long:
                                i += 1
                                continue

                            desc = ''
                            if i + 1 < len(lines):
                                next_line = lines[i + 1]
                                next_stripped = next_line.strip()
                                if next_stripped and next_line.startswith('    '):
                                    desc = next_stripped
                            i += 1
                        else:
                            i += 1
                            continue

        _append_standard_flag(flags, config, short, long, value_type, desc)

    return flags


def parse_flags_hashicorp(config, command_parts):
    """Parse HashiCorp CLI --help flag format (single-dash flags)."""
    args = [config.binary] + list(command_parts) + _help_args(config.help_flag)
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return []

    flags = []
    for line in output.split('\n'):
        m = _HASHI_FLAG_RE.match(line)
        if not m:
            continue

        name = m.group(1)
        eq_value = m.group(2)
        type_word = m.group(3)

        if name in config.inherited_skip_flags:
            continue

        desc_start = m.end()
        desc = line[desc_start:].strip() if desc_start < len(line) else ''

        flag = {'name': name, 'description': desc}
        if eq_value or type_word:
            flag['takes_value'] = True
        else:
            flag['type'] = 'bool'

        flags.append(flag)

    return flags


def parse_flags_npm(config, command_parts):
    """Parse npm bracket-style options from npm -l output."""
    # Get the command-specific help
    if command_parts:
        args = [config.binary] + list(command_parts) + ['-h']
    else:
        args = [config.binary, '--help']
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return []

    flags = []
    seen = set()

    for m in _NPM_FLAG_RE.finditer(output):
        short = m.group(1)
        long = _normalize_flag_alias(m.group(2))
        value_type = m.group(3)

        if long in seen or long in config.inherited_skip_flags:
            continue
        seen.add(long)

        flag = {'name': long, 'description': ''}
        if short:
            flag['short'] = short
        if value_type:
            flag['takes_value'] = True
        else:
            flag['type'] = 'bool'

        flags.append(flag)

    return flags


def parse_flags_systemd(config, command_parts):
    """Parse systemd-style flags: -s --long=VALUE  description."""
    args = [config.binary] + list(command_parts) + _help_args(config.help_flag)
    output, _ = run_command(*args, timeout=config.timeout)
    if not output:
        return []

    flags = []
    for line in output.split('\n'):
        m = _SYSTEMD_FLAG_RE.match(line)
        if m:
            short = _normalize_flag_alias(m.group(1))
            long = _normalize_flag_alias(m.group(2))
            value_type = m.group(3)
        else:
            # Try short-only format: "  -I  description"
            m = _SYSTEMD_SHORT_RE.match(line)
            if not m:
                continue
            short = _normalize_flag_alias(m.group(1))
            long = None
            value_type = None

        name = long or short
        if name in config.inherited_skip_flags:
            continue
        if short and short in config.inherited_skip_flags:
            continue

        desc_start = m.end()
        desc = line[desc_start:].strip() if desc_start < len(line) else ''

        flag = {'name': name, 'description': desc}
        if short and long:
            flag['short'] = short
        if value_type:
            flag['takes_value'] = True
        else:
            flag['type'] = 'bool'

        flags.append(flag)

    return flags


def parse_flags(config, command_parts):
    """Dispatch to the appropriate flag parsing strategy."""
    if config.flag_style == 'standard':
        return parse_flags_standard(config, command_parts)
    elif config.flag_style == 'hashicorp':
        return parse_flags_hashicorp(config, command_parts)
    elif config.flag_style == 'npm_bracket':
        return parse_flags_npm(config, command_parts)
    elif config.flag_style == 'systemd':
        return parse_flags_systemd(config, command_parts)
    return []


# --- Tree building and schema output ---

def escape_field(s):
    """Escape a field for schema output."""
    if not s:
        return ''
    return s.replace('\t', ' ').replace('\n', ' ').replace('\r', '')


def write_param(p, indent, file):
    """Output single param line in schema format."""
    name = p.get('name', '')
    short = p.get('short')

    if not name.startswith('-'):
        return

    if short:
        opt_spec = f"{name}|{short}"
    else:
        opt_spec = name

    type_field = ''
    if p.get('type') == 'bool' and not p.get('takes_value'):
        type_field = '@bool'
    elif p.get('choices'):
        type_field = '(' + '|'.join(p['choices']) + ')'

    desc = escape_field(p.get('description', ''))
    tabs = '\t' * indent

    parts = [f"{tabs}{opt_spec}"]
    if type_field:
        parts.append(type_field)
    if desc:
        parts.append(f"# {desc}")
    print(' '.join(parts), file=file)


class CommandTree:
    """Tree structure for organizing commands by path."""

    def __init__(self, name='', description=''):
        self.name = name
        self.description = description
        self.parameters = []
        self.children = {}

    def add_command(self, path_parts, description='', parameters=None):
        if not path_parts:
            if description:
                self.description = description
            if parameters:
                self.parameters = parameters
            return

        first = path_parts[0]
        if first not in self.children:
            self.children[first] = CommandTree(first)
        self.children[first].add_command(path_parts[1:], description, parameters)

    def write(self, file, indent=1):
        tabs = '\t' * indent
        desc = escape_field(self.description)
        if desc:
            print(f"{tabs}{self.name} # {desc}", file=file)
        else:
            print(f"{tabs}{self.name}", file=file)

        for p in self.parameters:
            write_param(p, indent + 1, file)

        for name in sorted(self.children.keys()):
            self.children[name].write(file, indent + 1)


def walk_commands(
    config,
    command_parts=None,
    depth=0,
    seen=None,
    parent_subcommand_names=None,
):
    """Recursively discover commands and their flags."""
    if command_parts is None:
        command_parts = []
    if seen is None:
        seen = set()

    if depth > config.max_depth:
        return

    command_path = ' '.join(command_parts)
    if command_path in seen:
        return
    seen.add(command_path)

    subcommands = discover_subcommands(config, command_parts)
    subcommands = [
        sub for sub in subcommands
        if sub['name'] not in ('help', 'completion', 'completions')
    ]

    # Some CLIs print the parent command's full sibling list for leaf help
    # (e.g. `pnpm config delete -h`), which can create synthetic recursion.
    subcommand_names = tuple(sorted({sub['name'] for sub in subcommands}))
    if subcommand_names and command_parts and parent_subcommand_names:
        if (
            parent_subcommand_names == subcommand_names
            and command_parts[-1] in subcommand_names
        ):
            subcommands = []
            subcommand_names = ()

    if subcommands:
        # Group command — emit with flags
        if command_path:
            flags = parse_flags(config, command_parts)
            yield {
                'name': command_path,
                'description': '',
                'parameters': flags,
            }

        for sub in subcommands:
            yield from walk_commands(
                config,
                command_parts + [sub['name']],
                depth + 1,
                seen,
                subcommand_names,
            )
    else:
        # Leaf command
        if command_path:
            flags = parse_flags(config, command_parts)
            yield {
                'name': command_path,
                'description': '',
                'parameters': flags,
            }


def export_helptext_cli(config):
    """Main entry point: export a CLI's command tree to .fcmps on stdout."""
    if not command_cache.auto_setup(config.cli_name, config.binary):
        sys.exit(1)

    version = get_cli_version(config)

    print(
        f"Exporting {config.cli_name} {version} commands via help text...",
        file=sys.stderr,
    )

    # Get subcommands first for progress reporting
    top_level = discover_subcommands(config, [])
    if config.subcommand_strategy != 'none':
        print(f"Found {len(top_level)} top-level commands", file=sys.stderr)

    # Get global flags
    global_flags = parse_flags(config, [])

    # Walk all commands
    commands = sorted(walk_commands(config), key=lambda x: x['name'])
    print(f"Exported {len(commands)} commands", file=sys.stderr)

    # Propagate descriptions from discovery
    desc_map = {}
    for sub in top_level:
        desc_map[sub['name']] = sub['summary']

    # Write schema
    print(f"# {config.schema_comment}", file=sys.stdout)
    print(f"# Generated from {config.cli_name} {version}", file=sys.stdout)
    print("", file=sys.stdout)
    print(f"{config.cli_name} # {config.root_description}", file=sys.stdout)

    # Global flags
    for p in global_flags:
        write_param(p, 1, sys.stdout)

    # Build tree
    root = CommandTree()
    for cmd in commands:
        parts = cmd['name'].split()
        root.add_command(parts, cmd.get('description', ''), cmd.get('parameters', []))

    # Apply descriptions from top-level discovery
    for name, child in root.children.items():
        if name in desc_map and not child.description:
            child.description = desc_map[name]

    for name in sorted(root.children.keys()):
        root.children[name].write(sys.stdout, indent=1)

    command_cache.save()
