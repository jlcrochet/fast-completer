#!/usr/bin/env python3
"""
Dump fast-completer binary blob to human-readable format for validation.

Usage:
    python dump_blob.py commands.fcmpb
    python dump_blob.py commands.fcmpb --section header
    python dump_blob.py commands.fcmpb --section tree
    python dump_blob.py commands.fcmpb --command 100
    python dump_blob.py commands.fcmpb --command "s3 cp"
    python dump_blob.py commands.fcmpb --param 500
    python dump_blob.py commands.fcmpb --string 1234
    python dump_blob.py commands.fcmpb --choices 8823963
    python dump_blob.py commands.fcmpb --find "bucket"
    python dump_blob.py commands.fcmpb --range commands:0:20
    python dump_blob.py commands.fcmpb --format json
"""

import argparse
import json
import re
import struct
import sys
from pathlib import Path

# Binary format constants (must match generate_blob.c)
MAGIC = b'FCMP'
VERSION = 9
HEADER_SIZE = 56
PARAM_SIZE = 17
COMMAND_SIZE = 18

# Param flags
FLAG_TAKES_VALUE  = 0x01
FLAG_IS_MEMBERS   = 0x02
FLAG_IS_COMPLETER = 0x04

# Header flags
HEADER_FLAG_BIG_ENDIAN = 0x01
HEADER_FLAG_NO_DESCRIPTIONS = 0x02


class BlobReader:
    """Reads and parses fast-completer binary blobs."""

    def __init__(self, data):
        self.data = data
        self.header = None
        self._parse_header()

    def _parse_header(self):
        """Parse the blob header."""
        if len(self.data) < HEADER_SIZE:
            raise ValueError(f"Blob too small: {len(self.data)} bytes (need at least {HEADER_SIZE})")

        values = struct.unpack_from('<4sHHIIIIIIIIIIII', self.data, 0)

        magic = values[0]
        if magic != MAGIC:
            raise ValueError(f"Invalid magic: {magic!r} (expected {MAGIC!r})")

        version = values[1]
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version} (expected {VERSION})")

        self.header = {
            'magic': magic.decode('ascii'),
            'version': version,
            'flags': values[2],
            'max_command_path_len': values[3],
            'command_count': values[4],
            'param_count': values[5],
            'string_table_size': values[6],
            'choices_count': values[7],
            'members_count': values[8],
            'string_table_off': values[9],
            'commands_off': values[10],
            'params_off': values[11],
            'choices_off': values[12],
            'members_off': values[13],
            'root_command_off': values[14],
        }

    def get_string(self, offset):
        """Decode a VLQ length-prefixed string from the string table."""
        if offset == 0:
            return ""

        str_table_start = self.header['string_table_off']
        pos = str_table_start + offset

        if pos >= len(self.data):
            return f"<invalid offset {offset}>"

        first_byte = self.data[pos]
        if first_byte < 128:
            length = first_byte
            start = pos + 1
        else:
            if pos + 1 >= len(self.data):
                return f"<invalid offset {offset}>"
            length = ((first_byte & 0x7f) << 8) | self.data[pos + 1]
            start = pos + 2

        if start + length > len(self.data):
            return f"<truncated string at {offset}>"

        return self.data[start:start + length].decode('utf-8', errors='replace')

    def get_string_raw(self, offset):
        """Get string with metadata (offset, length, encoding bytes)."""
        if offset == 0:
            return {'offset': 0, 'length': 0, 'encoding_bytes': 1, 'value': ''}

        str_table_start = self.header['string_table_off']
        pos = str_table_start + offset

        if pos >= len(self.data):
            return None

        first_byte = self.data[pos]
        if first_byte < 128:
            length = first_byte
            encoding_bytes = 1
        else:
            if pos + 1 >= len(self.data):
                return None
            length = ((first_byte & 0x7f) << 8) | self.data[pos + 1]
            encoding_bytes = 2

        start = pos + encoding_bytes
        if start + length > len(self.data):
            return None

        value = self.data[start:start + length].decode('utf-8', errors='replace')
        return {
            'offset': offset,
            'length': length,
            'encoding_bytes': encoding_bytes,
            'value': value,
            'raw_bytes': self.data[pos:start + length].hex()
        }

    def read_command(self, offset):
        """Read a Command struct at the given offset."""
        values = struct.unpack_from('<IIIHHH', self.data, offset)
        return {
            'name_off': values[0],
            'desc_off': values[1],
            'params_idx': values[2],
            'subcommands_idx': values[3],
            'params_count': values[4],
            'subcommands_count': values[5],
        }

    def read_param(self, offset):
        """Read a Param struct at the given offset."""
        values = struct.unpack_from('<IIIIB', self.data, offset)
        return {
            'name_off': values[0],
            'short_off': values[1],
            'desc_off': values[2],
            'choices_off': values[3],
            'flags': values[4],
        }

    def read_string_offsets(self, offset):
        """Read a variable-length count-prefixed array of string offsets.

        Format: u8 count if <255, else 0xFF + u16 count, then count * u32 offsets.
        """
        if offset >= len(self.data):
            return []
        first = self.data[offset]
        if first < 255:
            count = first
            pos = offset + 1
        else:
            if offset + 3 > len(self.data):
                return []
            count = struct.unpack_from('<H', self.data, offset + 1)[0]
            pos = offset + 3
        offsets = []
        for _ in range(count):
            if pos + 4 > len(self.data):
                break
            val = struct.unpack_from('<I', self.data, pos)[0]
            offsets.append(val)
            pos += 4
        return offsets

    def get_command_by_index(self, idx):
        """Get a single command by index."""
        if idx < 0 or idx >= self.header['command_count']:
            return None
        offset = self.header['commands_off'] + idx * COMMAND_SIZE
        cmd = self.read_command(offset)
        cmd['index'] = idx
        cmd['offset'] = offset
        cmd['name'] = self.get_string(cmd['name_off'])
        cmd['description'] = self.get_string(cmd['desc_off'])
        return cmd

    def get_param_by_index(self, idx):
        """Get a single param by index."""
        if idx < 0 or idx >= self.header['param_count']:
            return None
        offset = self.header['params_off'] + idx * PARAM_SIZE
        param = self.read_param(offset)
        param['index'] = idx
        param['offset'] = offset
        param['name'] = self.get_string(param['name_off'])
        param['short'] = self.get_string(param['short_off']) if param['short_off'] else None
        param['description'] = self.get_string(param['desc_off'])
        param['takes_value'] = bool(param['flags'] & FLAG_TAKES_VALUE)
        param['is_members'] = bool(param['flags'] & FLAG_IS_MEMBERS)
        param['is_completer'] = bool(param['flags'] & FLAG_IS_COMPLETER)
        if param['choices_off'] != 0:
            if param['is_completer']:
                # choices_off is a string table offset for completer
                param['completer'] = self.get_string(param['choices_off'])
                param['choices_or_members'] = None
            else:
                str_offsets = self.read_string_offsets(param['choices_off'])
                param['choices_or_members'] = [self.get_string(off) for off in str_offsets]
                param['choices_or_members_offsets'] = str_offsets
                param['completer'] = None
        else:
            param['choices_or_members'] = None
            param['completer'] = None
        return param

    def get_commands(self, start=0, end=None):
        """Get commands as a list of dicts."""
        if end is None:
            end = self.header['command_count']
        commands = []
        for i in range(start, min(end, self.header['command_count'])):
            commands.append(self.get_command_by_index(i))
        return commands

    def get_params(self, start=0, end=None):
        """Get params as a list of dicts."""
        if end is None:
            end = self.header['param_count']
        params = []
        for i in range(start, min(end, self.header['param_count'])):
            params.append(self.get_param_by_index(i))
        return params

    def get_root_command(self):
        """Get the root command."""
        cmd = self.read_command(self.header['root_command_off'])
        cmd['offset'] = self.header['root_command_off']
        cmd['name'] = self.get_string(cmd['name_off'])
        cmd['description'] = self.get_string(cmd['desc_off'])
        return cmd

    def find_command_by_path(self, path):
        """Find a command by its path (e.g., 's3 cp')."""
        parts = path.split()
        root = self.get_root_command()
        current_idx = root['subcommands_idx']
        current_count = root['subcommands_count']

        for part in parts:
            if current_count == 0:
                return None
            found = False
            offset = self.header['commands_off'] + current_idx * COMMAND_SIZE
            for _ in range(current_count):
                cmd = self.read_command(offset)
                name = self.get_string(cmd['name_off'])
                if name == part:
                    # Return the command info for the last part
                    if part == parts[-1]:
                        cmd['name'] = name
                        cmd['description'] = self.get_string(cmd['desc_off'])
                        cmd['offset'] = offset
                        cmd['index'] = (offset - self.header['commands_off']) // COMMAND_SIZE
                        return cmd
                    current_idx = cmd['subcommands_idx']
                    current_count = cmd['subcommands_count']
                    found = True
                    break
                offset += COMMAND_SIZE
            if not found and part != parts[-1]:
                return None
        return None

    def find_commands_matching(self, pattern):
        """Find commands with names matching a pattern."""
        regex = re.compile(pattern, re.IGNORECASE)
        matches = []
        for i in range(self.header['command_count']):
            cmd = self.get_command_by_index(i)
            if cmd and regex.search(cmd['name']):
                matches.append(cmd)
        return matches

    def find_params_matching(self, pattern):
        """Find params with names matching a pattern."""
        regex = re.compile(pattern, re.IGNORECASE)
        matches = []
        for i in range(self.header['param_count']):
            param = self.get_param_by_index(i)
            if param and regex.search(param['name']):
                matches.append(param)
        return matches

    def dump_command_tree(self, cmd_idx, count, indent=0, max_depth=None):
        """Recursively dump command tree."""
        if count == 0:
            return []
        if max_depth is not None and indent >= max_depth:
            return ["  " * indent + "..."]

        lines = []
        offset = self.header['commands_off'] + cmd_idx * COMMAND_SIZE

        for _ in range(count):
            cmd = self.read_command(offset)
            name = self.get_string(cmd['name_off'])
            desc = self.get_string(cmd['desc_off'])
            prefix = "  " * indent
            idx = (offset - self.header['commands_off']) // COMMAND_SIZE

            lines.append(f"{prefix}{name} [idx={idx}]")
            if desc:
                lines.append(f"{prefix}  # {desc[:60]}{'...' if len(desc) > 60 else ''}")

            # Dump params
            if cmd['params_count'] > 0:
                param_offset = self.header['params_off'] + cmd['params_idx'] * PARAM_SIZE
                for _ in range(cmd['params_count']):
                    param = self.read_param(param_offset)
                    pname = self.get_string(param['name_off'])
                    pidx = (param_offset - self.header['params_off']) // PARAM_SIZE
                    flags = []
                    if param['flags'] & FLAG_TAKES_VALUE:
                        flags.append("takes_value")
                    if param['choices_off'] != 0:
                        if param['flags'] & FLAG_IS_COMPLETER:
                            completer = self.get_string(param['choices_off'])
                            flags.append(f"completer={completer!r}")
                        else:
                            str_offsets = self.read_string_offsets(param['choices_off'])
                            if param['flags'] & FLAG_IS_MEMBERS:
                                flags.append(f"members({len(str_offsets)})")
                            else:
                                flags.append(f"choices({len(str_offsets)})")
                    flag_str = f" [{', '.join(flags)}]" if flags else ""
                    lines.append(f"{prefix}  {pname}{flag_str} [idx={pidx}]")
                    param_offset += PARAM_SIZE

            # Recurse into subcommands
            if cmd['subcommands_count'] > 0:
                lines.extend(self.dump_command_tree(cmd['subcommands_idx'], cmd['subcommands_count'], indent + 1, max_depth))

            offset += COMMAND_SIZE

        return lines


def format_command(cmd, verbose=False):
    """Format a command for display."""
    lines = []
    lines.append(f"Command [index={cmd['index']}] at offset {cmd.get('offset', '?')}")
    lines.append(f"  name_off:        {cmd['name_off']} -> {cmd['name']!r}")
    lines.append(f"  desc_off:        {cmd['desc_off']}")
    if verbose and cmd['description']:
        lines.append(f"                   {cmd['description']!r}")
    lines.append(f"  params_idx:      {cmd['params_idx']} (count: {cmd['params_count']})")
    lines.append(f"  subcommands_idx: {cmd['subcommands_idx']} (count: {cmd['subcommands_count']})")
    return '\n'.join(lines)


def format_param(param, verbose=False):
    """Format a param for display."""
    lines = []
    lines.append(f"Param [index={param['index']}] at offset {param.get('offset', '?')}")
    lines.append(f"  name_off:    {param['name_off']} -> {param['name']!r}")
    short_str = f" -> {param['short']!r}" if param.get('short') else ""
    lines.append(f"  short_off:   {param['short_off']}{short_str}")
    lines.append(f"  desc_off:    {param['desc_off']}")
    if verbose and param['description']:
        lines.append(f"               {param['description']!r}")
    lines.append(f"  choices_off: {param['choices_off']}")
    is_completer = param.get('is_completer', False)
    lines.append(f"  flags:       0x{param['flags']:02x} (takes_value={param['takes_value']}, is_members={param['is_members']}, is_completer={is_completer})")
    if param.get('completer'):
        lines.append(f"  completer: {param['completer']!r}")
    elif param['choices_or_members']:
        kind = "members" if param['is_members'] else "choices"
        lines.append(f"  {kind}: {param['choices_or_members']}")
        if 'choices_or_members_offsets' in param:
            lines.append(f"  {kind}_offsets: {param['choices_or_members_offsets']}")
    return '\n'.join(lines)


def dump_text(reader, section=None):
    """Dump blob in human-readable text format."""
    lines = []

    if section is None or section == 'header':
        lines.append("=== HEADER ===")
        for key, value in reader.header.items():
            if key == 'flags':
                flag_names = []
                if value & HEADER_FLAG_BIG_ENDIAN:
                    flag_names.append('big_endian')
                if value & HEADER_FLAG_NO_DESCRIPTIONS:
                    flag_names.append('no_descriptions')
                flag_str = ', '.join(flag_names) if flag_names else 'none'
                lines.append(f"  {key}: {value} ({flag_str})")
            else:
                lines.append(f"  {key}: {value}")
        lines.append("")

    if section is None or section == 'root':
        lines.append("=== ROOT COMMAND ===")
        root = reader.get_root_command()
        lines.append(f"  description: {root['description']}")
        lines.append(f"  params_idx: {root['params_idx']}")
        lines.append(f"  subcommands_idx: {root['subcommands_idx']}")
        lines.append("")

    if section is None or section == 'tree':
        lines.append("=== COMMAND TREE ===")
        root = reader.get_root_command()
        tree_lines = reader.dump_command_tree(root['subcommands_idx'], root['subcommands_count'])
        lines.extend(tree_lines)
        lines.append("")

    if section == 'commands':
        lines.append("=== ALL COMMANDS ===")
        for cmd in reader.get_commands():
            lines.append(f"[{cmd['index']:5d}] name_off={cmd['name_off']:6d} desc_off={cmd['desc_off']:6d} "
                         f"params={cmd['params_idx']:5d} subcmds={cmd['subcommands_idx']:5d} "
                         f"| {cmd['name']!r}")
        lines.append("")

    if section == 'params':
        lines.append("=== ALL PARAMS ===")
        for param in reader.get_params():
            flags = []
            if param['takes_value']:
                flags.append('V')
            if param['is_members']:
                flags.append('M')
            if param.get('is_completer'):
                flags.append('C')
            flag_str = ''.join(flags) if flags else '-'
            extra_str = ""
            if param.get('completer'):
                extra_str = f" -> completer={param['completer']!r}"
            elif param['choices_or_members']:
                extra_str = f" -> {param['choices_or_members'][:3]}{'...' if len(param['choices_or_members']) > 3 else ''}"
            lines.append(f"[{param['index']:5d}] {flag_str:3s} choices_off={param['choices_off']:6d} "
                         f"| {param['name']!r}{extra_str}")
        lines.append("")

    return '\n'.join(lines)


def dump_json(reader):
    """Dump blob in JSON format."""
    return json.dumps({
        'header': reader.header,
        'root': reader.get_root_command(),
        'commands': reader.get_commands(),
        'params': reader.get_params(),
    }, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description='Dump fast-completer binary blob',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s blob.fcmpb                      # Dump all sections
  %(prog)s blob.fcmpb -s header            # Dump only header
  %(prog)s blob.fcmpb -s tree              # Dump command tree
  %(prog)s blob.fcmpb --command 100        # Dump command at index 100
  %(prog)s blob.fcmpb --command "s3 cp"    # Dump command by path
  %(prog)s blob.fcmpb --param 500          # Dump param at index 500
  %(prog)s blob.fcmpb --string 1234        # Dump string at offset 1234
  %(prog)s blob.fcmpb --choices 8823963    # Dump choices at offset
  %(prog)s blob.fcmpb --find bucket        # Find commands/params matching "bucket"
  %(prog)s blob.fcmpb --range commands:0:20  # Dump commands 0-19
  %(prog)s blob.fcmpb --range params:100:110 # Dump params 100-109
        """
    )
    parser.add_argument('blob_file', type=Path, help='Binary blob file to dump')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--section', '-s',
                        choices=['header', 'root', 'tree', 'commands', 'params'],
                        help='Only dump specific section')
    parser.add_argument('--command', '-c', metavar='INDEX_OR_PATH',
                        help='Dump a specific command by index (number) or path (e.g., "s3 cp")')
    parser.add_argument('--param', '-p', metavar='INDEX', type=int,
                        help='Dump a specific param by index')
    parser.add_argument('--string', metavar='OFFSET', type=int,
                        help='Dump a string at a specific offset in the string table')
    parser.add_argument('--choices', metavar='OFFSET', type=int,
                        help='Dump choices/members at a specific blob offset')
    parser.add_argument('--find', metavar='PATTERN',
                        help='Find commands and params matching regex pattern')
    parser.add_argument('--range', metavar='TYPE:START:END',
                        help='Dump a range (e.g., commands:0:20 or params:100:200)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show more details')

    args = parser.parse_args()

    with open(args.blob_file, 'rb') as f:
        data = f.read()

    reader = BlobReader(data)

    # Handle specific queries
    if args.command is not None:
        try:
            idx = int(args.command)
            cmd = reader.get_command_by_index(idx)
        except ValueError:
            cmd = reader.find_command_by_path(args.command)

        if cmd:
            print(format_command(cmd, args.verbose))
            # Also show params if present
            if cmd['params_count'] > 0:
                print("\nParams:")
                for j in range(cmd['params_count']):
                    i = cmd['params_idx'] + j
                    param = reader.get_param_by_index(i)
                    if param is None:
                        break
                    print(f"  [{i}] {param['name']}", end='')
                    if param['takes_value']:
                        print(" [takes_value]", end='')
                    if param.get('completer'):
                        print(f" [completer={param['completer']!r}]", end='')
                    elif param['choices_or_members']:
                        kind = 'members' if param['is_members'] else 'choices'
                        print(f" [{kind}={param['choices_or_members']}]", end='')
                    print()
            # Show subcommands if present
            if cmd['subcommands_count'] > 0:
                print("\nSubcommands:")
                for j in range(cmd['subcommands_count']):
                    i = cmd['subcommands_idx'] + j
                    subcmd = reader.get_command_by_index(i)
                    if subcmd is None:
                        break
                    print(f"  [{i}] {subcmd['name']}")
        else:
            print(f"Command not found: {args.command}", file=sys.stderr)
            sys.exit(1)
        return

    if args.param is not None:
        param = reader.get_param_by_index(args.param)
        if param:
            print(format_param(param, args.verbose))
        else:
            print(f"Param not found: {args.param}", file=sys.stderr)
            sys.exit(1)
        return

    if args.string is not None:
        result = reader.get_string_raw(args.string)
        if result:
            print(f"String at offset {args.string}:")
            print(f"  length: {result['length']}")
            print(f"  encoding_bytes: {result['encoding_bytes']}")
            print(f"  value: {result['value']!r}")
            if args.verbose:
                print(f"  raw_bytes: {result['raw_bytes']}")
        else:
            print(f"Invalid string offset: {args.string}", file=sys.stderr)
            sys.exit(1)
        return

    if args.choices is not None:
        offsets = reader.read_string_offsets(args.choices)
        if offsets:
            print(f"Choices/Members at offset {args.choices}:")
            print(f"  count: {len(offsets)}")
            print(f"  offsets: {offsets}")
            print(f"  values: {[reader.get_string(off) for off in offsets]}")
        else:
            print(f"No choices at offset {args.choices}", file=sys.stderr)
            sys.exit(1)
        return

    if args.find is not None:
        commands = reader.find_commands_matching(args.find)
        params = reader.find_params_matching(args.find)

        if commands:
            print(f"=== MATCHING COMMANDS ({len(commands)}) ===")
            for cmd in commands[:50]:  # Limit output
                print(f"  [{cmd['index']:5d}] {cmd['name']!r}")
            if len(commands) > 50:
                print(f"  ... and {len(commands) - 50} more")
            print()

        if params:
            print(f"=== MATCHING PARAMS ({len(params)}) ===")
            for param in params[:50]:
                print(f"  [{param['index']:5d}] {param['name']!r}")
            if len(params) > 50:
                print(f"  ... and {len(params) - 50} more")
            print()

        if not commands and not params:
            print(f"No matches for: {args.find}", file=sys.stderr)
            sys.exit(1)
        return

    if args.range is not None:
        parts = args.range.split(':')
        if len(parts) != 3:
            print("Invalid range format. Use TYPE:START:END", file=sys.stderr)
            sys.exit(1)
        range_type, start, end = parts[0], int(parts[1]), int(parts[2])

        if range_type == 'commands':
            print(f"=== COMMANDS {start}:{end} ===")
            for cmd in reader.get_commands(start, end):
                print(f"[{cmd['index']:5d}] name_off={cmd['name_off']:6d} desc_off={cmd['desc_off']:6d} "
                      f"params={cmd['params_idx']:5d} subcmds={cmd['subcommands_idx']:5d} "
                      f"| {cmd['name']!r}")
        elif range_type == 'params':
            print(f"=== PARAMS {start}:{end} ===")
            for param in reader.get_params(start, end):
                flags = 'V' if param['takes_value'] else '-'
                if param['is_members']:
                    flags += 'M'
                if param.get('is_completer'):
                    flags += 'C'
                extra = ""
                if param.get('completer'):
                    extra = f" -> completer={param['completer']!r}"
                print(f"[{param['index']:5d}] {flags:3s} choices_off={param['choices_off']:6d} "
                      f"| {param['name']!r}{extra}")
        else:
            print(f"Unknown range type: {range_type}", file=sys.stderr)
            sys.exit(1)
        return

    # Default: dump sections
    if args.format == 'json':
        print(dump_json(reader))
    else:
        print(dump_text(reader, args.section))


if __name__ == '__main__':
    main()
