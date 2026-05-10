"""Hex dump viewer for SQLite database pages — print formatted hex + ASCII
dumps of individual pages, page ranges, or raw byte regions.

Provides both a CLI-friendly ``hexdump`` function and a ``HexViewer`` class
with filtering, annotation, and search capabilities.
"""

from __future__ import annotations

import math
import os
import struct
import sys
from typing import Iterator, Optional


# ── core formatting ──────────────────────────────────────────────────────────


def hexdump(
    data: bytes,
    *,
    offset: int = 0,
    width: int = 16,
    show_ascii: bool = True,
    show_offset: bool = True,
    group: int = 2,
    lowercase: bool = True,
) -> str:
    """Render *data* as a classic hex + ASCII dump.

    Parameters
    ----------
    data:
        Raw bytes to dump.
    offset:
        Base address printed in the left margin (logical start address).
    width:
        Bytes per line (default 16).
    show_ascii:
        Whether to append the ASCII sidebar.
    show_offset:
        Whether to show the offset column.
    group:
        How many bytes between spacing gaps in the hex column.
    lowercase:
        Use lowercase hex digits.

    Returns
    -------
    Multi-line string ready for printing.
    """
    fmt = f"{{:0{width // 2 + 1}x}}" if not lowercase else f"{{:0{width // 2 + 1}x}}"
    lines: list[str] = []

    # figure out address width
    if len(data) > 0xFFFFFFFF:
        addr_w = 16
    elif len(data) > 0xFFFF:
        addr_w = 8
    else:
        addr_w = 4

    digits = "0123456789abcdef" if lowercase else "0123456789ABCDEF"
    trans = _make_ascii_trans(digits)

    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        # hex part
        hex_parts: list[str] = []
        for g in range(0, len(chunk), group):
            group_bytes = chunk[g : g + group]
            hex_parts.append("".join(f"{b:02x}" if lowercase else f"{b:02X}" for b in group_bytes))
        hex_str = " ".join(hex_parts).ljust(width * 3 - 1)

        # ascii part
        if show_ascii:
            ascii_str = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in chunk
            )
        else:
            ascii_str = ""

        if show_offset:
            prefix = f"{offset + i:0{addr_w}x}"
            if show_ascii:
                lines.append(f"{prefix}  {hex_str}  |{ascii_str}|")
            else:
                lines.append(f"{prefix}  {hex_str}")
        else:
            if show_ascii:
                lines.append(f"{hex_str}  |{ascii_str}|")
            else:
                lines.append(hex_str)

    return "\n".join(lines)


def _make_ascii_trans(hex_digits: str) -> dict[int, str]:
    """Build translation map for printable-ASCII filtering."""
    trans = {}
    for b in range(256):
        if 32 <= b < 127:
            trans[b] = chr(b)
        else:
            trans[b] = "."
    return trans


# ── page-aware helpers ──────────────────────────────────────────────────────


def dump_page(
    db_path: str,
    page_num: int,
    page_size: Optional[int] = None,
    *,
    width: int = 16,
    group: int = 2,
    skip_empty: bool = True,
) -> str:
    """Read a single page from a SQLite database and return its hex dump.

    For page 1 the 100-byte database header is skipped so the dump shows
    the actual page content (aligned to the logical page start).
    """
    if page_size is None:
        page_size = _read_page_size(db_path)

    data = _read_page(db_path, page_num, page_size)

    if skip_empty and all(b == 0 for b in data):
        return f"[Page {page_num}: all zeros — {len(data)} bytes]"

    logical_offset = (page_num - 1) * page_size
    return hexdump(data, offset=logical_offset, width=width, group=group)


def dump_range(
    db_path: str,
    start: int,
    end: int,
    page_size: Optional[int] = None,
    *,
    width: int = 16,
    group: int = 2,
    skip_empty: bool = True,
) -> str:
    """Dump a range of pages (start to end, inclusive)."""
    if page_size is None:
        page_size = _read_page_size(db_path)

    parts: list[str] = []
    for p in range(start, end + 1):
        chunk = dump_page(
            db_path, p, page_size, width=width, group=group, skip_empty=skip_empty
        )
        parts.append(chunk)
        parts.append("")  # blank separator

    return "\n".join(parts)


# ── HexViewer (interactive-style browsing) ──────────────────────────────────


class HexViewer:
    """Browser over database pages that yields formatted dumps page-by-page.

    Intended for use inside the TUI or as a programmatic iterator::

        viewer = HexViewer(\"forensic.db\")
        for dump_str in viewer.head(5):
            print(dump_str)
    """

    def __init__(
        self,
        db_path: str,
        page_size: Optional[int] = None,
        *,
        width: int = 16,
        group: int = 2,
    ):
        self.db_path = db_path
        self.page_size = page_size or _read_page_size(db_path)
        self.width = width
        self.group = group

        with open(db_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            self.file_size = f.tell()

        self.total_pages = math.ceil(self.file_size / self.page_size)

    def page(self, num: int) -> str:
        """Return formatted dump for page *num* (1-indexed)."""
        return dump_page(
            self.db_path,
            num,
            self.page_size,
            width=self.width,
            group=self.group,
            skip_empty=False,
        )

    def head(self, count: int = 10) -> Iterator[str]:
        """Yield the first *count* pages."""
        for p in range(1, min(count, self.total_pages) + 1):
            yield f"── Page {p} of {self.total_pages} ──\n" + self.page(p)

    def tail(self, count: int = 10) -> Iterator[str]:
        """Yield the last *count* pages."""
        start = max(1, self.total_pages - count + 1)
        for p in range(start, self.total_pages + 1):
            yield f"── Page {p} of {self.total_pages} ──\n" + self.page(p)

    def search(self, needle: bytes) -> Iterator[tuple[int, str]]:
        """Search for *needle* bytes in every page.

        Yields ``(page_number, snippet)`` tuples.
        """
        for p in range(1, self.total_pages + 1):
            data = _read_page(self.db_path, p, self.page_size)
            pos = data.find(needle)
            if pos != -1:
                ctx = hexdump(
                    data[max(0, pos - 8) : pos + len(needle) + 8],
                    offset=(p - 1) * self.page_size + max(0, pos - 8),
                    width=16,
                )
                yield p, ctx

    def annotate(self, page_num: int, highlights: dict[int, str]) -> str:
        """Dump a page and annotate specific byte offsets with labels.

        *highlights* maps byte-offset-within-page → label string.
        """
        data = _read_page(self.db_path, page_num, self.page_size)
        lines: list[str] = []
        logical_base = (page_num - 1) * self.page_size

        for i in range(0, len(data), self.width):
            chunk = data[i : i + self.width]
            hex_str = " ".join(f"{b:02x}" for b in chunk).ljust(self.width * 3 - 1)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            addr = logical_base + i
            line = f"{addr:08x}  {hex_str}  |{ascii_str}|"

            # check for annotations in this line's range
            notes = []
            for off, label in highlights.items():
                if i <= off < i + self.width:
                    col = (off - i) * 3 + (off - i) // self.group + 10
                    notes.append(f"  {' ' * (col - 10)}^  {label}")
            if notes:
                lines.append(line)
                lines.extend(notes)
            else:
                lines.append(line)

        return "\n".join(lines)


# ── internal I/O helpers ────────────────────────────────────────────────────


def _read_page_size(db_path: str) -> int:
    with open(db_path, "rb") as f:
        header = f.read(18)
    if len(header) < 18:
        raise ValueError(f"File too small: {db_path}")
    ps = struct.unpack(">H", header[16:18])[0]
    return 65536 if ps == 1 else ps


def _read_page(db_path: str, page_num: int, page_size: int) -> bytes:
    with open(db_path, "rb") as f:
        if page_num == 1:
            # skip the 100-byte DB header
            f.seek(100)
            return f.read(page_size)
        else:
            f.seek((page_num - 1) * page_size)
            return f.read(page_size)


# ── CLI helper ───────────────────────────────────────────────────────────────


def print_hexdump(args):
    """CLI entry point for ``sqlime hexdump`` (registered in cli.py)."""
    db = args.database
    if args.page:
        print(dump_page(db, args.page, width=args.width, group=args.group))
    elif args.start:
        end = args.end or args.start
        print(dump_range(db, args.start, end, width=args.width, group=args.group))
    else:
        viewer = HexViewer(db, width=args.width, group=args.group)
        for dump in viewer.head(20 if args.lines is None else args.lines // 16 + 1):
            print(dump)


if __name__ == "__main__":
    # simple demo when run directly
    import argparse

    parser = argparse.ArgumentParser(description="Hex dump a SQLite DB")
    parser.add_argument("database")
    parser.add_argument("--page", type=int, help="Page number to dump")
    parser.add_argument("--start", type=int, help="Starting page")
    parser.add_argument("--end", type=int, help="Ending page")
    parser.add_argument("--width", type=int, default=16, help="Bytes per line")
    parser.add_argument("--group", type=int, default=2, help="Bytes per hex group")
    parser.add_argument("--lines", type=int, help="Approximate lines of output")
    args = parser.parse_args()
    print_hexdump(args)
