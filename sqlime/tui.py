"""Interactive terminal TUI for SQLime — zero external dependencies.

Provides a simple keyboard-driven menu for browsing database pages,
inspecting headers, scanning for deleted rows, and running common
forensic tasks — all using pure Python ``input()`` / ``print()`` loops.

Usage from CLI::

    sqlime tui path/to/database.db

Or programmatically::

    from sqlime.tui import ForensicsTUI
    ForensicsTUI(\"path/to/database.db\").run()
"""

from __future__ import annotations

import os
import shutil
import struct
import sys
import textwrap
from typing import Any, Optional

from . import __version__
from .pages import (
    read_database_header,
    read_page,
    get_page_size,
    PageHeader,
    hex_dump,
    list_freelist_pages,
    parse_cell_pointers,
)
from .hexdump import HexViewer, dump_page
from .schema import schema_summary
from .check import run_quick_check, run_integrity_check
from .recovery import scan_database_for_deleted_rows, format_recovery_results
from .carve import carve_blobs


# ── ANSI helpers (minimal, no deps) ─────────────────────────────────────────


def _clear() -> None:
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def _b(s: str) -> str:
    """Return *s* wrapped in ANSI bold if the terminal supports it."""
    if not sys.stdout.isatty():
        return s
    return f"\033[1m{s}\033[0m"


def _dim(s: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"\033[2m{s}\033[0m"


def _green(s: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"\033[92m{s}\033[0m"


def _red(s: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"\033[91m{s}\033[0m"


def _yellow(s: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"\033[93m{s}\033[0m"


def _header(title: str) -> None:
    """Print a section header with horizontal rule."""
    cols, _ = shutil.get_terminal_size((80, 24))
    rule = "—" * (cols - len(title) - 4)
    print(f"\n  {_b(title)} {_dim(rule)}\n")


# ── helpers ──────────────────────────────────────────────────────────────────


def _verify_db(path: str) -> bool:
    """Return True if *path* is a valid SQLite database."""
    if not os.path.exists(path):
        print(f"  {_red('[!]')} File not found: {path}")
        return False
    try:
        hdr = read_database_header(path)
        return hdr.is_valid()
    except Exception:
        return False


def _prompt(label: str, default: str = "") -> str:
    """Prompt and return stripped input."""
    try:
        if default:
            val = input(f"  {label} [{_dim(default)}]: ").strip()
            return val if val else default
        return input(f"  {label}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def _pause() -> None:
    """Wait for Enter."""
    try:
        input(f"\n  {_dim('press Enter to continue')} ")
    except (EOFError, KeyboardInterrupt):
        pass


# ── menu items ───────────────────────────────────────────────────────────────


def _show_banner(db_path: str) -> None:
    _clear()
    cols, _ = shutil.get_terminal_size((80, 24))
    title = f" SQLime v{__version__} "
    bar = "=" * ((cols - len(title)) // 2)
    print(f"\n  {_b(bar + title + bar)}")
    print(f"  {_dim(os.path.abspath(db_path))}")
    try:
        hdr = read_database_header(db_path)
        print(
            f"  "
            f"{_green('valid') if hdr.is_valid() else _red('invalid header')}"
            f"  ·  {hdr.page_size} B/page  ·  "
            f"{hdr.db_size_pages} pages  ·  "
            f"{hdr.total_freelist_pages} free"
        )
    except Exception as e:
        print(f"  {_red(f'error: {e}')}")
    print()


def _show_menu(options: list[tuple[str, str]]) -> str:
    """Display a numbered menu and return the chosen key."""
    for idx, (key, desc) in enumerate(options, 1):
        print(f"  {_b(f'{idx:>2}.')} {key:<28} {_dim(desc)}")
    print()

    while True:
        try:
            raw = input(f"  {_b('choice')} [{_dim('1-' + str(len(options)) + ', q')}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return "q"
        if raw.lower() in ("q", "quit", "exit"):
            return "q"
        try:
            idx = int(raw)
            if 1 <= idx <= len(options):
                return options[idx - 1][0]
        except ValueError:
            pass
        print(f"  {_yellow('?')} enter a number 1–{len(options)} or q")


# ── menu actions ─────────────────────────────────────────────────────────────


def _action_overview(db_path: str) -> None:
    _clear()
    _header("Database Overview")
    try:
        hdr = read_database_header(db_path)
        print(f"  Page size:          {hdr.page_size} bytes")
        print(f"  Pages on disk:      {hdr.db_size_pages}")
        print(f"  File size:          {hdr.db_size_pages * hdr.page_size / 1024:.1f} KB")
        print(f"  Encoding:           {hdr.encoding_name()}")
        print(f"  Schema format:      {hdr.schema_format}")
        print(f"  Application ID:     0x{hdr.application_id:08X}")
        print(f"  Free pages:         {hdr.total_freelist_pages}")
        print(f"  Largest root page:  {hdr.largest_root_page}")
        print(f"  User version:       {hdr.user_version}")
        print(f"  Change counter:     {hdr.file_change_counter}")
        print(f"  Text encoding:      {hdr.text_encoding}")
        valid = hdr.is_valid()
        print(f"  Valid signature:    {_green('yes') if valid else _red('no')}")
    except Exception as e:
        print(f"  {_red(str(e))}")
    _pause()


def _action_browse_pages(db_path: str) -> None:
    _clear()
    _header("Browse Pages")
    try:
        viewer = HexViewer(db_path)
    except Exception as e:
        print(f"  {_red(str(e))}")
        _pause()
        return

    page = 1
    while True:
        _clear()
        print(f"  {_b('Page')} {page} {_dim(f'of {viewer.total_pages}')}\n")
        try:
            print(dump_page(db_path, page, viewer.page_size))
        except Exception as e:
            print(f"  Error: {e}")

        print()
        nav = _prompt("n(ext) p(rev) #(goto) q(uit)", "n")
        if nav == "q":
            break
        elif nav == "p" and page > 1:
            page -= 1
        elif nav == "n" and page < viewer.total_pages:
            page += 1
        elif nav.isdigit():
            p = int(nav)
            if 1 <= p <= viewer.total_pages:
                page = p


def _action_schema(db_path: str) -> None:
    _clear()
    _header("Schema")
    try:
        print(schema_summary(db_path))
    except Exception as e:
        print(f"  {_red(str(e))}")
    _pause()


def _action_integrity(db_path: str) -> None:
    _clear()
    _header("Integrity Check")
    print(f"  {_dim('Running quick check...')}")
    try:
        quick = run_quick_check(db_path)
        if quick.get("passed"):
            print(f"  {_green('[✓]')} Quick check passed")
        else:
            print(f"  {_red('[✗]')} Quick check: {quick.get('quick_check')}")
    except Exception as e:
        print(f"  {_red(str(e))}")

    print(f"\n  {_dim('Running full integrity check (may take a while)...')}")
    try:
        result = run_integrity_check(db_path)
        if isinstance(result, dict):
            ok = result.get("integrity_check", "")
            print(f"  {'  ' + _green('[✓]') if 'ok' in str(ok).lower() else _red('[✗]')} {ok}")
            if result.get("errors"):
                for err in result["errors"]:
                    print(f"    {_red(str(err))}")
        else:
            print(f"  {result}")
    except Exception as e:
        print(f"  {_red(str(e))}")
    _pause()


def _action_deleted_rows(db_path: str) -> None:
    _clear()
    _header("Deleted Row Recovery")
    print(f"  {_dim('Scanning for ghost records...')}")
    try:
        results = scan_database_for_deleted_rows(db_path)
        output = format_recovery_results(results)
        if output.strip():
            print(output)
        else:
            print(f"  {_yellow('No deleted rows found.')}")
    except Exception as e:
        print(f"  {_red(str(e))}")
    _pause()


def _action_freelist(db_path: str) -> None:
    _clear()
    _header("Free Pages")
    try:
        pages = list_freelist_pages(db_path)
        if pages:
            print(f"  Found {_b(str(len(pages)))} free page(s):")
            for chunk in _chunked(pages, 10):
                print(f"    {', '.join(str(p) for p in chunk)}")
        else:
            print(f"  {_yellow('No free pages.')}")
    except Exception as e:
        print(f"  {_red(str(e))}")
    _pause()


def _action_blob_carve(db_path: str) -> None:
    _clear()
    _header("BLOB Carving")
    out = _prompt("Output directory", "carved_output")
    if not out:
        return
    try:
        results = carve_blobs(db_path, out)
        if isinstance(results, list):
            print(f"  Extracted {len(results)} file(s) to {out}:")
            for r in results[:20]:
                fname = r.get("file", r.get("path", "?"))
                ftype = r.get("type", r.get("signature", "?"))
                print(f"    {_dim(ftype):12} {fname}")
            if len(results) > 20:
                print(f"    ... and {len(results) - 20} more")
        else:
            print(f"  {str(results)}")
    except Exception as e:
        print(f"  {_red(str(e))}")
    _pause()


def _action_export(db_path: str) -> None:
    """Simple export to JSON via the CLI equivalent."""
    _clear()
    _header("Export Database")
    from .export import export_database_json

    out = _prompt("Output prefix", "export_dump")
    try:
        results = export_database_json(db_path, out)
        if isinstance(results, list):
            for r in results:
                print(f"  Wrote {r.get('table', '?')} → {r.get('path', '?')} "
                      f"({r.get('row_count', 0)} rows)")
        else:
            print(f"  {str(results)}")
    except Exception as e:
        print(f"  {_red(str(e))}")
    _pause()


def _chunked(lst: list, n: int):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


# ── main TUI class ──────────────────────────────────────────────────────────


class ForensicsTUI:
    """Interactive terminal UI for SQLime forensic toolkit.

    Parameters
    ----------
    db_path:
        Path to a SQLite database file.
    """

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"Database not found: {self.db_path}")
        if not _verify_db(self.db_path):
            raise ValueError(f"Not a valid SQLite database: {self.db_path}")

        self._menu_items: list[tuple[str, str, str]] = [
            ("overview",     "Database Overview",     "Header info, encoding, sizes"),
            ("browse",       "Browse Pages",          "Hex-dump pages interactively"),
            ("schema",       "Schema",                "Tables, indices, views"),
            ("integrity",    "Integrity Check",        "Quick + full DB check"),
            ("deleted",      "Deleted Row Recovery",   "Scan for ghost records"),
            ("freelist",     "Free Pages",             "List unallocated pages"),
            ("carve",        "BLOB Carving",           "Extract embedded files"),
            ("export",       "Export to JSON",         "Dump all tables as JSON"),
        ]

    def run(self) -> None:
        """Start the interactive TUI loop."""
        while True:
            _show_banner(self.db_path)
            options = [(key, desc) for key, _, desc in self._menu_items]
            choice = _show_menu(options)

            if choice == "q":
                print(f"\n  {_green('bye!')}\n")
                break

            action_map = {
                "overview":  _action_overview,
                "browse":    _action_browse_pages,
                "schema":    _action_schema,
                "integrity": _action_integrity,
                "deleted":   _action_deleted_rows,
                "freelist":  _action_freelist,
                "carve":     _action_blob_carve,
                "export":    _action_export,
            }
            handler = action_map.get(choice)
            if handler:
                handler(self.db_path)


# ── CLI entry point ──────────────────────────────────────────────────────────


def run_tui(args: Optional[Any] = None) -> None:
    """Entry point for ``sqlime tui [database]`` subcommand.

    ``args`` can be a namespace with ``.database`` or a raw path string.
    """
    if args is None:
        args = sys.argv[1:]

    if isinstance(args, str):
        db_path = args
    elif hasattr(args, "database"):
        db_path = args.database
    elif isinstance(args, list):
        db_path = args[0] if args else ""
    else:
        db_path = getattr(args, "database", "")

    if not db_path:
        print("  Usage: sqlime tui <database.db>", file=sys.stderr)
        sys.exit(1)

    try:
        tui = ForensicsTUI(db_path)
        tui.run()
    except (FileNotFoundError, ValueError) as e:
        print(f"  {_red(str(e))}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n  {_green('bye!')}\n")
        sys.exit(0)


if __name__ == "__main__":
    run_tui()
