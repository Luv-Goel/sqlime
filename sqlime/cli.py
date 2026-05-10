"""SQLime CLI entry point."""

import argparse
import sys
import os

from . import __version__
from .pages import (
    read_page, get_page_size, read_database_header,
    PageHeader, hex_dump, list_freelist_pages,
)
from .wal import wal_summary, recover_deleted_rows_from_wal
from .recovery import scan_database_for_deleted_rows, format_recovery_results
from .schema import schema_summary, generate_dot
from .check import (
    run_integrity_check, run_quick_check, check_foreign_keys,
    scan_for_corruption, format_check_results,
)
from .carve import carve_blobs, format_carve_results
from .export import (
    export_database_csv, export_database_json, export_schema_sql,
    format_export_results,
)
from .report import generate_forensic_report
from .tui import run_tui
from .hexdump import print_hexdump

OK = "[OK]"
FAIL = "[FAIL]"
WARN = "[!]"


def main():
    parser = argparse.ArgumentParser(
        prog="sqlime",
        description="SQLite forensic inspection and recovery toolkit",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # inspect
    p = sub.add_parser("inspect", help="Page-level database inspection")
    p.add_argument("database", help="Path to SQLite database")
    p.add_argument("--page", type=int, help="Specific page number to inspect")
    p.add_argument("--hex", action="store_true", help="Show raw hex dump")
    p.add_argument("--decode", action="store_true", help="Decode page headers")
    p.add_argument("--freelist", action="store_true", help="List free pages")

    # recover
    p = sub.add_parser("recover", help="Recover deleted records and WAL data")
    p.add_argument("database", help="Path to SQLite database")
    p.add_argument("--wal", help="Path to WAL journal file")
    p.add_argument("--deleted", action="store_true", help="Scan for deleted rows")
    p.add_argument("--blob-extract", metavar="DIR", help="Carve BLOB files to directory")

    # wal (new top-level command)
    p = sub.add_parser("wal", help="Analyze WAL journal file")
    p.add_argument("wal_path", help="Path to WAL file")
    p.add_argument("--recover", metavar="DB", help="Attempt WAL recovery against a database")

    # report
    p = sub.add_parser("report", help="Generate forensic HTML report")
    p.add_argument("database", help="Path to SQLite database")
    p.add_argument("-o", "--output", default="forensic_report.html", help="Output path")
    p.add_argument("--title", default="SQLite Forensic Report", help="Report title")

    # schema
    p = sub.add_parser("schema", help="Extract schema and dependency graph")
    p.add_argument("database", help="Path to SQLite database")
    p.add_argument("--graph", metavar="FILE", help="Output Graphviz DOT file")

    # check
    p = sub.add_parser("check", help="Run corruption checks")
    p.add_argument("database", help="Path to SQLite database")
    p.add_argument("--quick", action="store_true", help="Run quick check only")
    p.add_argument("--verbose", action="store_true", help="Detailed error output")

    # export
    p = sub.add_parser("export", help="Export data to CSV/JSON/SQL")
    p.add_argument("database", help="Path to SQLite database")
    p.add_argument("--format", choices=["csv", "json", "sql"], default="csv", help="Export format")
    p.add_argument("-o", "--output", default="export", help="Output path (dir or file for SQL)")

    # hexdump
    p = sub.add_parser("hexdump", help="Hex dump database pages")
    p.add_argument("database", help="Path to SQLite database")
    p.add_argument("--page", type=int, help="Page number to dump")
    p.add_argument("--start", type=int, help="Starting page")
    p.add_argument("--end", type=int, help="Ending page (with --start)")
    p.add_argument("--width", type=int, default=16, help="Bytes per line")
    p.add_argument("--group", type=int, default=2, help="Bytes per hex group")

    # tui
    p = sub.add_parser("tui", help="Interactive terminal UI")
    p.add_argument("database", help="Path to SQLite database")

    args = parser.parse_args()

    if args.command == "inspect":
        _cmd_inspect(args)
    elif args.command == "recover":
        _cmd_recover(args)
    elif args.command == "wal":
        _cmd_wal(args)
    elif args.command == "report":
        _cmd_report(args)
    elif args.command == "schema":
        _cmd_schema(args)
    elif args.command == "check":
        _cmd_check(args)
    elif args.command == "export":
        _cmd_export(args)
    elif args.command == "hexdump":
        print_hexdump(args)
    elif args.command == "tui":
        run_tui(args)


def _verify_db(path: str) -> bool:
    """Check if a path is a valid SQLite database."""
    if not os.path.exists(path):
        print(f" {FAIL} File not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        hdr = read_database_header(path)
        if not hdr.is_valid():
            print(f" {FAIL} Not a valid SQLite database: {path}", file=sys.stderr)
            sys.exit(1)
        return True
    except Exception as e:
        print(f" {FAIL} Failed to read database: {e}", file=sys.stderr)
        sys.exit(1)


def _cmd_inspect(args):
    _verify_db(args.database)
    page_size = get_page_size(args.database)

    if args.page:
        page_data = read_page(args.database, args.page, page_size)
        if args.hex:
            print(hex_dump(page_data, offset=(args.page - 1) * page_size))
        else:
            header = PageHeader(page_data, args.page, page_size)
            print(header.summary())
            if args.decode:
                print("")
                print(f"  Page type: {header.type_name()}")
                print(f"  Cell count: {header.cell_count}")
                print(f"  Cell content start: {header.cell_start}")
                print(f"  First freeblock: {header.first_freeblock}")
                if header.right_child_ptr:
                    print(f"  Right child page: {header.right_child_ptr}")
    elif args.freelist:
        pages = list_freelist_pages(args.database)
        if pages:
            print(f"  Free pages ({len(pages)}): {', '.join(str(p) for p in pages[:50])}")
            if len(pages) > 50:
                print(f"  ... and {len(pages) - 50} more")
        else:
            print("  No free pages found.")
    else:
        hdr = read_database_header(args.database)
        print("=" * 56)
        print("  SQLite Database Inspection")
        print("=" * 56)
        print(hdr.summary())
        print("")
        print(f"  Free pages: {hdr.total_freelist_pages}")
        print(f"  Page size: {hdr.page_size} bytes")
        print(f"  Pages on disk: {hdr.db_size_pages}")
        print(f"  Valid signature: {'Yes' if hdr.is_valid() else 'No'}")


def _cmd_recover(args):
    _verify_db(args.database)

    if args.deleted:
        print("  Scanning for deleted records...")
        results = scan_database_for_deleted_rows(args.database)
        print(format_recovery_results(results))

    if args.wal:
        print(f"  Analyzing WAL: {args.wal}")
        print(wal_summary(args.wal))
        results = recover_deleted_rows_from_wal(args.database, args.wal)
        if results:
            print(f"\n  Found {len(results)} tables with WAL page data:")
            for r in results:
                print(f"    {r['table']}: root page {r['root_page']} ({r['data_size']:,} bytes in WAL)")

    if args.blob_extract:
        print(f"  Carving BLOBs to {args.blob_extract}...")
        results = carve_blobs(args.database, args.blob_extract)
        print(format_carve_results(results))

    if not args.deleted and not args.wal and not args.blob_extract:
        print(f" {WARN} Specify --deleted, --wal, or --blob-extract to recover data")


def _cmd_wal(args):
    if args.recover:
        _verify_db(args.recover)
        results = recover_deleted_rows_from_wal(args.recover, args.wal_path)
        print(f"  WAL recovery against {args.recover}:")
        if results:
            for r in results:
                print(f"    {r['table']}: page data in WAL ({r['data_size']:,} bytes)")
        else:
            print("    No WAL data found for known tables.")
    else:
        print(wal_summary(args.wal_path))


def _cmd_report(args):
    _verify_db(args.database)
    print("  Generating report...")
    output = generate_forensic_report(args.database, args.output, args.title)
    file_size = os.path.getsize(output)
    print(f"  {OK} Report saved to {output} ({file_size:,} bytes)")


def _cmd_schema(args):
    _verify_db(args.database)

    if args.graph:
        dot = generate_dot(args.database)
        if args.graph == "-":
            print(dot)
        else:
            with open(args.graph, "w") as f:
                f.write(dot)
            print(f"  {OK} DOT graph saved to {args.graph}")
    else:
        print(schema_summary(args.database))


def _cmd_check(args):
    _verify_db(args.database)

    if args.quick:
        result = run_quick_check(args.database)
        if result.get("passed"):
            print(f"  {OK} Quick check passed")
        else:
            print(f"  {FAIL} Quick check: {result.get('quick_check')}")
        return

    print("  Running integrity check...")
    integrity = run_integrity_check(args.database)
    fk_violations = check_foreign_keys(args.database)
    page_issues = scan_for_corruption(args.database) if args.verbose else []

    print(format_check_results(integrity, fk_violations, page_issues))


def _cmd_export(args):
    _verify_db(args.database)

    if args.format == "sql":
        output = args.output
        if not output.endswith(".sql"):
            output += ".sql"
        result = export_schema_sql(args.database, output)
        print(format_export_results([result]))
    elif args.format == "csv":
        results = export_database_csv(args.database, args.output)
        print(format_export_results(results))
    elif args.format == "json":
        results = export_database_json(args.database, args.output)
        print(format_export_results(results))


if __name__ == "__main__":
    main()
