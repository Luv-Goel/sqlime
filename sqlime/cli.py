"""SQLime CLI entry point."""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="sqlime",
        description="SQLite forensic inspection and recovery toolkit",
    )
    parser.add_argument("--version", action="version", version="0.1.0")

    sub = parser.add_subparsers(dest="command", required=True)

    # inspect
    p_inspect = sub.add_parser("inspect", help="Page-level database inspection")
    p_inspect.add_argument("database", help="Path to SQLite database")
    p_inspect.add_argument("--page", type=int, help="Specific page number to inspect")
    p_inspect.add_argument("--hex", action="store_true", help="Show raw hex dump")
    p_inspect.add_argument("--decode", action="store_true", help="Decode page headers")

    # recover
    p_recover = sub.add_parser("recover", help="Recover deleted records and WAL data")
    p_recover.add_argument("database", help="Path to SQLite database")
    p_recover.add_argument("--wal", help="Path to WAL journal file")
    p_recover.add_argument("--deleted", action="store_true", help="Scan for deleted rows")
    p_recover.add_argument("--blob-extract", help="Carve BLOB files to directory")

    # report
    p_report = sub.add_parser("report", help="Generate forensic HTML report")
    p_report.add_argument("database", help="Path to SQLite database")
    p_report.add_argument("-o", "--output", default="forensic_report.html", help="Output path")

    # schema
    p_schema = sub.add_parser("schema", help="Extract schema and dependency graph")
    p_schema.add_argument("database", help="Path to SQLite database")
    p_schema.add_argument("--graph", help="Output Graphviz DOT file")

    # check
    p_check = sub.add_parser("check", help="Run corruption checks")
    p_check.add_argument("database", help="Path to SQLite database")
    p_check.add_argument("--verbose", action="store_true", help="Detailed error output")

    # export
    p_export = sub.add_parser("export", help="Export data to CSV/JSON")
    p_export.add_argument("database", help="Path to SQLite database")
    p_export.add_argument("--format", choices=["csv", "json"], default="csv")
    p_export.add_argument("-o", "--output", default="export", help="Output path (dir or file)")

    args = parser.parse_args()
    print(f"SQLime v{__version__} — coming soon!")
    print(f"Command: {args.command}")
    sys.exit(0)


if __name__ == "__main__":
    main()
