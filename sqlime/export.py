"""Data export to CSV, JSON, and other formats."""

import csv
import json
import os
import sqlite3


def export_table_csv(database: str, table: str, output: str) -> dict:
    """Export a table to CSV."""
    conn = sqlite3.connect(database)
    cur = conn.execute(f'SELECT * FROM "{table}"')
    headers = [d[0] for d in cur.description]
    rows = cur.fetchall()
    conn.close()

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    return {
        "format": "csv",
        "table": table,
        "output": output,
        "rows": len(rows),
        "columns": len(headers),
    }


def export_database_csv(database: str, output_dir: str) -> list[dict]:
    """Export all tables to individual CSV files."""
    os.makedirs(output_dir, exist_ok=True)
    conn = sqlite3.connect(database)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"
    ).fetchall()
    conn.close()

    results = []
    for (tname,) in tables:
        output = os.path.join(output_dir, f"{tname}.csv")
        result = export_table_csv(database, tname, output)
        results.append(result)

    return results


def export_table_json(database: str, table: str, output: str) -> dict:
    """Export a table to JSON (array of objects)."""
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    cur = conn.execute(f'SELECT * FROM "{table}"')
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()

    # Convert bytes to hex for JSON serialization
    def serialize(obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return str(obj)

    serialized = []
    for row in rows:
        serialized.append({k: serialize(v) if isinstance(v, bytes) else v
                           for k, v in row.items()})

    with open(output, "w", encoding="utf-8") as f:
        json.dump(serialized, f, indent=2, default=str)

    return {
        "format": "json",
        "table": table,
        "output": output,
        "rows": len(rows),
        "columns": len(rows[0]) if rows else 0,
    }


def export_database_json(database: str, output_dir: str) -> list[dict]:
    """Export all tables to individual JSON files."""
    os.makedirs(output_dir, exist_ok=True)
    conn = sqlite3.connect(database)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"
    ).fetchall()
    conn.close()

    results = []
    for (tname,) in tables:
        output = os.path.join(output_dir, f"{tname}.json")
        result = export_table_json(database, tname, output)
        results.append(result)

    return results


def export_schema_sql(database: str, output: str) -> dict:
    """Export the full schema as SQL DDL."""
    conn = sqlite3.connect(database)
    rows = conn.execute(
        "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
    ).fetchall()
    conn.close()

    with open(output, "w", encoding="utf-8") as f:
        for (sql_stmt,) in rows:
            f.write(sql_stmt.strip())
            f.write(";\n\n")

    return {
        "format": "sql",
        "output": output,
        "statements": len(rows),
    }


def format_export_results(results: list[dict]) -> str:
    """Format export results for display."""
    if not results:
        return "  No data exported."

    lines = []
    for r in results:
        fmt = r["format"]
        table = r.get("table", "schema")
        rows_count = r.get("rows", 0)
        output = r.get("output", "")
        lines.append(f"  [{fmt}] {table}: {rows_count} rows -> {output}")

    return "\n".join(lines)
