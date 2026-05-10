"""Schema extraction and dependency graph generation."""

import sqlite3


def get_schema(database: str) -> list[dict]:
    """Extract the complete schema (tables, indexes, views, triggers)."""
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    objects = []

    # Tables
    rows = conn.execute(
        "SELECT name, rootpage, sql FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"
    ).fetchall()
    for row in rows:
        objects.append({
            "type": "table",
            "name": row["name"],
            "rootpage": row["rootpage"],
            "sql": row["sql"] or f"CREATE TABLE {row['name']} (unknown)",
        })

    # Indexes
    rows = conn.execute(
        "SELECT name, rootpage, sql, tbl_name FROM sqlite_master WHERE type='index'"
    ).fetchall()
    for row in rows:
        objects.append({
            "type": "index",
            "name": row["name"],
            "rootpage": row["rootpage"],
            "table": row["tbl_name"],
            "sql": row["sql"] or f"CREATE INDEX {row['name']} ON {row['tbl_name']}",
        })

    # Views
    rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='view'"
    ).fetchall()
    for row in rows:
        objects.append({
            "type": "view",
            "name": row["name"],
            "sql": row["sql"] or f"CREATE VIEW {row['name']} AS ...",
        })

    # Triggers
    rows = conn.execute(
        "SELECT name, sql, tbl_name FROM sqlite_master WHERE type='trigger'"
    ).fetchall()
    for row in rows:
        objects.append({
            "type": "trigger",
            "name": row["name"],
            "table": row["tbl_name"],
            "sql": row["sql"] or f"CREATE TRIGGER {row['name']} ...",
        })

    conn.close()

    # Add column info to tables
    for obj in objects:
        if obj["type"] == "table":
            conn = sqlite3.connect(database)
            cols = conn.execute(f"PRAGMA table_info(\"{obj['name']}\")").fetchall()
            conn.close()
            obj["columns"] = [
                {"cid": c[0], "name": c[1], "type": c[2], "notnull": bool(c[3]),
                 "default": c[4], "pk": bool(c[5])}
                for c in cols
            ]

    return objects


def get_foreign_keys(database: str) -> list[dict]:
    """Extract foreign key relationships."""
    conn = sqlite3.connect(database)
    fks = []
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"
    ).fetchall()
    for (tname,) in tables:
        rows = conn.execute(f"PRAGMA foreign_key_list(\"{tname}\")").fetchall()
        for row in rows:
            fks.append({
                "table": tname,
                "id": row[0],
                "seq": row[1],
                "from": row[3],
                "to": row[4],
                "references": row[2],
                "on_update": row[5],
                "on_delete": row[6],
                "match": row[7],
            })
    conn.close()
    return fks


def generate_dot(database: str) -> str:
    """Generate a Graphviz DOT graph of the schema."""
    objects = get_schema(database)
    fks = get_foreign_keys(database)

    lines = [
        "digraph SQLiteSchema {",
        "  rankdir=LR;",
        "  node [shape=plaintext, fontname=monospace];",
        "  edge [fontname=monospace, fontsize=10];",
        "",
        "  // Tables",
    ]

    for obj in objects:
        if obj["type"] == "table":
            name = obj["name"]
            cols = obj.get("columns", [])
            col_lines = []
            for c in cols:
                pk_mark = "🔑 " if c["pk"] else ""
                nullable = "" if c["notnull"] else "?"
                col_lines.append(
                    f"    <tr><td align=\"left\">{pk_mark}{c['name']}</td>"
                    f"<td>{c['type']}{nullable}</td></tr>"
                )
            col_str = "\n".join(col_lines)
            lines.append(f'  "{name}" [label=<')
            lines.append('    <table border="1" cellborder="1" cellspacing="0">')
            lines.append(f'    <tr><td bgcolor="#4a90d9" colspan="2"><b>{name}</b></td></tr>')
            lines.append(f'    {col_str}')
            lines.append('    </table>>];')
            lines.append("")

    # Indexes
    for obj in objects:
        if obj["type"] == "index":
            name = obj["name"]
            tname = obj["table"]
            lines.append(f'  "{name}" [shape=note, label="{name}", fontname=monospace];')
            lines.append(f'  "{name}" -> "{tname}" [style=dashed, arrowhead=none, label="index"];')

    # Foreign keys
    for fk in fks:
        src = fk["table"]
        dst = fk["references"]
        label = f"{fk['from']} -> {fk['to']}"
        lines.append(f'  "{src}" -> "{dst}" [label="{label}", color=red];')

    lines.append("}")
    return "\n".join(lines)


def schema_summary(database: str) -> str:
    """Pretty-print the schema."""
    objects = get_schema(database)
    fks = get_foreign_keys(database)

    lines = []
    tables = [o for o in objects if o["type"] == "table"]
    indexes = [o for o in objects if o["type"] == "index"]
    views = [o for o in objects if o["type"] == "view"]
    triggers = [o for o in objects if o["type"] == "trigger"]

    lines.append("=" * 56)
    lines.append("  Schema Summary")
    lines.append("=" * 56)
    lines.append(f"  Tables:   {len(tables)}")
    lines.append(f"  Indexes:  {len(indexes)}")
    lines.append(f"  Views:    {len(views)}")
    lines.append(f"  Triggers: {len(triggers)}")
    lines.append(f"  Foreign keys: {len(fks)}")
    lines.append("")

    for t in tables:
        lines.append(f"  Table: {t['name']}")
        lines.append(f"    Root page: {t['rootpage']}")
        for c in t.get("columns", []):
            pk = " PK" if c["pk"] else ""
            nn = " NOT NULL" if c["notnull"] else ""
            default = f" DEFAULT {c['default']}" if c["default"] is not None else ""
            lines.append(f"    {c['name']:<24} {c['type']}{pk}{nn}{default}")
        lines.append("")

    for idx in indexes:
        lines.append(f"  Index: {idx['name']} on {idx['table']} (root={idx['rootpage']})")

    for v in views:
        lines.append(f"  View: {v['name']}")

    for t in triggers:
        lines.append(f"  Trigger: {t['name']} ON {t['table']}")

    return "\n".join(lines)
