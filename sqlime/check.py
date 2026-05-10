"""Corruption detection and integrity checking."""

import sqlite3
from .pages import (
    read_page, read_database_header,
    PageHeader,
)


def run_integrity_check(database: str) -> dict:
    """Run PRAGMA integrity_check and return results."""
    try:
        conn = sqlite3.connect(database)
        cur = conn.execute("PRAGMA integrity_check")
        rows = cur.fetchall()
        conn.close()

        errors = [r[0] for r in rows if r[0] != "ok"]
        return {
            "passed": len(errors) == 0,
            "integrity_check": "ok" if not errors else errors,
            "errors": errors,
        }
    except sqlite3.DatabaseError as e:
        return {
            "passed": False,
            "integrity_check": f"error: {e}",
            "errors": [str(e)],
        }


def run_quick_check(database: str) -> dict:
    """Run PRAGMA quick_check (faster, less thorough)."""
    try:
        conn = sqlite3.connect(database)
        cur = conn.execute("PRAGMA quick_check")
        result = cur.fetchone()[0]
        conn.close()
        return {
            "passed": result == "ok",
            "quick_check": result,
        }
    except sqlite3.DatabaseError as e:
        return {"passed": False, "quick_check": f"error: {e}"}


def check_foreign_keys(database: str) -> list[dict]:
    """Check for foreign key violations."""
    try:
        conn = sqlite3.connect(database)
        conn.execute("PRAGMA foreign_keys = ON")
        cur = conn.execute("PRAGMA foreign_key_check")
        rows = cur.fetchall()
        conn.close()

        violations = []
        for row in rows:
            violations.append({
                "table": row[0],
                "rowid": row[1],
                "parent": row[2],
                "fkid": row[3],
            })
        return violations
    except sqlite3.DatabaseError:
        return []


def scan_for_corruption(database: str) -> list[dict]:
    """Scan database file for structural corruption at the page level."""
    issues = []
    try:
        hdr = read_database_header(database)
        page_size = hdr.page_size
        total_pages = hdr.db_size_pages

        if not hdr.is_valid():
            return [{"type": "error", "message": "Not a valid SQLite database file"}]

        # Check database header version
        if hdr.write_version != 1:
            issues.append({
                "type": "warning",
                "message": f"Unusual write version: {hdr.write_version} (expected 1)",
            })

        # Check each page header
        for page_num in range(1, min(total_pages + 1, 1000)):  # Limit to first 1000 pages
            try:
                page_data = read_page(database, page_num, page_size)
                if len(page_data) < page_size:
                    issues.append({
                        "type": "error",
                        "message": f"Page {page_num}: truncated (got {len(page_data)} bytes)",
                    })
                    continue

                page_type = page_data[0]
                if page_type not in (2, 5, 10, 13):
                    issues.append({
                        "type": "warning",
                        "message": f"Page {page_num}: unknown page type 0x{page_type:02x}",
                    })
                    continue

                header = PageHeader(page_data, page_num, page_size)
                if header.cell_start > page_size:
                    issues.append({
                        "type": "error",
                        "message": f"Page {page_num}: cell content region starts at {header.cell_start} but page size is {page_size}",
                    })
                if header.cell_count > 2000:  # Unreasonable cell count
                    issues.append({
                        "type": "warning",
                        "message": f"Page {page_num}: unusually high cell count ({header.cell_count})",
                    })

            except Exception as e:
                issues.append({
                    "type": "error",
                    "message": f"Page {page_num}: parse error - {e}",
                })

    except Exception as e:
        issues.append({
            "type": "error",
            "message": f"Failed to read database: {e}",
        })

    return issues


def format_check_results(
    integrity: dict,
    fk_violations: list[dict],
    page_issues: list[dict]
) -> str:
    """Format corruption check results for display."""
    lines = []

    # Integrity check
    if integrity.get("passed"):
        lines.append("  [OK] PRAGMA integrity_check passed")
    else:
        for err in integrity.get("errors", []):
            lines.append(f"  [FAIL] {err}")

    # Foreign key check
    if fk_violations:
        lines.append(f"\n  [WARN] {len(fk_violations)} foreign key violations:")
        for v in fk_violations[:10]:
            lines.append(f"    Table {v['table']}, rowid {v['rowid']} -> {v['parent']}")
        if len(fk_violations) > 10:
            lines.append(f"    ... and {len(fk_violations) - 10} more")
    else:
        lines.append("\n  [OK] No foreign key violations")

    # Page-level issues
    errors = [i for i in page_issues if i["type"] == "error"]
    warnings = [i for i in page_issues if i["type"] == "warning"]

    if errors:
        lines.append(f"\n  [FAIL] {len(errors)} structural error(s):")
        for e in errors[:10]:
            lines.append(f"    {e['message']}")
    if warnings:
        lines.append(f"\n  [WARN] {len(warnings)} warning(s):")
        for w in warnings[:10]:
            lines.append(f"    {w['message']}")

    if not errors and not warnings:
        lines.append("\n  [OK] No page-level corruption detected")

    return "\n".join(lines)
