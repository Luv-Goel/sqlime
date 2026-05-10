"""BLOB carving — extract embedded files from SQLite BLOB fields."""

import os
from typing import Optional

# Magic bytes for common file formats
MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpg",
    b"GIF8": "gif",
    b"%PDF": "pdf",
    b"\x1f\x8b": "gz",
    b"PK\x03\x04": "zip",
    b"PK\x05\x06": "zip_empty",

    b"\x42\x4d": "bmp",
    b"\x49\x49\x2a\x00": "tiff",
    b"\x4d\x4d\x00\x2a": "tiff",
    b"\x00\x00\x01\x00": "ico",
    b"Rar!\x1a\x07": "rar",
    b"\x7fELF": "elf",
    b"\xca\xfe\xba\xbe": "class",
    b"\xef\xbb\xbf": "utf8_bom",
    b"\xfe\xff": "utf16_be_bom",
    b"\xff\xfe": "utf16_le_bom",
    b"{\\rtf": "rtf",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "ole2",
    b"\x00\x01\x00\x00\x00": "tto",
    b"qoif": "qoi",
    b"fLaC": "flac",
    b"\x49\x44\x33": "mp3_id3",
    b"\xff\xfb": "mp3",
    b"\x1a\x45\xdf\xa3": "webm_mkv",
    b"\x00\x00\x00\x20\x66\x74\x79\x70": "mp4",
    b"\x00\x00\x00\x18\x66\x74\x79\x70": "mp4_variation",
    b"\x4f\x67\x67\x53": "ogg",
    b"WEBVTT": "vtt",
    b"Nu\x10\x00": "nu_db",
}


def identify_magic(data: bytes) -> Optional[str]:
    """Identify file type from magic bytes."""
    for magic, ftype in MAGIC_BYTES.items():
        if data.startswith(magic):
            return ftype
    return None


def find_blob_columns(database: str) -> list[dict]:
    """Find all BLOB columns across all tables and their page locations."""
    import sqlite3
    conn = sqlite3.connect(database)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"
    ).fetchall()

    blob_columns = []
    for (tname,) in tables:
        col_info = conn.execute(f"PRAGMA table_info(\"{tname}\")").fetchall()
        for col in col_info:
            cid, cname, ctype = col[0], col[1], col[2].upper() if col[2] else ""
            if "BLOB" in ctype or ctype in ("", "NONE"):
                blob_columns.append({
                    "table": tname,
                    "column": cname,
                    "cid": cid,
                    "type_declared": ctype,
                })
    conn.close()
    return blob_columns


def extract_blobs_from_table(
    database: str,
    table: str,
    column: str,
    output_dir: str,
    max_blobs: int = 0,
) -> list[dict]:
    """Extract BLOB values from a specific table/column."""
    import sqlite3
    os.makedirs(output_dir, exist_ok=True)
    conn = sqlite3.connect(database)
    rows = conn.execute(f'SELECT rowid, "{column}" FROM "{table}"').fetchall()
    conn.close()

    extracted = []
    for rowid, blob_data in rows:
        if blob_data is None or not isinstance(blob_data, (bytes, bytearray)):
            continue
        if len(blob_data) < 4:
            continue

        file_type = identify_magic(bytes(blob_data[:16]))
        if file_type:
            ext = file_type
        else:
            ext = "bin"

        filename = f"{table}_{column}_row{rowid}.{ext}"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "wb") as f:
            f.write(blob_data)

        extracted.append({
            "table": table,
            "column": column,
            "rowid": rowid,
            "file": filename,
            "size": len(blob_data),
            "type": file_type or "unknown",
        })

        if max_blobs and len(extracted) >= max_blobs:
            break

    return extracted


def carve_blobs(database: str, output_dir: str, max_per_column: int = 50) -> list[dict]:
    """Find and extract all BLOBs from a database.

    Scans all tables and all BLOB-like columns, tries to identify
    file types by magic bytes, and extracts them.
    """
    blob_columns = find_blob_columns(database)
    all_extracted = []

    for bc in blob_columns:
        try:
            extracted = extract_blobs_from_table(
                database, bc["table"], bc["column"],
                output_dir, max_blobs=max_per_column,
            )
            all_extracted.extend(extracted)
        except Exception:
            continue

    return all_extracted


def format_carve_results(results: list[dict]) -> str:
    """Format BLOB carving results for display."""
    if not results:
        return "  No BLOBs found or extracted."

    by_type = {}
    for r in results:
        by_type.setdefault(r["type"], []).append(r)

    lines = [f"  Extracted {len(results)} BLOB(s):\n"]
    for ftype, items in sorted(by_type.items()):
        total_size = sum(i["size"] for i in items)
        lines.append(f"  {ftype}: {len(items)} files ({total_size / 1024:.1f} KB)")

    lines.append("")
    for r in results[:20]:
        lines.append(f"    {r['table']}.{r['column']} (row {r['rowid']}): {r['file']} ({r['size']:,} bytes)")

    if len(results) > 20:
        lines.append(f"    ... and {len(results) - 20} more")

    return "\n".join(lines)
