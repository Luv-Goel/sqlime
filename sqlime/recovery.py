"""Deleted record recovery and unallocated space scanning."""

import struct
from typing import Optional
from .pages import (
    read_page, get_page_size, PageHeader,
)


def _parse_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Parse a SQLite varint, returning (value, bytes_consumed)."""
    value = 0
    for i in range(9):
        if offset + i >= len(data):
            break
        byte = data[offset + i]
        if i < 8:
            value = (value << 7) | (byte & 0x7F)
            if (byte & 0x80) == 0:
                return value, i + 1
        else:
            value = (value << 8) | byte
            return value, i + 1
    return value, 1


def _parse_record(data: bytes, column_types: list[str]) -> dict:
    """Parse a SQLite record given column type hints.

    Column types are: 'text', 'int', 'real', 'blob', 'null'.
    """
    if len(data) < 1:
        return {}

    offset = 0
    # Record format: header_size varint + type varints + payload
    header_size, consumed = _parse_varint(data, offset)
    offset += consumed

    types = []
    while offset < header_size:
        col_type, consumed = _parse_varint(data, offset)
        types.append(col_type)
        offset += consumed

    values = {}
    for i, col_type in enumerate(types):
        if col_type == 0:  # NULL
            values[f"col_{i}"] = None
        elif col_type == 1:  # 8-bit signed
            val = struct.unpack("b", data[offset:offset + 1])[0]
            values[f"col_{i}"] = val
            offset += 1
        elif col_type == 2:  # 16-bit signed
            val = struct.unpack(">h", data[offset:offset + 2])[0]
            values[f"col_{i}"] = val
            offset += 2
        elif col_type == 3:  # 24-bit signed
            val = int.from_bytes(data[offset:offset + 3], "big", signed=True)
            values[f"col_{i}"] = val
            offset += 3
        elif col_type == 4:  # 32-bit signed
            val = struct.unpack(">i", data[offset:offset + 4])[0]
            values[f"col_{i}"] = val
            offset += 4
        elif col_type == 5:  # 48-bit signed
            val = int.from_bytes(data[offset:offset + 6], "big", signed=True)
            values[f"col_{i}"] = val
            offset += 6
        elif col_type == 6:  # 64-bit signed
            val = struct.unpack(">q", data[offset:offset + 8])[0]
            values[f"col_{i}"] = val
            offset += 8
        elif col_type == 7:  # IEEE 64-bit float
            val = struct.unpack(">d", data[offset:offset + 8])[0]
            values[f"col_{i}"] = val
            offset += 8
        elif col_type >= 12 and col_type % 2 == 0:  # BLOB (type-12)/2 bytes
            blob_size = (col_type - 12) // 2
            values[f"col_{i}"] = data[offset:offset + blob_size]
            offset += blob_size
        elif col_type >= 13 and col_type % 2 == 1:  # TEXT (type-13)/2 bytes
            text_size = (col_type - 13) // 2
            try:
                values[f"col_{i}"] = data[offset:offset + text_size].decode("utf-8")
            except UnicodeDecodeError:
                values[f"col_{i}"] = data[offset:offset + text_size].hex()
            offset += text_size
        else:
            values[f"col_{i}"] = f"<unknown_type_{col_type}>"

    return values


def _find_freeblocks(page_data: bytes, page_size: int, header: PageHeader) -> list[dict]:
    """Walk the freeblock chain within a page and return freeblock locations."""
    freeblocks = []
    next_fb = header.first_freeblock
    while next_fb != 0:
        if next_fb + 4 > page_size:
            break
        fb_size = struct.unpack(">H", page_data[next_fb:next_fb + 2])[0]
        next_ptr = struct.unpack(">H", page_data[next_fb + 2:next_fb + 4])[0]
        if fb_size < 4:
            break
        freeblocks.append({
            "offset": next_fb,
            "size": fb_size,
            "next": next_ptr,
            "data": page_data[next_fb:next_fb + fb_size],
        })
        next_fb = next_ptr
    return freeblocks


def _find_unallocated_space(page_data: bytes, page_size: int, header: PageHeader) -> list[dict]:
    """Find unallocated space between cell pointer array and cell content area."""
    # The cell pointer array grows from offset 8/12 downward
    # The cell content grows from the bottom of the page upward
    # Unallocated space is between them

    array_end = max(8 if header._is_leaf() else 12, header.cell_count * 2)
    content_start = min(header.cell_start, page_size)

    if content_start > array_end:
        # There's unallocated space between cell pointer array end and cell content start
        # There is unallocated space between cell pointer array end and cell content start
        # Filter out the freeblock area
        fb_regions = set()
        next_fb = header.first_freeblock
        while next_fb != 0:
            if next_fb + 4 > page_size:
                break
            fb_size = struct.unpack(">H", page_data[next_fb:next_fb + 2])[0]
            for off in range(next_fb, min(next_fb + fb_size, content_start)):
                fb_regions.add(off)
            next_ptr = struct.unpack(">H", page_data[next_fb + 2:next_fb + 4])[0]
            next_fb = next_ptr

        # Find contiguous unallocated chunks not in freeblock regions
        chunks = []
        current_start = None
        for i in range(array_end, content_start):
            if i not in fb_regions:
                if current_start is None:
                    current_start = i
            else:
                if current_start is not None:
                    chunk_size = i - current_start
                    if chunk_size > 0:
                        chunks.append({"offset": current_start, "size": chunk_size})
                    current_start = None
        if current_start is not None:
            chunk_size = content_start - current_start
            if chunk_size > 0:
                chunks.append({"offset": current_start, "size": chunk_size})

        return chunks
    return []


def scan_page_for_deleted_records(
    file_path: str,
    page_num: int,
    page_size: int,
    column_hints: Optional[list[str]] = None
) -> list[dict]:
    """Scan a page for deleted/ghost records in freeblocks and unallocated space."""
    page_data = read_page(file_path, page_num, page_size)
    if len(page_data) < page_size:
        return []

    header = PageHeader(page_data, page_num, page_size)

    # Find freeblocks (formally deleted cells)
    freeblocks = _find_freeblocks(page_data, page_size, header)

    # Find unallocated space that might contain old record data
    unalloc = _find_unallocated_space(page_data, page_size, header)

    candidates = []

    # Try to parse records from freeblocks
    for fb in freeblocks:
        if fb["size"] >= 8:  # Minimum for a valid record
            try:
                rec = _parse_record(fb["data"], column_hints or [])
                if rec:
                    candidates.append({
                        "source": "freeblock",
                        "page": page_num,
                        "offset": fb["offset"],
                        "size": fb["size"],
                        "record": rec,
                    })
            except Exception:
                pass

    # Try to parse from unallocated space
    for chunk in unalloc:
        if chunk["size"] >= 8:
            try:
                rec = _parse_record(page_data[chunk["offset"]:chunk["offset"] + chunk["size"]],
                                    column_hints or [])
                if rec:
                    candidates.append({
                        "source": "unallocated",
                        "page": page_num,
                        "offset": chunk["offset"],
                        "size": chunk["size"],
                        "record": rec,
                    })
            except Exception:
                pass

    return candidates


def scan_database_for_deleted_rows(file_path: str) -> list[dict]:
    """Scan the entire database for deleted rows across all pages."""
    import sqlite3

    # Get table information first
    conn = sqlite3.connect(file_path)
    tables = conn.execute(
        "SELECT name, rootpage FROM sqlite_master WHERE type='table' AND rootpage > 0"
    ).fetchall()
    conn.close()

    page_size = get_page_size(file_path)
    # Get column hints from schema
    hints_by_page = {}
    for tname, rootpage in tables:
        try:
            conn = sqlite3.connect(file_path)
            cols = conn.execute(f"PRAGMA table_info(\"{tname}\")").fetchall()
            conn.close()
            hints = []
            for col in cols:
                type_name = col[2].lower() if col[2] else ""
                if type_name in ("text", "varchar", "char", "clob"):
                    hints.append("text")
                elif type_name in ("int", "integer", "bigint", "smallint", "tinyint"):
                    hints.append("int")
                elif type_name in ("real", "float", "double", "numeric"):
                    hints.append("real")
                elif type_name in ("blob",):
                    hints.append("blob")
                else:
                    hints.append("text")
                hints_by_page[rootpage] = hints
        except Exception:
            hints_by_page[rootpage] = []

    results = []
    # Scan pages that correspond to table root pages and their leaf pages
    # For now, scan root pages and do a limited scan
    scanned_pages = set()
    for tname, rootpage in tables:
        if rootpage in scanned_pages:
            continue
        scanned_pages.add(rootpage)
        candidates = scan_page_for_deleted_records(
            file_path, rootpage, page_size,
            hints_by_page.get(rootpage)
        )
        for c in candidates:
            c["table"] = tname
        results.extend(candidates)

    return results


def format_recovery_results(results: list[dict]) -> str:
    """Format deleted row recovery results for display."""
    if not results:
        return "  No deleted records found."

    lines = [f"  Found {len(results)} potential deleted record(s):\n"]
    for r in results[:50]:  # Limit display
        table = r.get("table", "?")
        src = r["source"]
        page = r["page"]
        record = r.get("record", {})
        line = f"  [{src}] page={page} table={table}"
        vals = list(record.values())[:5]
        if vals:
            line += f"  values={vals}"
        lines.append(line)

    if len(results) > 50:
        lines.append(f"  ... and {len(results) - 50} more")

    return "\n".join(lines)
