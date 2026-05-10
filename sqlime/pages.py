"""SQLite page-level inspection — hex dump, header decoding, type analysis."""

import struct
from typing import Optional

PAGE_TYPES = {
    2: "Interior Index",
    5: "Interior Table",
    10: "Leaf Index",
    13: "Leaf Table",
}

PAGE_TYPE_BYTE = {v: k for k, v in PAGE_TYPES.items()}


class PageHeader:
    """Parsed SQLite page header (first 8-100 bytes depending on page type)."""

    __slots__ = (
        "page_num", "page_type", "first_freeblock", "cell_count",
        "cell_start", "freeblock_count", "fragmented_bytes",
        "right_child_ptr", "page_size",
    )

    def __init__(self, data: bytes, page_num: int, page_size: int):
        self.page_num = page_num
        self.page_size = page_size
        self.page_type = data[0]
        self.first_freeblock = struct.unpack(">H", data[1:3])[0]
        self.cell_count = struct.unpack(">H", data[3:5])[0]
        self.cell_start = struct.unpack(">H", data[5:7])[0]
        self.freeblock_count = data[7]
        self.fragmented_bytes = data[7] if self._is_leaf() else 0
        # Right child pointer only on interior pages
        self.right_child_ptr = None
        if not self._is_leaf():
            self.right_child_ptr = struct.unpack(">I", data[8:12])[0]

    def _is_leaf(self) -> bool:
        return self.page_type in (10, 13)

    def is_table(self) -> bool:
        return self.page_type in (5, 13)

    def type_name(self) -> str:
        return PAGE_TYPES.get(self.page_type, f"Unknown ({self.page_type})")

    def summary(self) -> str:
        parts = [
            f"Page {self.page_num}: {self.type_name()}",
            f"cells={self.cell_count}",
        ]
        if self.first_freeblock:
            parts.append(f"freeblock_start={self.first_freeblock}")
        if self.right_child_ptr:
            parts.append(f"right_child={self.right_child_ptr}")
        return " | ".join(parts)


class DatabaseHeader:
    """SQLite database header (first 100 bytes of page 1)."""

    def __init__(self, data: bytes):
        self.magic = data[:16]
        self.page_size = struct.unpack(">H", data[16:18])[0]
        if self.page_size == 1:
            self.page_size = 65536
        self.write_version = data[18]
        self.read_version = data[19]
        self.reserved_space = data[20]
        self.max_payload = data[21]
        self.min_payload = data[22]
        self.leaf_payload = data[23]
        self.file_change_counter = struct.unpack(">I", data[24:28])[0]
        self.db_size_pages = struct.unpack(">I", data[28:32])[0]
        self.first_freelist_trunk = struct.unpack(">I", data[32:36])[0]
        self.total_freelist_pages = struct.unpack(">I", data[36:40])[0]
        self.schema_cookie = struct.unpack(">I", data[40:44])[0]
        self.schema_format = struct.unpack(">I", data[44:48])[0]
        self.default_cache_size = struct.unpack(">I", data[48:52])[0]
        self.largest_root_page = struct.unpack(">I", data[52:56])[0]
        self.text_encoding = struct.unpack(">I", data[56:60])[0]
        self.user_version = struct.unpack(">I", data[60:64])[0]
        self.incremental_vacuum = struct.unpack(">I", data[64:68])[0]
        self.application_id = struct.unpack(">I", data[68:72])[0]
        self.version_valid_for = struct.unpack(">I", data[72:76])[0]
        self.sqlite_version_number = struct.unpack(">I", data[76:80])[0]

    def is_valid(self) -> bool:
        return self.magic == b"SQLite format 3\0"

    def encoding_name(self) -> str:
        return {1: "UTF-8", 2: "UTF-16LE", 3: "UTF-16BE"}.get(self.text_encoding, "Unknown")

    def summary(self) -> str:
        return (
            f"Page size: {self.page_size}\n"
            f"Size on disk: {self.db_size_pages} pages ({self.db_size_pages * self.page_size / 1024:.1f} KB)\n"
            f"Encoding: {self.encoding_name()}\n"
            f"Schema format: {self.schema_format}\n"
            f"Application ID: 0x{self.application_id:08X}\n"
            f"Free pages: {self.total_freelist_pages}\n"
            f"Largest root: {self.largest_root_page}\n"
            f"User version: {self.user_version}"
        )


class CellPointer:
    """A cell pointer from the cell pointer array."""

    def __init__(self, index: int, offset: int):
        self.index = index
        self.offset = offset


def read_page(file_path: str, page_num: int, page_size: Optional[int] = None) -> bytes:
    """Read a specific page from a SQLite database file.

    For page 1, the first 100 bytes are the database header;
    the page content starts at offset 100.
    """
    if page_size is None:
        page_size = get_page_size(file_path)
    with open(file_path, "rb") as f:
        # Page 1 has 100-byte DB header before page content
        if page_num == 1:
            offset = 100
            # Page 1 content is page_size - 100 bytes (plus the header we skip)
            f.seek(offset)
            return f.read(page_size)  # Read page_size bytes from content start
        else:
            offset = (page_num - 1) * page_size
            f.seek(offset)
            return f.read(page_size)


def get_page_size(file_path: str) -> int:
    """Read the page size from the database header."""
    with open(file_path, "rb") as f:
        header = f.read(18)
    if len(header) < 18:
        raise ValueError(f"File too small to be a SQLite database: {file_path}")
    page_size = struct.unpack(">H", header[16:18])[0]
    if page_size == 1:
        page_size = 65536
    return page_size


def read_database_header(file_path: str) -> DatabaseHeader:
    """Read the full 100-byte database header."""
    with open(file_path, "rb") as f:
        data = f.read(100)
    if len(data) < 100:
        raise ValueError(f"File too small: {file_path}")
    return DatabaseHeader(data)


def parse_cell_pointers(page_data: bytes, header: PageHeader) -> list[CellPointer]:
    """Parse the cell pointer array from a page."""
    pointers = []
    # Cell pointer array starts at offset 8 (or 12 for interior pages)
    # and extends to cell_start - 1
    array_start = 12 if not header._is_leaf() else 8
    for i in range(header.cell_count):
        pos = array_start + (i * 2)
        if pos + 2 > len(page_data):
            break
        offset = struct.unpack(">H", page_data[pos:pos + 2])[0]
        pointers.append(CellPointer(i, offset))
    return pointers


def hex_dump(data: bytes, offset: int = 0, bytes_per_line: int = 16) -> str:
    """Pretty hex dump with ASCII sidebar."""
    result = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        result.append(f"{offset + i:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(result)


def list_freelist_pages(file_path: str) -> list[int]:
    """Walk the freelist trunk pages and list all free pages."""
    hdr = read_database_header(file_path)
    page_size = hdr.page_size
    free_pages = []
    trunk = hdr.first_freelist_trunk
    while trunk != 0:
        data = read_page(file_path, trunk, page_size)
        # First 4 bytes: number of trunk page
        # Next 4 bytes: pointer to next trunk page
        # Remaining: leaf page pointers
        next_trunk = struct.unpack(">I", data[4:8])[0]
        leaf_count = (page_size - 8) // 4
        for i in range(leaf_count):
            pos = 8 + (i * 4)
            if pos + 4 <= page_size:
                leaf = struct.unpack(">I", data[pos:pos + 4])[0]
                if leaf == 0:
                    break
                free_pages.append(leaf)
        trunk = next_trunk
    return free_pages


def format_page_type_byte(byte_val: int) -> str:
    """Decode the page type byte from a page header."""
    return PAGE_TYPES.get(byte_val, f"Unknown (0x{byte_val:02x})")
