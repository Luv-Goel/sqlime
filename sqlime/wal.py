"""WAL (Write-Ahead Log) reading and recovery."""

import struct
from typing import Optional


WAL_MAGIC = b"\x37\x7f\x06\x83\x00\x00\x00\x00"

# Checksum methods
CHECKSUM_LEGACY = 1
CHECKSUM_NATIVE = 2


class WALHeader:
    """SQLite WAL file header (first 32 bytes)."""

    def __init__(self, data: bytes):
        self.magic = data[:8]
        self.file_format = struct.unpack(">I", data[8:12])[0]
        self.page_size = struct.unpack(">I", data[12:16])[0]
        self.checkpoint_seq = struct.unpack(">I", data[16:20])[0]
        self.salt_1 = struct.unpack(">I", data[20:24])[0]
        self.salt_2 = struct.unpack(">I", data[24:28])[0]
        self.checksum_method = struct.unpack(">I", data[28:32])[0]

    def is_valid(self) -> bool:
        return self.magic[:4] == WAL_MAGIC[:4]

    def summary(self) -> str:
        return (
            f"Page size: {self.page_size}\n"
            f"Format: {self.file_format}\n"
            f"Checkpoint sequence: {self.checkpoint_seq}\n"
            f"Checksum method: {'native' if self.checksum_method == CHECKSUM_NATIVE else 'legacy'}"
        )


class WALFrame:
    """A single WAL frame (header + page data)."""

    def __init__(self, index: int, header_bytes: bytes, page_data: bytes):
        self.index = index
        self.page_number = struct.unpack(">I", header_bytes[:4])[0]
        self.db_size_after = struct.unpack(">I", header_bytes[4:8])[0]
        self.salt_1 = struct.unpack(">I", header_bytes[8:12])[0]
        self.salt_2 = struct.unpack(">I", header_bytes[12:16])[0]
        self.checksum_1 = struct.unpack(">I", header_bytes[16:20])[0]
        self.checksum_2 = struct.unpack(">I", header_bytes[20:24])[0]
        self.page_data = page_data

    def is_commit(self) -> bool:
        """Check if this frame is a commit marker (page_number == 0)."""
        return self.page_number == 0

    def is_checkpoint(self) -> bool:
        """Check if this frame has the same salt as the header (checkpoint frame)."""
        return self.page_number == 0 and self.salt_1 == 0 and self.salt_2 == 0

    def summary(self) -> str:
        label = "COMMIT" if self.is_commit() else f"Page {self.page_number}"
        return f"Frame {self.index}: {label} (db_size={self.db_size_after})"


def read_wal_header(file_path: str) -> Optional[WALHeader]:
    """Read the WAL file header."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(32)
        if len(data) < 32:
            return None
        return WALHeader(data)
    except (FileNotFoundError, IOError):
        return None


def read_wal_frames(file_path: str, max_frames: int = 0) -> list[WALFrame]:
    """Read all frames from a WAL file.

    Each frame = 24-byte frame header + page_size bytes of page data.
    """
    hdr = read_wal_header(file_path)
    if not hdr or not hdr.is_valid():
        return []

    page_size = hdr.page_size
    frame_size = 24 + page_size

    with open(file_path, "rb") as f:
        # Skip WAL header (32 bytes)
        f.seek(32)
        raw = f.read()

    frames = []
    index = 0
    offset = 0
    while offset + frame_size <= len(raw):
        frame_hdr = raw[offset:offset + 24]
        frame_data = raw[offset + 24:offset + frame_size]
        index += 1
        frame = WALFrame(index, frame_hdr, frame_data)
        if frame.is_commit():
            # Commit frames don't have page data but mark transaction boundaries
            pass
        frames.append(frame)
        offset += frame_size
        if max_frames and len(frames) >= max_frames:
            break

    return frames


def extract_pages_from_wal(file_path: str, db_path: str) -> dict[int, bytes]:
    """Extract page data from WAL, returning latest version of each page.

    WAL frames are applied in order. Later frames for the same page
    override earlier ones. Returns {page_number: page_data_bytes}.
    """
    frames = read_wal_frames(file_path)
    if not frames:
        return {}

    pages = {}
    for frame in frames:
        if not frame.is_commit():
            pages[frame.page_number] = frame.page_data
    return pages


def recover_deleted_rows_from_wal(
    db_path: str,
    wal_path: Optional[str] = None,
    table_name: Optional[str] = None
) -> list[dict]:
    """Attempt to recover row data from WAL frames for a specific table.

    Uses the latest WAL page versions to try reading records that
    may have been deleted from the main database.
    """
    if wal_path is None:
        wal_path = db_path + "-wal"

    wal_pages = extract_pages_from_wal(wal_path, db_path)
    if not wal_pages:
        return []

    import sqlite3

    # Get table schema and page mapping
    conn = sqlite3.connect(db_path)
    cur = conn.execute("SELECT name, rootpage FROM sqlite_master WHERE type='table'")
    tables = dict(cur.fetchall())
    conn.close()

    if table_name:
        target_root = tables.get(table_name)
        if target_root is None:
            return []
        table_list = [(table_name, target_root)]
    else:
        table_list = list(tables.items())

    # For now, return WAL page info
    results = []
    for tname, rootpage in table_list:
        if rootpage in wal_pages:
            results.append({
                "table": tname,
                "root_page": rootpage,
                "wal_frame_present": True,
                "data_size": len(wal_pages[rootpage]),
            })
    return results


def wal_summary(file_path: str) -> str:
    """Generate a human-readable summary of a WAL file."""
    hdr = read_wal_header(file_path)
    if not hdr:
        return "Not a valid WAL file or file not found."
    if not hdr.is_valid():
        return "Invalid WAL magic bytes."

    frames = read_wal_frames(file_path)
    pages_in_wal = set()
    commit_count = 0
    for f in frames:
        if f.is_commit():
            commit_count += 1
        else:
            pages_in_wal.add(f.page_number)

    lines = ["=" * 56, "  WAL Journal Analysis", "=" * 56,
             hdr.summary(),
             f"Total frames: {len(frames)}",
             f"Unique pages in WAL: {len(pages_in_wal)}",
             f"Transaction commits: {commit_count}",
             ""]
    if commit_count > 0:
        lines.append("  Transaction Timeline:")
        for f in frames:
            if f.is_commit():
                lines.append(f"    Frame {f.index}: COMMIT (DB size: {f.db_size_after} pages)")
    return "\n".join(lines)
