"""Tests for sqlime core modules — pages, hexdump, schema, check, recovery."""

import os
import sqlite3
import struct
import tempfile

import pytest

from sqlime import __version__
from sqlime.pages import (
    read_database_header,
    get_page_size,
    read_page,
    PageHeader,
    DatabaseHeader,
    hex_dump,
    list_freelist_pages,
    parse_cell_pointers,
    format_page_type_byte,
)
from sqlime.hexdump import HexViewer, dump_page, dump_range, hexdump
from sqlime.schema import schema_summary
from sqlime.check import run_quick_check, run_integrity_check


# ── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def db_path():
    """Create a small SQLite database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT, value REAL)")
    conn.execute("CREATE TABLE t2 (k INTEGER, v TEXT)")
    conn.execute("INSERT INTO t1 VALUES (1, 'alice', 1.1)")
    conn.execute("INSERT INTO t1 VALUES (2, 'bob', 2.2)")
    conn.execute("INSERT INTO t1 VALUES (3, 'carol', 3.3)")
    conn.execute("INSERT INTO t2 VALUES (10, 'ten')")
    conn.execute("INSERT INTO t2 VALUES (20, 'twenty')")
    conn.execute("DELETE FROM t1 WHERE id = 2")  # ghost record
    conn.commit()
    conn.close()
    yield path
    os.unlink(path)


# ── version ─────────────────────────────────────────────────────────────────


def test_version():
    assert isinstance(__version__, str)
    assert __version__.count(".") >= 2


# ── database header ─────────────────────────────────────────────────────────


def test_header_reads(db_path):
    hdr = read_database_header(db_path)
    assert hdr.is_valid()
    assert hdr.magic == b"SQLite format 3\0"
    assert hdr.page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
    assert hdr.db_size_pages >= 1
    assert hdr.encoding_name() in ("UTF-8", "UTF-16LE", "UTF-16BE")
    assert hdr.summary() != ""


def test_header_invalid():
    """Writing a NamedTemporaryFile on Windows needs care with file handles."""
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    try:
        tmp.write(b"not a sqlite database" * 10)
        tmp.close()
        hdr = read_database_header(tmp.name)
        assert not hdr.is_valid()
    finally:
        os.unlink(tmp.name)


def test_get_page_size(db_path):
    ps = get_page_size(db_path)
    assert ps in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)


# ── page read / header ────────────────────────────────────────────────────


def test_read_page(db_path):
    ps = get_page_size(db_path)
    # page 1 should exist and have a valid type byte
    data = read_page(db_path, 1, ps)
    assert len(data) == ps
    hdr = PageHeader(data, 1, ps)
    assert hdr.page_type in (2, 5, 10, 13)
    assert hdr.type_name() != ""
    assert hdr.summary() != ""


def test_page_header_summary(db_path):
    ps = get_page_size(db_path)
    data = read_page(db_path, 1, ps)
    hdr = PageHeader(data, 1, ps)
    s = hdr.summary()
    assert "Page 1" in s
    assert "cells=" in s


def test_hex_dump():
    data = bytes(range(256))
    dumped = hex_dump(data)
    assert "00 01 02 03" in dumped
    assert "|" in dumped
    lines = dumped.split("\n")
    assert len(lines) == 16  # 256 bytes ÷ 16 per line


def test_list_freelist(db_path):
    pages = list_freelist_pages(db_path)
    assert isinstance(pages, list)


def test_parse_cell_pointers(db_path):
    ps = get_page_size(db_path)
    data = read_page(db_path, 1, ps)
    hdr = PageHeader(data, 1, ps)
    ptrs = parse_cell_pointers(data, hdr)
    assert len(ptrs) == hdr.cell_count


def test_format_page_type():
    assert "Leaf Table" in format_page_type_byte(13)
    assert "Interior Table" in format_page_type_byte(5)
    assert "Unknown" in format_page_type_byte(99)


# ── hexdump module ─────────────────────────────────────────────────────────


def test_hexdump_basic():
    data = b"hello\x00world"
    out = hexdump(data)
    assert "hello" in out
    assert "world" in out
    assert "|" in out


def test_hexdump_no_ascii():
    data = b"test"
    out = hexdump(data, show_ascii=False)
    assert "|" not in out


def test_hexdump_no_offset():
    data = b"test"
    out = hexdump(data, show_offset=False)
    lines = out.split("\n")
    for line in lines:
        # without offset, lines start with hex bytes — they won't have
        # the typical "00000000  " prefix pattern
        assert not line.startswith("00000000")


def test_dump_page(db_path):
    out = dump_page(db_path, 1)
    assert "Page 1" in out or "00" in out


def test_dump_range(db_path):
    out = dump_range(db_path, 1, 2)
    assert out.strip()


def test_hexviewer(db_path):
    viewer = HexViewer(db_path)
    assert viewer.total_pages >= 1
    pages = list(viewer.head(2))
    assert len(pages) <= 2
    pages2 = list(viewer.tail(2))
    assert len(pages2) <= 2


def test_hexviewer_search(db_path):
    viewer = HexViewer(db_path)
    results = list(viewer.search(b"alice"))
    # the string "alice" should be in the DB
    assert len(results) >= 1
    pagenum, snippet = results[0]
    assert isinstance(pagenum, int)


# ── schema ─────────────────────────────────────────────────────────────────


def test_schema_summary(db_path):
    out = schema_summary(db_path)
    assert "t1" in out or "CREATE TABLE" in out
    assert out.strip()


# ── check ──────────────────────────────────────────────────────────────────


def test_quick_check(db_path):
    result = run_quick_check(db_path)
    assert isinstance(result, dict)
    # should pass for a valid DB
    assert result.get("passed", False) or result.get("quick_check", "")
