# 🔍 SQLime — SQLite Forensic Toolkit

<div align="center">

**Inspect, recover, and analyze SQLite databases like a digital forensics expert.**

[![CI](https://github.com/Luv-Goel/sqlime/actions/workflows/ci.yml/badge.svg)](https://github.com/Luv-Goel/sqlime/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue?logo=python)](https://github.com/Luv-Goel/sqlime)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Luv-Goel/sqlime?style=social)](https://github.com/Luv-Goel/sqlime/stargazers)

**Zero API keys. Zero cloud. Pure CLI forensics.**

</div>

---

## What is SQLime?

SQLime is a **professional-grade forensic CLI** for SQLite databases. Think of it as a digital forensics toolkit for the most ubiquitous database format on the planet — every phone, browser, app, and embedded device uses SQLite.

**Use it when you need to:**

- 🔬 **Inspect** database structure at the page level (hex dump, header decode, cell analysis)
- 💀 **Recover** deleted records from unallocated space
- 📋 **Analyze** WAL journal files for uncommitted transactions and historical data
- 🧩 **Carve** embedded files from BLOB columns (images, PDFs, archives)
- 🩺 **Diagnose** corruption with integrity checks, page scanning, and foreign key validation
- 🗺️ **Visualize** schema with dependency graphs and comprehensive reports
- 📤 **Export** data to CSV, JSON, or SQL with forensic context

## Quick Start

```bash
# Install
pip install sqlime

# Get the big picture
sqlime inspect chat.db

# Check for corruption
sqlime check chat.db

# Recover deleted data
sqlime recover chat.db --deleted

# Dump the schema
sqlime schema chat.db

# Export everything
sqlime export chat.db --format json -o evidence/

# Generate a forensic report
sqlime report chat.db -o report.html

# Drill into specific pages
sqlime inspect chat.db --page 3 --hex
sqlime inspect chat.db --page 5 --decode

# Analyze WAL files
sqlime wal chat.db-wal

# Carve embedded files
sqlime recover chat.db --blob-extract carved_files/
```

## Commands

| Command | What it does |
|---------|-------------|
| `sqlime inspect <db>` | Full database header + metadata overview |
| `sqlime inspect <db> --page N` | Hex dump or decode a specific page |
| `sqlime inspect <db> --freelist` | List freelist (free/unallocated) pages |
| `sqlime schema <db>` | Tables, indexes, views, triggers, columns, types |
| `sqlime schema <db> --graph out.dot` | Generate Graphviz dependency graph |
| `sqlime check <db>` | PRAGMA integrity_check + foreign key validation |
| `sqlime recover <db> --deleted` | Scan freeblocks + unallocated space for ghost records |
| `sqlime recover <db> --wal <wal>` | Analyze and recover data from WAL journal |
| `sqlime recover <db> --blob-extract <dir>` | Carve and extract BLOB files |
| `sqlime wal <file>` | Analyze standalone WAL journal file |
| `sqlime export <db> --format csv/json/sql` | Bulk export all data or schema DDL |
| `sqlime report <db> -o report.html` | Generate standalone forensic HTML report |

## Features in Detail

### 🔬 Page-Level Inspection
SQLite stores data in fixed-size pages (usually 4KB). SQLime gives you full access:
- **Hex dump** any page with ASCII sidebar, offset markers, and color coding
- **Decode page headers** — type (leaf/interior table, leaf/interior index, overflow), cell count, freeblock pointers, cell content region
- **Parse cell pointers** — see what's actually stored and where
- **Walk freelists** — find all unallocated pages

### 💀 Deleted Row Recovery
When SQLite deletes a row, it marks the record as free but doesn't immediately overwrite the data. SQLime can:
- Find **freeblocks** within pages (formally deleted, recycled cell space)
- Scan **unallocated space** between the cell pointer array and content region
- Attempt to decode residual record data from these areas
- Map ghost records back to their original tables using schema information

### 📋 WAL Journal Analysis
Write-Ahead Log files contain a complete history of recent changes:
- Parse WAL headers, frame headers, and checksums
- Extract page data from WAL frames — including pages from **uncommitted** or **rolled back** transactions
- Match WAL frames to database tables
- Visualize transaction timeline

### 🧩 BLOB Carving
Databases often embed files in BLOB columns. SQLime can:
- Find all BLOB columns across all tables
- Extract BLOB data and identify file types by **magic bytes** (PNG, JPG, PDF, ZIP, GIF, MP4, and 30+ more)
- Carve files directly to disk with proper extensions

### 🩺 Corruption Detection
- **PRAGMA integrity_check** — the official SQLite integrity verification
- **PRAGMA quick_check** — faster alternative for large databases
- **Foreign key validation** — find orphaned rows
- **Page-level structural scan** — validate page headers, cell counts, and content regions

### 🗺️ Schema Visualization
- Full schema: tables, indexes, views, triggers with columns, types, constraints
- Column-level detail: PK, NOT NULL, defaults, type affinity
- **Graphviz DOT export** — visualize table relationships and foreign keys
- **HTML report** — interactive forensic summary with status cards and navigation

## Project Structure

```
sqlime/
├── sqlime/
│   ├── cli.py         # argparse CLI with 7 subcommands
│   ├── pages.py       # Page-level reading, headers, hex dump
│   ├── wal.py         # WAL journal parsing and recovery
│   ├── recovery.py    # Deleted row scanning, record parsing
│   ├── schema.py      # Schema extraction, Graphviz DOT export
│   ├── check.py       # Integrity checks and corruption scanning
│   ├── carve.py       # BLOB carving with magic byte detection
│   ├── export.py      # CSV, JSON, SQL export
│   └── report.py      # HTML forensic report generation
├── tests/
├── pyproject.toml
└── README.md
```

## Why SQLime?

Existing forensic SQLite tools are:
- **$$$ Expensive** — Belkasoft, Magnet, Oxygen cost thousands
- **GUI-only** — can't script or integrate into CI/CD pipelines
- **Overkill** — you don't need a full suite for a quick recovery
- **Closed source** — can't audit what they're doing

SQLime is: **free**, **open source**, **CLI-first**, **scriptable**, and **auditable**.

And unlike similar CLI tools, SQLime focuses on **actual forensics** — it reads raw pages, walks freeblocks, parses WAL frames, and finds ghost data. It's not just a sqlite3 wrapper with pretty output.

## Roadmap

- [x] Page-level inspection (hex + decode)
- [x] Deleted row recovery (freeblocks + unallocated space)
- [x] WAL journal analysis and recovery
- [x] BLOB carving with magic byte detection
- [x] Schema extraction and DOT graph export
- [x] HTML forensic report
- [x] CSV/JSON/SQL export
- [ ] Live forensic mode (process memory + temp files)
- [ ] Timeline reconstruction (WAL frame ordering + table row versions)
- [ ] Crypto wallet forensics (detect common wallet DB patterns)

## License

MIT. Do whatever, but use responsibly — forensic tools are powerful.

---

*SQLime was built by [ClawWorks Engineering Inc.](https://github.com/Luv-Goel) — 6 projects/day, no excuses.*
