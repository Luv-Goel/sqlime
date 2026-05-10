# SQLime — SQLite Forensic Toolkit 🔍

Professional-grade SQLite database analysis and recovery toolkit.

**No API keys. No external services. Pure Python.**

## Features

- **Page-Level Inspection** — Hex dump + decoded page headers (btree pages, overflow pages, freelist)
- **WAL Journal Recovery** — Extract data from WAL files including uncommitted transactions
- **Deleted Row Scanning** — Recover freed records from unallocated space on database pages
- **Schema Visualization** — DDL extraction and dependency graph (Graphviz)
- **Corruption Detection** — Page-level integrity checks beyond `PRAGMA integrity_check`
- **Blob Carving** — Extract embedded files (images, documents) from BLOB fields
- **CSV/JSON Export** — Export recovered data in standard formats
- **HTML Report** — Interactive forensic report with expandable sections

## Quick Start

```bash
pip install sqlime  # coming soon

# Inspect a database
sqlime inspect path/to/database.db

# Scan for deleted records
sqlime recover path/to/database.db

# Generate a forensic report
sqlime report path/to/database.db -o report.html
```

## Why SQLime?

Existing tools (sqlite3 CLI, DB Browser, sqlite-utils) don't do forensics. They work on live, clean databases. SQLime is built for the adversarial case:

- Recover data after `DELETE` or `DROP TABLE`
- Extract data from corrupted or partially-overwritten databases
- Read WAL files that were never checkpointed
- Generate court-ready forensic reports

## License

MIT
