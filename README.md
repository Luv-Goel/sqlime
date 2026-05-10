# SQLime ðŸ•µï¸

<div align="center">

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-lightgrey)]()

**SQLite forensic inspection and recovery toolkit â€” page inspection, ghost records, WAL analysis, BLOB carving. Zero dependencies.**

</div>

---

## Features

- **Database inspection** â€” Tables, indices, views, triggers, foreign keys, schema overview
- **Page-level analysis** â€” Inspect individual database pages, B-tree structure
- **Integrity check** â€” Full database integrity verification with detailed reporting
- **Ghost record recovery** â€” Recover deleted records from free pages and unallocated space
- **WAL journal analysis** â€” Read WAL frames, checkpoints, rollback investigation
- **BLOB carving** â€” Extract embedded files using 30+ magic byte signatures (PNG, JPEG, PDF, ZIP, etc.)
- **Multiple export formats** â€” CSV, JSON, SQL INSERT statements for recovered data
- **HTML forensic reports** â€” Professional reports suitable for evidence documentation
- **Zero dependencies** â€” Pure Python 3.8+, stdlib only
- **No API keys required** â€” Completely offline, works with any SQLite database

## Quick Start

```bash
pip install sqlime-forensics

# Inspect database
sqlime inspect database.db

# Show schema
sqlime schema database.db

# Integrity check
sqlime check database.db

# Recover deleted records
sqlime recover database.db --output recovered.csv

# Analyze WAL journal
sqlime wal database.db-wal

# Carve embedded files
sqlime export database.db --output ./carved_files

# HTML forensic report
sqlime report database.db --output report.html
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `sqlime inspect [db]` | Database metadata and schema overview |
| `sqlime schema [db]` | Full schema with DDL for all objects |
| `sqlime check [db]` | Database integrity verification |
| `sqlime recover [db]` | Ghost record recovery from free pages |
| `sqlime wal [file]` | WAL journal analysis |
| `sqlime export [db]` | BLOB carving and file extraction |
| `sqlime report [db]` | Full forensic HTML report |

## Key Features in Detail

### Ghost Record Recovery
Recovers deleted or overwritten records from SQLite's free pages, unallocated space, and page fragmentation. Supports CSV, JSON, and SQL output formats for recovered data.

### WAL Journal Analysis
Reads Write-Ahead Log (WAL) files to recover data from uncheckpointed transactions, analyze rollback states, and reconstruct database history.

### BLOB Carving
Extracts embedded files using signature-based carving with 30+ magic byte patterns:
- Images: PNG, JPEG, GIF, BMP, TIFF, WEBP
- Documents: PDF, DOC, DOCX, XLS, XLSX
- Archives: ZIP, GZIP, TAR, RAR, 7Z
- Media: MP3, MP4, AVI, WAV, FLAC
- Data: SQLite DB, JSON, XML

## Architecture

```
sqlime/
â”œâ”€â”€ sqlime/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ cli.py       # CLI entry point
â”‚   â”œâ”€â”€ core.py      # Database operations
â”‚   â”œâ”€â”€ recovery.py  # Ghost record recovery
â”‚   â”œâ”€â”€ wal.py       # WAL journal analysis
â”‚   â”œâ”€â”€ carve.py     # BLOB carving engine
â”‚   â””â”€â”€ report.py    # HTML report generation
â”œâ”€â”€ pyproject.toml
â””â”€â”€ README.md
```

## License

MIT â€” see [LICENSE](LICENSE).
