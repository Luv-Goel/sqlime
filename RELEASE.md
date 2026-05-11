# SQLime v0.1.0 — SQLite Forensic Toolkit

**Inspect, recover, and analyze SQLite databases like a digital forensics expert.**

## What's Inside

### 7 CLI Commands
| Command | What it does |
|---------|-------------|
| `sqlime inspect` | Full database page-level inspection + hex dump |
| `sqlime schema` | Schema extraction + Graphviz DOT graph export |
| `sqlime check` | PRAGMA integrity checks + corruption scanning |
| `sqlime recover` | Deleted row recovery + WAL analysis + BLOB carving |
| `sqlime wal` | Standalone WAL journal file analysis |
| `sqlime export` | Multi-format export (CSV, JSON, SQL DDL) |
| `sqlime report` | Generate standalone forensic HTML report |

### Core Features
- **Page-level hex dump** with ASCII sidebar and offset markers
- **Page header decoding** — type, cell count, freeblock chain, cell content region
- **Deleted row recovery** — scans freeblocks and unallocated space for ghost records
- **WAL journal parsing** — read WAL headers, frames, and extract historical page data
- **BLOB carving** — detect 30+ file types by magic bytes, extract to disk
- **Schema visualization** — DOT graph export, column-level detail with constraints
- **Foreign key detection** — auto-detect FK relationships from schema
- **Integrity scanning** — PRAGMA integrity_check + page-level structural validation
- **HTML forensic reports** — standalone with status cards, tables, navigation

### Technical
- Zero API keys required
- Zero external dependencies (stdlib-only)
- Pure Python, cross-platform
- MIT License

## Quick Start
```bash
pip install sqlime
sqlime inspect chat.db
sqlime check chat.db
sqlime recover chat.db --deleted
sqlime report chat.db -o report.html
```
