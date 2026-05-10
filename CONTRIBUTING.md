# Contributing

Thanks for your interest in SQLime! 🕵️‍♂️

This project is a SQLite forensic toolkit that aims to stay **zero-dependency** — pure Python, stdlib only. Every contribution should respect that constraint.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Luv-Goel/sqlime.git
cd sqlime

# Install in editable mode
pip install -e .

# Verify it works
sqlime --version
sqlime inspect tests/create_test_db.py  # or point it at any .db
```

## Development

### Code style

We use [ruff](https://docs.astral.sh/ruff/) for formatting and linting. There's no config file — the defaults are fine. Just run:

```bash
pip install ruff
ruff check sqlime/ --ignore=E501
```

Line-length warnings (E501) are intentionally ignored for readability in forensic output strings.

### Testing

Tests live in `tests/`. We use plain `pytest`:

```bash
pip install pytest
python -m pytest tests/ -v
```

Before pushing, make sure:
- Existing tests pass
- Any new functionality has reasonable test coverage
- The import chain works (`python -c "import sqlime"`)

### Project structure

```
sqlime/
├── sqlime/
│   ├── __init__.py   # Version + package metadata
│   ├── cli.py        # CLI entry point (argparse)
│   ├── pages.py      # Page-level read / decode / hex dump
│   ├── hexdump.py    # Dedicated hex dump viewer with search/annotate
│   ├── recovery.py   # Deleted-row (ghost record) scanning
│   ├── wal.py        # WAL journal parsing
│   ├── carve.py      # BLOB carving (30+ magic signatures)
│   ├── schema.py     # Schema extraction + Graphviz DOT output
│   ├── check.py      # Integrity checks, corruption scanning
│   ├── export.py     # CSV / JSON / SQL export
│   ├── report.py     # HTML forensic report generation
│   └── tui.py        # Interactive terminal UI
├── tests/
│   └── ...           # pytest test files
├── pyproject.toml
├── CONTRIBUTING.md
└── README.md
```

## Adding a feature

1. **New subcommand?** Wire it into `cli.py` — add the parser in `main()` and a dispatch in the `if args.command ==` chain. Put the business logic in a dedicated module under `sqlime/`.

2. **New forensic analysis?** Keep it in a focused module. If it analyses pages, it probably goes near `pages.py`; if it recovers data, near `recovery.py`.

3. **No new dependencies.** If you need a library, implement the subset you need inline. SQLime's selling point is that it works offline with zero `pip install` friction.

## Commit conventions

We don't enforce strict conventional commits, but descriptive messages help:

```
good:  feat: add hexdump page range search
bad:   update stuff
good:  fix: handle 65536-byte page size edge case
```

## Pull requests

- Open early, even if the feature is incomplete — feedback is welcome.
- Keep PRs focused on one thing. Multiple features → multiple PRs.
- Update the README if you add or change user-facing behaviour.
- Make sure CI is green.

## Questions?

Open an issue! We're friendly.
