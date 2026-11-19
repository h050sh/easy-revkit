# Contributing

Thanks for your interest in improving revkit!

## Setup

```bash
git clone https://github.com/h050sh/easy-revkit.git
cd easy-revkit
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[full,dev]"
```

## Before opening a pull request

```bash
ruff check .
pytest
```

- Keep revkit a **single, self-contained file** (`revkit.py`) so it can still be dropped onto an analysis VM and run without installing.
- revkit must remain **static-only**: never execute, load or import the sample being analysed.
- New format handlers or string rules should come with a test in `tests/`.
- **Never commit real malware samples.** Generate small synthetic test inputs inside the test instead.
- Keep optional dependencies optional: guard imports with `try/except ImportError` and degrade gracefully.

## Reporting bugs

Open an issue with the revkit version (`revkit --version`), your OS/Python version, the file
type and the full error output. Do not attach live malware; share a hash instead.
