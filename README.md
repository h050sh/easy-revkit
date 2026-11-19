# easy-revkit

[![CI](https://github.com/h050sh/easy-revkit/actions/workflows/ci.yml/badge.svg)](https://github.com/h050sh/easy-revkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**One command to triage any file.** `revkit` is a universal *static* reverse-engineering
triage tool: point it at a binary, script, archive or document and it tells you what it is,
what's interesting inside, and where to look next — hardcoded secrets, C2 URLs, auth/licence
check logic, crypto constants, embedded payloads and obfuscated script layers.

> [!IMPORTANT]
> revkit performs **static analysis only** — the sample is never executed.
> Still, always handle untrusted samples inside an isolated analysis VM.

---

## Features

| Area | What revkit does |
|------|------------------|
| **Native binaries** (PE x86/x64, ELF, Mach-O) | Imports & suspicious API families, Capstone disassembly, reconstructed auth/check logic (`strcmp`/`memcmp` against constants, inlined compares), stack strings, candidate hardcoded secrets, compiler/language hints (Rust, Go, Nim, Delphi), UPX detection |
| **.NET** | Metadata & `#US` heap strings per method, optional decompilation via `ilspycmd` |
| **PyInstaller / `.pyc`** | Archive extraction, marshal string recovery, optional decompilation (`pycdc` / `decompyle3`) |
| **Java / Android** (JAR, class, APK, DEX) | Constant-pool and DEX string extraction, optional `jadx` decompilation |
| **Scripts** (PowerShell, JS, VBS, batch, bash, Python) | Multi-layer deobfuscation (base64, gzip/deflate, char-codes, XOR brute force, …) |
| **Archives** (ZIP, TAR, GZ) | Recursive analysis with configurable depth |
| **Documents** (PDF, OLE/OOXML Office) | Flate stream decompression, embedded JavaScript, VBA macro extraction (`oletools`) |
| **Everything** | Hashes & entropy, classified strings (keys, tokens, JWTs, credentials, URLs, IPs, UNC paths, registry keys, hashes with hashcat modes), crypto constant detection (AES, SHA, MD5, TEA, ChaCha, RC4, …), file carving |
| **Ghidra** (optional) | Headless decompilation of only the functions that reference interesting strings |

Findings are ranked **HIGH / MED / INFO / LOW** and written to the terminal, `report.md` and `report.json`.

## Installation

```bash
git clone https://github.com/h050sh/easy-revkit.git
cd easy-revkit
pip install ".[full]"
```

| Install | Includes |
|---------|----------|
| `pip install .` | Core: `capstone`, `pefile` |
| `pip install ".[full]"` | Recommended: adds `lief`, `pyelftools`, `dnfile`, `oletools` |
| `pip install -e ".[full,dev]"` | Development: adds `pytest`, `ruff` |

No install needed for a quick run either — `revkit.py` is a single self-contained file:

```bash
python3 revkit.py sample.exe
```

### Optional external tools

revkit automatically uses these when they're on your `PATH`:

| Tool | Used for |
|------|----------|
| `upx` | Unpacking UPX-packed binaries |
| `ilspycmd` | .NET decompilation |
| `jadx` | Java / Android decompilation |
| `pycdc` / `decompyle3` | Python bytecode decompilation |
| Ghidra (`analyzeHeadless`, or set `GHIDRA_HOME`) | `--ghidra` decompilation |

## Usage

```text
revkit <file> [-o OUTDIR] [--ghidra] [--all-strings] [--carve] [--max-depth N]
```

| Option | Description |
|--------|-------------|
| `-o`, `--outdir` | Output directory (default: `<file>_revkit`) |
| `--ghidra` | Decompile relevant functions with Ghidra headless |
| `--all-strings` | Write every extracted string to `strings.txt` |
| `--carve` | Extract embedded files to `carved/` |
| `--max-depth N` | Recursion depth for archives / embedded files (default: 3) |
| `-V`, `--version` | Show version and exit |

### Examples

```bash
# Crackme / CTF binary
revkit crackme.exe

# Suspicious document, extracting anything embedded
revkit invoice.docm --carve

# Deep dive with Ghidra decompilation
revkit implant.elf --ghidra -o analysis/implant
```

### Output

```text
<outdir>/
├── report.md         # human-readable report
├── report.json       # machine-readable: meta, findings, sections
├── strings.txt       # with --all-strings
├── carved/           # with --carve
└── ghidra_decompiled.c   # with --ghidra
```

Set `NO_COLOR=1` to disable coloured terminal output. Note that the tool's console output and
reports are currently in Dutch.

## Development

```bash
pip install -e ".[full,dev]"
ruff check .
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Disclaimer

revkit is intended for malware analysis, incident response, CTFs, education and authorised
security research. Only analyse software you are permitted to analyse.

## License

[MIT](LICENSE) © Haider
