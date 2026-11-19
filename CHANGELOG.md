# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-19

### Added
- Packaging via `pyproject.toml` with a `revkit` console command and a `[full]` extra.
- `--version` flag and a clear error when the input file does not exist.
- Test suite (pytest) and GitHub Actions CI (ruff + tests on Linux, macOS, Windows).
- README, license (MIT), contributing guide, security policy and issue/PR templates.

### Changed
- Removed an unused import and dead code paths.

### Initial feature set
- Static triage for PE, ELF, Mach-O, .NET, PyInstaller, Java/Android, Python bytecode,
  scripts, archives, PDF and Office documents, with Markdown and JSON reports.
