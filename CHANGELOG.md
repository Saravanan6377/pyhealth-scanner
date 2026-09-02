# Changelog

All notable changes to the PyHealth Scanner project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-28

### Added

- **Unified CLI Tool (`pyhealth`)**: Typer-based command-line interface with subcommands: `scan`, `quality`, `security`, `complexity`, `deps`, `docs`, `git`, `report`, and `version`.
- **Project Scanner Engine**: Scans directory structures, counts total and Python files, lines of code, detects large files ($\ge 10\text{ MiB}$), empty directories, and duplicate file groups.
- **Code Quality Analyzer**: Integrates Ruff static analysis, checks for long functions ($> 50$ lines), deep nesting ($> 4$ levels), `TODO`/`FIXME` comments, and duplicate function signatures.
- **Security Analyzer**: Integrates Bandit security linting and a native secret detection scanner (API keys, passwords, bearer tokens, JWTs, SSH private keys) with automatic secret redaction (`[REDACTED]`).
- **Complexity Analyzer**: Integrates Radon to calculate Maintainability Index ($0\text{--}100$), average function cyclomatic complexity, maximum cyclomatic complexity, and flags high-complexity functions ($> 10$).
- **Dependency Analyzer**: Performs AST import extraction, declared dependency mapping (`pyproject.toml`, `requirements.txt`, `setup.py`), unused/missing package detection, and project-scoped vulnerability audits via `pip-audit`.
- **Documentation Analyzer**: Performs AST analysis for public modules, classes, and top-level/method functions, docstring coverage calculation, and checks for required repository documentation (`README`, `LICENSE`, `CHANGELOG`, `CONTRIBUTING`).
- **Git Health Analyzer**: Read-only Git repository inspection. Checks for `.gitignore` presence, tracked/untracked file counts, sensitive tracked credential files (`.env`, `credentials.json`, `*.pem`, `*.key`), and large tracked files ($\ge 10\text{ MiB}$).
- **Unified Health Score Engine**: Centralized scoring engine calculating 0--100 scores across 7 categories (Security, Quality, Complexity, Dependencies, Documentation, Structure, Git), overall project score, letter grade (`Excellent`, `Good`, `Fair`, `Poor`, `Critical`), severity impact, category weighting, and priority recommendation ranking.
- **Unified Report Engine**: Multi-format reporting engine (`JsonReporter`, `MarkdownReporter`, `HtmlReporter`, `CsvReporter`, `SarifReporter`). Supports standard JSON, GitHub Flavored Markdown, self-contained offline HTML reports, CSV spreadsheets, SARIF v2.1.0 for GitHub Code Scanning, and `--format all` batch generation.
