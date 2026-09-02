# PyHealth Scanner

[![PyPI version](https://img.shields.io/pypi/v/pyhealth-scanner)](https://pypi.org/project/pyhealth-scanner/)
[![Python](https://img.shields.io/pypi/pyversions/pyhealth-scanner)](https://pypi.org/project/pyhealth-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Production Ready](https://img.shields.io/badge/status-production--ready-brightgreen)](https://github.com/Saravanan6377/pyhealth-scanner)
**A unified Python project health analyzer.**

PyHealth Scanner is a single command that inspects your Python project from every angle — code quality, security, dependencies, documentation, complexity, and more — and gives you an actionable health report.

---

## Version

**Current version: 2.0.0** — Production Ready

> PyHealth Scanner 2.0.0 provides a unified analysis suite covering code quality, security, complexity, dependencies, documentation, Git health, health scoring, and multi-format reporting.

---

## Project Status

| Feature | Status |
|---|---|
| Package foundation | ✅ Available |
| CLI (`pyhealth version`, `pyhealth scan`) | ✅ Available |
| Code quality analysis (Ruff) | ✅ Available |
| Security scanning (Bandit + Native Scanner) | ✅ Available |
| Complexity analysis (Radon) | ✅ Available |
| Dependency analysis (pip-audit & AST) | ✅ Available |
| Documentation analysis | ✅ Available |
| Git health analysis | ✅ Available |
| Health scoring | ✅ Available |
| Reports (JSON, HTML, Markdown, CSV, SARIF) | ✅ Available |

---

## Unified Report Engine

PyHealth includes a report generator capable of outputting reports in JSON, Markdown, HTML, CSV, and SARIF v2.1.0 formats.

```bash
# Render to console (default)
pyhealth report .

# Output formatted JSON
pyhealth report . --format json

# Output Markdown report
pyhealth report . --format markdown --output report.md

# Generate self-contained offline HTML report
pyhealth report . --format html --output report.html

# Export findings to CSV
pyhealth report . --format csv --output report.csv

# Export SARIF for GitHub Code Scanning / CI/CD
pyhealth report . --format sarif --output results.sarif

# Generate all report formats at once
pyhealth report . --format all --output reports/
```

### Supported Report Formats

- **`console`**: Rich CLI summary display (same as `pyhealth scan .`).
- **`json`**: Complete, deterministic JSON dataset of project metrics, health score, category scores, and sanitized issues.
- **`markdown`**: GitHub Flavored Markdown report with executive summary, category table, recommendations, and detailed findings.
- **`html`**: Self-contained, responsive, offline HTML report with embedded styling. Zero external network/CDN dependencies.
- **`csv`**: Standard CSV spreadsheet export with one row per issue (`category,severity,code,message,file,line,column,tool,suggestion`).
- **`sarif`**: Standard SARIF v2.1.0 JSON format for GitHub Security Scanning and CI/CD code analysis pipelines.
- **`all`**: Generates `report.json`, `report.md`, `report.html`, `report.csv`, and `report.sarif` in one pass.

### Single Analysis Execution & Privacy

When generating reports (including `--format all`), PyHealth Scanner executes project analyzers **exactly once** and feeds the unified `ProjectReport` model to the requested renderers. All report formats strictly preserve the secret-privacy guarantee: actual password, key, and token contents are never exposed.

---

## Unified Health Score Engine

The Health Score Engine evaluates all analyzer results to calculate a weighted 0–100 overall score, PyHealth Grade, category scores, top priority issues, and deduplicated recommendations.

### PyHealth Grade Interpretation

- **90–100**: Excellent
- **80–89**: Good
- **70–79**: Fair
- **50–69**: Needs Improvement
- **0–49**: Poor

> **Disclaimer**: The PyHealth score is an opinionated engineering metric designed to help prioritize improvements. It is not a formal or industry-standard software quality measurement.

### Category Weights

Default category weights sum to `1.00`:

| Category | Default Weight | Key Inputs |
|---|---|---|
| Security | `0.30` | Bandit findings, native secret findings (`PYSxxx`) |
| Quality | `0.20` | Ruff lints, long functions, deep nesting, TODO/FIXME, duplicates, syntax errors |
| Complexity | `0.15` | Maintainability Index (MI), high complexity findings (`PYH101`) |
| Dependencies | `0.15` | Vulnerabilities (`PYH203`), missing deps (`PYH202`), unused deps (`PYH201`) |
| Documentation | `0.10` | Docstring coverage %, required doc files (`README`, `LICENSE`, etc.) |
| Structure | `0.05` | Large files, empty directories, duplicate file groups |
| Git | `0.05` | `.gitignore` presence, large tracked files, sensitive tracked files |

### Custom Category Weights Configuration

Configure custom weights in `pyproject.toml`:

```toml
[tool.pyhealth.score]
security = 0.30
quality = 0.20
complexity = 0.15
dependencies = 0.15
documentation = 0.10
structure = 0.05
git = 0.05
```

Custom weights must be numeric, non-negative, and sum to `1.0` within `0.0001`.

### Unavailable Categories

If a category is unavailable (for instance, if the analysis path is not inside a Git repository), PyHealth marks `Git: N/A` and excludes its weight from the denominator rather than penalizing the project with a zero score.

---

## Git Health Analysis

Analyze Git repository status, `.gitignore` presence, tracked/untracked file counts, branch/commit metadata, large tracked files (`>= 10 MiB`), and sensitive tracked filenames:

```bash
pyhealth git .
```

### Features & Security Rules

- **Read-Only Guarantee**: PyHealth **never** modifies repository state, tracked files, or `.gitignore`. It never creates commits, resets branches, or rewrites Git history.
- **Repository & Worktree Detection**: Detects `.git` directories and Git worktrees safely. If the path is not inside a Git repository, PyHealth reports `Repository: ✗` without crashing.
- **`.gitignore` Check**: Emits `PYH401` if `.gitignore` is missing at the project root.
- **Large Tracked Files**: Flags tracked files whose size is $\ge 10\text{ MiB}$ ($10,485,760\text{ bytes}$) with `PYH402` (MEDIUM severity).
- **Sensitive Tracked Filenames**: Screens tracked filenames/paths against sensitive patterns (`.env`, `.env.*`, `credentials.json`, `secrets.json`, `*.pem`, `*.key`, `id_rsa`, `*.p12`, `*.pfx`) and emits `PYH403` (HIGH severity). **File contents are never inspected or printed.**
- **Safe Subprocess Execution**: Executes `git` commands safely using `subprocess.run` with list arguments and `shell=False`. Parses NUL-delimited (`\0`) path lists to support spaces, tabs, and Unicode in filenames.

### Git Health Limitations

- **Filename-Based Screening Only**: Sensitive file screening in Git health analysis is based on filename/path pattern matching. Deep content-based secret scanning is handled separately by Stage 4 (Security Analyzer).
- **Local Environment Dependent**: Git statistics (branch name, commit count, untracked files) rely on the local `git` CLI executable being installed and accessible in `PATH`.

---

## Documentation Analysis

Analyze project documentation files (`README.md`, `LICENSE`, `CHANGELOG.md`, `CONTRIBUTING.md`) and Python docstring coverage for public APIs:

```bash
pyhealth docs .
```

### Docstring Coverage Formula

Docstring coverage is calculated across all public objects as:

$$\text{Docstring Coverage} = \frac{\text{documented public objects}}{\text{total public objects}} \times 100$$

Where `total public objects` = public modules + public classes + public functions (including public methods).

### Public vs. Private Object Rules

- **Public Modules**: Python files whose stem does not start with `_` (analyzed under standard `IGNORED_DIRS` rules).
- **Public Classes**: Classes defined at module level or inside public classes whose name does not start with `_`.
- **Public Functions**: Top-level functions whose name does not start with `_`. Nested local functions inside another function are excluded from public API counts.
- **Public Methods**: Methods defined directly inside a public class whose name does not start with `_` (e.g. `def run(self):` is public; `def _helper(self):` is private).
- **Private Objects**: Any object or file starting with an underscore `_` (including dunder methods like `__init__`) is excluded from documentation requirements.

### Documentation Analysis Limitations

- **Static Metric Only**: Docstring coverage is a simple static metric that checks for docstring presence; it does not grade the quality, accuracy, or clarity of the written text.
- **File Matching**: Documentation file presence checks for standard file names (`README.md`, `LICENSE`, etc.) and common case-insensitive variations. Custom documentation layouts or non-standard file names may not be automatically detected.
- **README Quality**: README completeness checks verify basic presence and structural content (description, setup, usage instructions) without performing natural-language understanding.

---

## Dependency Analysis Limitations

Dependency analysis in PyHealth is designed to be safe, conservative, and non-destructive:

- **Heuristic Unused Detection**: "Unused dependency" findings are heuristic. Packages required indirectly, dynamically via `importlib`, through plugins, or in optional features may not appear as direct imports in static AST code analysis.
- **Import vs. Distribution Mismatches**: Top-level import names do not always match PyPI distribution names (e.g. `import PIL` -> `Pillow`). Common mismatches are mapped automatically, but custom or rare mappings may not be covered.
- **Dynamic Imports**: Dynamic `__import__()` or `importlib.import_module()` calls are not evaluated statically.
- **Development & Optional Dependencies**: Development dependencies (e.g., `pytest`, `ruff`) and optional extras are tracked separately and are not flagged as unused.
- **Safe `setup.py` Parsing**: `setup.py` files are parsed statically using regex patterns. PyHealth **never** executes arbitrary `setup.py` code.


---

## What PyHealth Will Do

With PyHealth Scanner 2.0.0, a single `pyhealth scan .` can:

- **Analyze code quality** — lint errors, style violations, and complexity hotspots.
- **Audit security** — known vulnerability patterns and insecure coding practices.
- **Inspect dependencies** — outdated packages, missing pins, and license risks.
- **Review documentation** — missing docstrings, incomplete README, and coverage gaps.
- **Assess Git health** — stale branches, large files, and commit hygiene.
- **Suggest cleanups** — dead code, unused imports, and temporary files.
- **Score overall health** — a single 0–100 project health score with trend tracking.
- **Export reports** — Console, JSON, HTML, Markdown, CSV, and SARIF formats.

---

## Installation

### From PyPI

```bash
pip install pyhealth-scanner
```

### From Source

```bash
git clone https://github.com/pyhealth-scanner/pyhealth-scanner.git
cd pyhealth-scanner
pip install .
```

---

## Usage

```bash
# Show version
pyhealth version

# Scan the current directory (full analysis — available in Stage 2+)
pyhealth scan .

# Scan a specific project
pyhealth scan /path/to/your/project

# Show all commands and options
pyhealth --help
```

---

## Development Setup

Requires **Python 3.10 or later**.

```bash
# Clone the repository
git clone https://github.com/Saravanan6377/pyhealth-scanner.git
cd pyhealth-scanner

# Create and activate a virtual environment (recommended)
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install in editable mode with development dependencies
python -m pip install -e ".[dev]"
```

---

## Running Tests

```bash
pytest
```

To run tests with a coverage report:

```bash
pytest --cov=pyhealth --cov-report=term-missing
```

---

## Building the Package

```bash
python -m build
```

This produces:

```
dist/
├── pyhealth_scanner-2.0.0.tar.gz
└── pyhealth_scanner-2.0.0-py3-none-any.whl
```

---

## Contributing

Contributions, bug reports, and feature requests are welcome!

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Make your changes and add tests.
4. Ensure all tests pass (`pytest`).
5. Run the linter (`ruff check .`).
6. Open a pull request.

---

## License

This project is licensed under the [MIT License](LICENSE).
