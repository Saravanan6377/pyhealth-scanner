# Contributing to PyHealth Scanner

Thank you for your interest in contributing to PyHealth Scanner!

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/pyhealth-scanner/pyhealth-scanner.git
   cd pyhealth-scanner
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install PyHealth in editable mode with development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

## Running Tests

Run the full test suite with `pytest`:

```bash
pytest
```

To run with coverage reporting:

```bash
pytest --cov=pyhealth
```

## Code Quality & Linting

PyHealth uses [Ruff](https://github.com/astral-sh/ruff) for code formatting and linting rules.

To run Ruff checks:

```bash
python -m ruff check .
```

To automatically fix formatting or safe lint warnings:

```bash
python -m ruff check --fix .
```

## Building the Package

To build the wheel and source distribution artifacts locally:

```bash
python -m build
```

The built artifacts will be available in the `dist/` directory:
- `dist/pyhealth-2.0.0-py3-none-any.whl`
- `dist/pyhealth-2.0.0.tar.gz`

## Coding Standards

- **Python Compatibility**: Target Python 3.10+.
- **Type Annotations**: Use static type hints throughout code modules (`from __future__ import annotations`).
- **Docstrings**: Include clear Google-style docstrings for public classes, functions, and modules.
- **Privacy & Redaction**: Ensure hardcoded secrets and sensitive credentials are NEVER logged or exposed in raw form in reports.
- **Offline HTML**: Keep `HtmlReporter` fully self-contained without external network, CDN, font, or script dependencies.
- **Deterministic Reporting**: Ensure report outputs remain deterministic and predictable.

## Pull Request Guidelines

1. Ensure all 240+ tests pass (`pytest`).
2. Ensure Ruff check passes with 0 errors (`python -m ruff check .`).
3. Ensure package builds cleanly (`python -m build`).
4. Update `CHANGELOG.md` for major changes or new capabilities.
