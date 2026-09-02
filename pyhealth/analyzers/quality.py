"""Code quality analyser for PyHealth.

Combines Ruff (via subprocess JSON output) with Python-native ``ast``
and ``tokenize`` checks to produce a unified list of :class:`~pyhealth.models.Issue`
objects that downstream formatters and reporters can consume.
"""

from __future__ import annotations

import ast
import copy
import io
import json
import shutil
import subprocess
import sys
import tokenize
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from pyhealth.models import Issue, QualityResult, Severity
from pyhealth.scanner import IGNORED_DIRS

# ---------------------------------------------------------------------------
# Ruff severity mapping
# Keyed by rule-code prefix (longest match wins; see _ruff_severity()).
# ---------------------------------------------------------------------------

_RUFF_SEVERITY: dict[str, Severity] = {
    # Three-letter prefixes (checked before shorter ones)
    "ANN": Severity.INFO,    # annotations
    "ERA": Severity.INFO,    # commented-out code (eradicate)
    "RUF": Severity.LOW,     # ruff-specific rules
    # Two-letter prefixes
    "PL": Severity.MEDIUM,   # pylint
    "UP": Severity.LOW,      # pyupgrade
    # Single-letter prefixes
    "B": Severity.HIGH,      # flake8-bugbear
    "C": Severity.MEDIUM,    # convention / complexity
    "E": Severity.MEDIUM,    # pycodestyle errors
    "F": Severity.HIGH,      # pyflakes (undefined names, unused imports)
    "I": Severity.INFO,      # isort
    "N": Severity.LOW,       # pep8-naming
    "S": Severity.HIGH,      # bandit security rules
    "T": Severity.LOW,       # flake8-print / debugger statements
    "W": Severity.LOW,       # pycodestyle warnings
}

# Control-flow node types that increment nesting depth.
# ast.Match is available from Python 3.10, which is our minimum requirement.
_NESTING_TYPES = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.Match)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _ruff_severity(code: str) -> Severity:
    """Map a Ruff rule code to a :class:`~pyhealth.models.Severity`.

    Extracts the alphabetic prefix from *code* (e.g. ``"F401"`` → ``"F"``,
    ``"UP001"`` → ``"UP"``, ``"RUF100"`` → ``"RUF"``) and returns the
    longest-prefix match in :data:`_RUFF_SEVERITY`, falling back to
    :attr:`~pyhealth.models.Severity.INFO`.
    """
    prefix = ""
    for ch in code:
        if ch.isalpha():
            prefix += ch
        else:
            break
    for end in range(len(prefix), 0, -1):
        if prefix[:end] in _RUFF_SEVERITY:
            return _RUFF_SEVERITY[prefix[:end]]
    return Severity.INFO


def _get_control_bodies(node: ast.stmt) -> list[list[ast.stmt]]:
    """Return every statement-list body inside a control-flow *node*."""
    if isinstance(node, ast.If):
        return [node.body, node.orelse]
    if isinstance(node, (ast.For, ast.While)):
        return [node.body, node.orelse]
    if isinstance(node, ast.With):
        return [node.body]
    if isinstance(node, ast.Try):
        bodies: list[list[ast.stmt]] = [node.body]
        for handler in node.handlers:
            bodies.append(handler.body)
        if node.orelse:
            bodies.append(node.orelse)
        if node.finalbody:
            bodies.append(node.finalbody)
        return [b for b in bodies if b]
    if isinstance(node, ast.Match):
        return [case.body for case in node.cases]
    return []


def _max_nesting(stmts: list[ast.stmt], depth: int) -> int:
    """Return the maximum control-flow nesting depth within *stmts*.

    Only :data:`_NESTING_TYPES` nodes count as nesting levels.  All other
    statement types are visited transparently (they do not add depth).

    Args:
        stmts: The list of statements to inspect.
        depth: Current nesting depth entering this list.

    Returns:
        The maximum depth reached anywhere inside *stmts*.
    """
    max_d = depth
    for stmt in stmts:
        if isinstance(stmt, _NESTING_TYPES):
            inner = depth + 1
            max_d = max(max_d, inner)
            for body in _get_control_bodies(stmt):
                if body:
                    max_d = max(max_d, _max_nesting(body, inner))
    return max_d


# ---------------------------------------------------------------------------
# AST name normaliser (used by duplicate-function detection)
# ---------------------------------------------------------------------------


class _NameNormalizer(ast.NodeTransformer):
    """Replace ``Name``/``arg`` identifiers with positional tokens ``_v0``, ``_v1``, …

    Only the top-level function body is normalised; nested functions and
    class definitions are returned unchanged so they don't pollute the key.
    """

    def __init__(self) -> None:
        self._map: dict[str, str] = {}
        self._counter = 0

    def _token(self, name: str) -> str:
        if name not in self._map:
            self._map[name] = f"_v{self._counter}"
            self._counter += 1
        return self._map[name]

    def visit_Name(self, node: ast.Name) -> ast.Name:  # noqa: N802 – required interface
        return ast.Name(id=self._token(node.id), ctx=node.ctx)

    def visit_arg(self, node: ast.arg) -> ast.arg:  # noqa: N802
        return ast.arg(arg=self._token(node.arg))

    def visit_FunctionDef(  # noqa: N802
        self, node: ast.FunctionDef
    ) -> ast.FunctionDef:
        return node  # do not recurse into nested functions

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef
    ) -> ast.AsyncFunctionDef:
        return node  # do not recurse into nested async functions

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:  # noqa: N802
        return node  # do not recurse into nested classes


# ---------------------------------------------------------------------------
# QualityAnalyzer
# ---------------------------------------------------------------------------


class QualityAnalyzer:
    """Analyses code quality within a project directory.

    Runs the following checks:

    * **Ruff** — lint and style via machine-readable JSON output.
    * **PYH001** — long functions (default: > 80 lines).
    * **PYH002** — deep nesting (default: > 4 levels of control flow).
    * **PYH003** — TODO/FIXME comments (token-level; ignores string literals).
    * **PYH004** — duplicate function bodies across files.
    * **PYH005** — syntax errors that prevent AST parsing.

    All findings are normalised into :class:`~pyhealth.models.Issue` objects
    so that downstream formatters and future analysers share a single model.

    Args:
        root: Root directory to analyse.
        max_function_lines: PYH001 threshold.  Defaults to ``80``.
        max_nesting_depth: PYH002 threshold.  Defaults to ``4``.

    Example::

        from pathlib import Path
        from pyhealth.analyzers.quality import QualityAnalyzer

        result = QualityAnalyzer(Path(".")).analyze()
        print(f"{result.total_issues} issues found")
    """

    def __init__(
        self,
        root: Path,
        max_function_lines: int = 80,
        max_nesting_depth: int = 4,
    ) -> None:
        self.root = root
        self.max_function_lines = max_function_lines
        self.max_nesting_depth = max_nesting_depth

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> QualityResult:
        """Run all quality checks and return a :class:`~pyhealth.models.QualityResult`.

        A single unreadable or unparseable file never aborts the full scan;
        the error is recorded as a PYH005 issue and analysis continues.
        """
        py_files = self._collect_py_files()
        issues: list[Issue] = []
        ruff_count = 0
        long_count = 0
        nesting_count = 0
        todo_count = 0

        # --- Ruff (JSON output) ---
        ruff_issues = self._run_ruff()
        ruff_count = len(ruff_issues)
        issues.extend(ruff_issues)

        # --- Per-file: tokenize + AST ---
        for fp in py_files:
            source = self._read_source(fp)
            if source is None:
                continue

            # PYH003: TODO/FIXME (comment tokens only, not string literals)
            todo_issues = self._check_todos(source, str(fp))
            todo_count += len(todo_issues)
            issues.extend(todo_issues)

            # Parse AST; record PYH005 and move on if it fails
            try:
                tree = ast.parse(source, filename=str(fp))
            except SyntaxError as exc:
                issues.append(
                    Issue(
                        category="quality",
                        severity=Severity.HIGH,
                        code="PYH005",
                        message=f"Syntax error: {exc.msg}",
                        file=str(fp),
                        line=exc.lineno,
                        tool="pyhealth",
                    )
                )
                continue

            for node in ast.walk(tree):
                if not isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    continue

                # PYH001: long functions
                if (
                    hasattr(node, "end_lineno")
                    and node.end_lineno is not None
                ):
                    line_count = node.end_lineno - node.lineno + 1
                    if line_count > self.max_function_lines:
                        long_count += 1
                        issues.append(
                            Issue(
                                category="quality",
                                severity=Severity.MEDIUM,
                                code="PYH001",
                                message=(
                                    f"Function '{node.name}' is {line_count}"
                                    f" lines (max {self.max_function_lines})"
                                ),
                                file=str(fp),
                                line=node.lineno,
                                tool="pyhealth",
                                suggestion=(
                                    "Break into smaller, focused functions."
                                ),
                            )
                        )

                # PYH002: deep nesting
                depth = _max_nesting(node.body, 0)
                if depth > self.max_nesting_depth:
                    nesting_count += 1
                    issues.append(
                        Issue(
                            category="quality",
                            severity=Severity.MEDIUM,
                            code="PYH002",
                            message=(
                                f"Function '{node.name}' has nesting depth"
                                f" {depth} (max {self.max_nesting_depth})"
                            ),
                            file=str(fp),
                            line=node.lineno,
                            tool="pyhealth",
                            suggestion=(
                                "Reduce nesting with early returns or helper"
                                " functions."
                            ),
                        )
                    )

        # --- PYH004: duplicate functions (cross-file) ---
        dup_issues = self._check_duplicates(py_files)
        dup_count = len(dup_issues)
        issues.extend(dup_issues)

        return QualityResult(
            python_files=len(py_files),
            issues=issues,
            ruff_findings=ruff_count,
            long_functions=long_count,
            deep_nesting=nesting_count,
            todo_fixme_count=todo_count,
            duplicate_function_count=dup_count,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_py_files(self) -> list[Path]:
        return [
            entry
            for entry in self._walk(self.root)
            if entry.is_file() and entry.suffix == ".py"
        ]

    def _walk(self, path: Path) -> Iterator[Path]:
        """Recursively yield every non-ignored entry under *path*."""
        try:
            entries = sorted(path.iterdir())
        except PermissionError:
            return
        for entry in entries:
            if entry.is_dir():
                if entry.name in IGNORED_DIRS:
                    continue
                yield entry
                yield from self._walk(entry)
            else:
                yield entry

    def _read_source(self, path: Path) -> str | None:
        """Return the UTF-8 text of *path*, or ``None`` on any read error."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def _run_ruff(self) -> list[Issue]:
        """Run ``ruff check --output-format=json`` and return normalised Issues.

        Safe subprocess requirements satisfied:

        * No ``shell=True``.
        * Arguments passed as a list.
        * stdout/stderr captured separately.
        * Non-zero exit is expected when violations are found; handled
          by parsing stdout regardless of exit code.
        * Missing Ruff (``FileNotFoundError`` or ``SubprocessError``) returns
          an empty list rather than raising.
        * Malformed JSON returns an empty list.
        """
        ruff_exe = shutil.which("ruff")
        cmd: list[str] = (
            [ruff_exe, "check", "--output-format=json", str(self.root)]
            if ruff_exe
            else [
                sys.executable,
                "-m",
                "ruff",
                "check",
                "--output-format=json",
                str(self.root),
            ]
        )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return []

        stdout = proc.stdout.strip()
        if not stdout:
            return []

        try:
            findings = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        if not isinstance(findings, list):
            return []

        issues: list[Issue] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            code = str(finding.get("code") or "")
            message = str(finding.get("message") or "")
            filename = finding.get("filename")
            location = finding.get("location")
            row: int | None = None
            col: int | None = None
            if isinstance(location, dict):
                row = location.get("row")
                col = location.get("column")

            issues.append(
                Issue(
                    category="quality",
                    severity=_ruff_severity(code),
                    code=code,
                    message=message,
                    file=str(filename) if filename else None,
                    line=row,
                    column=col,
                    tool="ruff",
                )
            )
        return issues

    def _check_todos(self, source: str, filename: str) -> list[Issue]:
        """Detect TODO/FIXME inside *comment tokens only*.

        Uses Python's ``tokenize`` module so that TODO/FIXME inside string
        literals (e.g. ``message = "TODO: fix"``) are never flagged.
        Each comment token produces at most one :class:`Issue` even if both
        keywords appear in the same comment.
        """
        issues: list[Issue] = []
        try:
            tokens = tokenize.generate_tokens(io.StringIO(source).readline)
            for tok_type, tok_string, tok_start, _tok_end, _line in tokens:
                if tok_type != tokenize.COMMENT:
                    continue
                upper = tok_string.upper()
                for keyword in ("TODO", "FIXME"):
                    if keyword in upper:
                        issues.append(
                            Issue(
                                category="quality",
                                severity=Severity.INFO,
                                code="PYH003",
                                message=f"{keyword} comment found",
                                file=filename,
                                line=tok_start[0],
                                column=tok_start[1],
                                tool="pyhealth",
                            )
                        )
                        break  # one issue per comment token
        except tokenize.TokenError:
            pass
        return issues

    def _canonical_body(self, body: list[ast.stmt]) -> str:
        """Return a normalised canonical key for *body*.

        Steps:

        1. Skip a leading docstring (``ast.Expr`` whose value is a string
           constant).
        2. Require at least 2 remaining statements (trivial functions are not
           reported as duplicates).
        3. Deep-copy each statement and run :class:`_NameNormalizer` over it
           so that variable/parameter names do not affect the key.
        4. Concatenate ``ast.dump()`` output for all normalised statements.
        """
        stmts = body
        if (
            stmts
            and isinstance(stmts[0], ast.Expr)
            and isinstance(stmts[0].value, ast.Constant)
            and isinstance(stmts[0].value.value, str)
        ):
            stmts = stmts[1:]

        if len(stmts) < 2:
            return ""

        normalizer = _NameNormalizer()
        normalized = [normalizer.visit(copy.deepcopy(s)) for s in stmts]
        return "|".join(ast.dump(s) for s in normalized)

    def _check_duplicates(self, py_files: list[Path]) -> list[Issue]:
        """Find functions with identical (normalised) bodies across *py_files*.

        Detection strategy:

        1. Compute :meth:`_canonical_body` for every function definition.
        2. Group by canonical key.
        3. Any group with 2 or more members produces PYH004 issues (one per
           non-first occurrence).

        Methods and async functions are treated identically to plain functions.
        """
        groups: defaultdict[str, list[tuple[str, int, str]]] = defaultdict(
            list
        )

        for fp in py_files:
            source = self._read_source(fp)
            if source is None:
                continue
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    continue
                key = self._canonical_body(node.body)
                if key:
                    groups[key].append((str(fp), node.lineno, node.name))

        issues: list[Issue] = []
        for group in groups.values():
            if len(group) < 2:
                continue
            first_file, first_line, first_name = group[0]
            for dup_file, dup_line, dup_name in group[1:]:
                # Guard: skip if somehow the same (file, line) appears twice
                if dup_file == first_file and dup_line == first_line:
                    continue
                issues.append(
                    Issue(
                        category="quality",
                        severity=Severity.MEDIUM,
                        code="PYH004",
                        message=(
                            f"Function '{dup_name}' has a duplicate body"
                            f" (matches '{first_name}'"
                            f" at {first_file}:{first_line})"
                        ),
                        file=dup_file,
                        line=dup_line,
                        tool="pyhealth",
                        suggestion=(
                            "Extract shared logic into a reusable helper"
                            " function."
                        ),
                    )
                )
        return issues
