"""Complexity analyser for PyHealth using Radon."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import radon.complexity as cc
import radon.metrics as mi
from radon.visitors import Class, Function

from pyhealth.models import ComplexityResult, Issue, Severity
from pyhealth.scanner import IGNORED_DIRS


class ComplexityAnalyzer:
    """Analyses cyclomatic complexity and Maintainability Index of Python files.

    Uses Radon programmatically (via ``radon.complexity`` and ``radon.metrics``).

    Args:
        root: Root directory to analyse.
        max_cyclomatic_complexity: Threshold above which a function/method is
            flagged as high-complexity (default: 10).
    """

    def __init__(
        self,
        root: Path,
        max_cyclomatic_complexity: int = 10,
    ) -> None:
        self.root = root
        self.max_cyclomatic_complexity = max_cyclomatic_complexity

    def analyze(self) -> ComplexityResult:
        """Run complexity analysis across all non-ignored Python files."""
        py_files = self._collect_py_files()
        issues: list[Issue] = []
        functions_count = 0
        classes_count = 0
        total_cc = 0
        max_cc = 0
        high_cc_count = 0
        mi_scores: list[float] = []

        for fp in py_files:
            source = self._read_source(fp)
            if source is None:
                continue

            # Compute Maintainability Index (MI)
            try:
                raw_mi = mi.mi_visit(source, multi=True)
                # Normalize MI to 0.0 - 100.0 scale
                norm_mi = max(0.0, min(100.0, float(raw_mi)))
                mi_scores.append(norm_mi)
            except SyntaxError:
                pass

            # Compute Cyclomatic Complexity (CC)
            try:
                blocks = cc.cc_visit(source)
            except SyntaxError:
                continue

            for block in blocks:
                if isinstance(block, Class):
                    classes_count += 1
                elif isinstance(block, Function):
                    functions_count += 1
                    comp = block.complexity
                    total_cc += comp
                    if comp > max_cc:
                        max_cc = comp

                    if comp > self.max_cyclomatic_complexity:
                        high_cc_count += 1
                        severity = (
                            Severity.HIGH
                            if comp >= 14
                            else Severity.MEDIUM
                        )
                        msg = (
                            f"Function '{block.name}' has cyclomatic"
                            f" complexity {comp}. Configured maximum is"
                            f" {self.max_cyclomatic_complexity}."
                        )
                        issues.append(
                            Issue(
                                category="complexity",
                                severity=severity,
                                code="PYH101",
                                message=msg,
                                file=str(fp),
                                line=block.lineno,
                                tool="radon",
                                suggestion=(
                                    "Consider breaking this function into"
                                    " smaller units or simplifying conditional"
                                    " logic."
                                ),
                            )
                        )

        avg_cc = (
            round(total_cc / functions_count, 1)
            if functions_count > 0
            else 0.0
        )
        avg_mi = (
            round(sum(mi_scores) / len(mi_scores), 1)
            if mi_scores
            else 100.0
        )

        return ComplexityResult(
            python_files=len(py_files),
            issues=issues,
            functions_analyzed=functions_count,
            classes_analyzed=classes_count,
            average_complexity=avg_cc,
            max_complexity=max_cc,
            maintainability_index=avg_mi,
            high_complexity_findings=high_cc_count,
        )

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
        """Return the text of *path* decoded as UTF-8, or ``None`` on any read error."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
