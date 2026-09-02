"""Documentation analyzer for PyHealth.

Checks project documentation files (README, LICENSE, CHANGELOG, CONTRIBUTING)
and calculates Python docstring coverage for public modules, classes, functions,
and methods.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from pyhealth.models import DocumentationResult, Issue, Severity
from pyhealth.scanner import IGNORED_DIRS

# Document file patterns (case-insensitive stem matching)
_README_PATTERNS = {"readme"}
_LICENSE_PATTERNS = {"license", "copying"}
_CHANGELOG_PATTERNS = {"changelog", "history"}
_CONTRIBUTING_PATTERNS = {"contributing"}


class DocumentationAnalyzer:
    """Analyzes project documentation files and Python docstring coverage.

    Args:
        root: Root directory of the project to analyze.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def analyze(self) -> DocumentationResult:
        """Run documentation checks and return aggregated results."""
        issues: list[Issue] = []

        # 1. Documentation files check
        readme_path, readme_exists = self._find_doc_file(_README_PATTERNS)
        _, license_exists = self._find_doc_file(_LICENSE_PATTERNS)
        _, changelog_exists = self._find_doc_file(_CHANGELOG_PATTERNS)
        _, contributing_exists = self._find_doc_file(_CONTRIBUTING_PATTERNS)

        if not readme_exists:
            issues.append(
                Issue(
                    category="documentation",
                    severity=Severity.HIGH,
                    code="PYH301",
                    message="README file is missing.",
                    tool="pyhealth",
                    suggestion=(
                        "Add a README describing the project, installation, "
                        "usage, development setup, and licensing."
                    ),
                )
            )
        elif readme_path is not None:
            # Minimal/incomplete README check
            if self._is_readme_minimal(readme_path):
                issues.append(
                    Issue(
                        category="documentation",
                        severity=Severity.MEDIUM,
                        code="PYH301",
                        file=str(readme_path.relative_to(self.root)),
                        message="README file exists but is minimal or incomplete.",
                        tool="pyhealth",
                        suggestion=(
                            "Expand the README to include project description, "
                            "installation, and usage instructions."
                        ),
                    )
                )

        if not license_exists:
            issues.append(
                Issue(
                    category="documentation",
                    severity=Severity.HIGH,
                    code="PYH302",
                    message="LICENSE file is missing.",
                    tool="pyhealth",
                    suggestion=(
                        "Add a LICENSE file specifying open-source "
                        "or proprietary usage rights."
                    ),
                )
            )

        if not changelog_exists:
            issues.append(
                Issue(
                    category="documentation",
                    severity=Severity.LOW,
                    code="PYH303",
                    message="CHANGELOG file is missing.",
                    tool="pyhealth",
                    suggestion=(
                        "Add a CHANGELOG file to document notable changes "
                        "for each release."
                    ),
                )
            )

        if not contributing_exists:
            issues.append(
                Issue(
                    category="documentation",
                    severity=Severity.INFO,
                    code="PYH304",
                    message="CONTRIBUTING file is missing.",
                    tool="pyhealth",
                    suggestion=(
                        "Add a CONTRIBUTING file to guide contributors "
                        "on how to submit changes."
                    ),
                )
            )

        # 2. Python AST Docstring Analysis
        py_files = self._collect_py_files()
        files_analyzed = 0
        public_modules = 0
        public_classes = 0
        public_functions = 0
        documented_objects = 0

        for fp in py_files:
            rel_path = str(fp.relative_to(self.root))
            try:
                source = fp.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue

            files_analyzed += 1
            is_public_module = not fp.stem.startswith("_")

            mod_classes, mod_funcs, mod_docs, mod_issues, is_mod_doc_counted = (
                self._analyze_module_ast(tree, rel_path, is_public_module, fp.stem)
            )

            if is_mod_doc_counted:
                public_modules += 1

            public_classes += mod_classes
            public_functions += mod_funcs
            documented_objects += mod_docs
            issues.extend(mod_issues)

        total_public_objects = public_modules + public_classes + public_functions
        if total_public_objects > 0:
            docstring_coverage = (documented_objects / total_public_objects) * 100.0
        else:
            docstring_coverage = 100.0

        return DocumentationResult(
            issues=issues,
            files_analyzed=files_analyzed,
            public_modules=public_modules,
            public_classes=public_classes,
            public_functions=public_functions,
            documented_objects=documented_objects,
            docstring_coverage=round(docstring_coverage, 1),
            readme_exists=readme_exists,
            license_exists=license_exists,
            changelog_exists=changelog_exists,
            contributing_exists=contributing_exists,
        )

    def _find_doc_file(self, pattern_stems: set[str]) -> tuple[Path | None, bool]:
        """Check if any file in root matches the pattern stems case-insensitively."""
        try:
            entries = list(self.root.iterdir())
        except (PermissionError, OSError):
            return None, False

        for entry in entries:
            if entry.is_file():
                stem_lower = entry.stem.lower()
                name_lower = entry.name.lower()
                if stem_lower in pattern_stems or name_lower in pattern_stems:
                    return entry, True
        return None, False

    def _is_readme_minimal(self, path: Path) -> bool:
        """Check if README file is minimal or lacks essential content."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return True

        if not text:
            return True

        words = text.split()
        if len(words) < 20:
            return True

        lower_text = text.lower()
        has_install = "install" in lower_text or "setup" in lower_text
        has_usage = (
            "usage" in lower_text
            or "example" in lower_text
            or "quickstart" in lower_text
        )
        if not (has_install or has_usage):
            return True

        return False

    def _collect_py_files(self) -> list[Path]:
        return [
            entry
            for entry in self._walk(self.root)
            if entry.is_file() and entry.suffix == ".py"
        ]

    def _walk(self, path: Path) -> Iterator[Path]:
        try:
            entries = sorted(path.iterdir())
        except (PermissionError, OSError):
            return
        for entry in entries:
            if entry.is_dir():
                if entry.name in IGNORED_DIRS:
                    continue
                yield entry
                yield from self._walk(entry)
            else:
                yield entry

    def _analyze_module_ast(
        self, tree: ast.Module, rel_path: str, is_public_module: bool, stem: str
    ) -> tuple[int, int, int, list[Issue], bool]:
        """Analyze AST for public modules, classes, functions, and methods."""
        classes_count = 0
        funcs_count = 0
        docs_count = 0
        issues: list[Issue] = []
        is_mod_doc_counted = False

        # First collect classes and top-level functions
        top_level_funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        classes: list[ast.ClassDef] = []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_"):
                    top_level_funcs.append(node)
            elif isinstance(node, ast.ClassDef):
                if not node.name.startswith("_"):
                    classes.append(node)

        # Check module docstring requirement
        if is_public_module:
            # Empty module with 0 public objects does not require a docstring
            has_public_objects = bool(top_level_funcs or classes)
            is_empty_module = len(tree.body) == 0

            if not (is_empty_module and not has_public_objects):
                is_mod_doc_counted = True
                mod_doc = ast.get_docstring(tree)
                if mod_doc:
                    docs_count += 1
                else:
                    issues.append(
                        Issue(
                            category="documentation",
                            severity=Severity.LOW,
                            code="PYH305",
                            message=f"Public module '{stem}' has no docstring.",
                            file=rel_path,
                            line=1,
                            tool="pyhealth",
                            suggestion=(
                                "Document the module's overall purpose and "
                                "key components."
                            ),
                        )
                    )

        # Analyze top-level public functions
        for func_node in top_level_funcs:
            funcs_count += 1
            doc = ast.get_docstring(func_node)
            if doc:
                docs_count += 1
            else:
                issues.append(
                    Issue(
                        category="documentation",
                        severity=Severity.LOW,
                        code="PYH305",
                        message=f"Public function '{func_node.name}' has no docstring.",
                        file=rel_path,
                        line=func_node.lineno,
                        tool="pyhealth",
                        suggestion=(
                            "Document the function's purpose, parameters, "
                            "return value, and important exceptions."
                        ),
                    )
                )

        # Analyze classes (and methods inside them)
        for class_node in classes:
            c_cnt, f_cnt, d_cnt, c_issues = self._analyze_class_node(
                class_node, rel_path
            )
            classes_count += c_cnt
            funcs_count += f_cnt
            docs_count += d_cnt
            issues.extend(c_issues)

        return classes_count, funcs_count, docs_count, issues, is_mod_doc_counted

    def _analyze_class_node(
        self, class_node: ast.ClassDef, rel_path: str
    ) -> tuple[int, int, int, list[Issue]]:
        """Analyze a public class and its public methods/nested classes."""
        classes_count = 1
        funcs_count = 0
        docs_count = 0
        issues: list[Issue] = []

        doc = ast.get_docstring(class_node)
        if doc:
            docs_count += 1
        else:
            issues.append(
                Issue(
                    category="documentation",
                    severity=Severity.LOW,
                    code="PYH305",
                    message=f"Public class '{class_node.name}' has no docstring.",
                    file=rel_path,
                    line=class_node.lineno,
                    tool="pyhealth",
                    suggestion="Document the class's purpose, attributes, and usage.",
                )
            )

        for item in class_node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not item.name.startswith("_"):
                    funcs_count += 1
                    m_doc = ast.get_docstring(item)
                    if m_doc:
                        docs_count += 1
                    else:
                        issues.append(
                            Issue(
                                category="documentation",
                                severity=Severity.LOW,
                                code="PYH305",
                                message=(
                            f"Public method '{item.name}' has no docstring."
                        ),
                                file=rel_path,
                                line=item.lineno,
                                tool="pyhealth",
                                suggestion=(
                                    "Document the method's purpose, parameters, "
                                    "return value, and important exceptions."
                                ),
                            )
                        )
            elif isinstance(item, ast.ClassDef):
                if not item.name.startswith("_"):
                    c_cnt, f_cnt, d_cnt, c_issues = self._analyze_class_node(
                        item, rel_path
                    )
                    classes_count += c_cnt
                    funcs_count += f_cnt
                    docs_count += d_cnt
                    issues.extend(c_issues)

        return classes_count, funcs_count, docs_count, issues
