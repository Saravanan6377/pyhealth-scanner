"""Dependency analyser for PyHealth.

Examines Python dependency declarations (requirements.txt, pyproject.toml,
setup.cfg, setup.py), compares them with static AST import analysis and
installed package metadata, and optionally runs pip-audit for vulnerability
checking.
"""

from __future__ import annotations

import ast
import configparser
import importlib.metadata
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

# Python 3.11+ tomllib, with fallback to tomli or basic parser
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

from pyhealth.models import DependencyResult, Issue, Severity
from pyhealth.scanner import IGNORED_DIRS

# ---------------------------------------------------------------------------
# Standard library module set
# ---------------------------------------------------------------------------

_STDLIB_MODULES: set[str] = (
    getattr(sys, "stdlib_module_names", set())
    | {
        "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii",
        "bisect", "builtins", "bz2", "calendar", "cgi", "cmath", "cmd",
        "codecs", "collections", "concurrent", "configparser", "contextlib",
        "copy", "csv", "ctypes", "dataclasses", "datetime", "decimal",
        "difflib", "dis", "doctest", "email", "enum", "errno", "faulthandler",
        "fcntl", "fileinput", "fnmatch", "fractions", "functools", "gc",
        "getopt", "getpass", "gettext", "glob", "gzip", "hashlib", "heapq",
        "hmac", "html", "http", "imaplib", "importlib", "inspect", "io",
        "ipaddress", "itertools", "json", "keyword", "linecache", "locale",
        "logging", "lzma", "math", "mimetypes", "multiprocessing", "netrc",
        "numbers", "operator", "os", "pathlib", "pickle", "pkgutil",
        "platform", "plistlib", "poplib", "posixpath", "pprint", "profile",
        "pstats", "py_compile", "pydoc", "queue", "random", "re", "readline",
        "reprlib", "resource", "rlcompleter", "sched", "select", "selectors",
        "shelve", "shutil", "signal", "site", "socket", "socketserver",
        "sqlite3", "ssl", "stat", "string", "struct", "subprocess", "sys",
        "sysconfig", "tarfile", "tempfile", "termios", "textwrap", "threading",
        "time", "timeit", "tkinter", "token", "tokenize", "tomllib", "trace",
        "traceback", "tracemalloc", "tty", "types", "typing", "unicodedata",
        "unittest", "urllib", "uuid", "venv", "warnings", "weakref",
        "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
    }
)

# Common import name to PyPI distribution name mapping
_IMPORT_TO_DIST: dict[str, str] = {
    "pil": "pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "attr": "attrs",
    "fitz": "pymupdf",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "serial": "pyserial",
    "git": "gitpython",
    "jwt": "pyjwt",
    "dotenv": "python-dotenv",
}

# Reverse mapping: distribution name to possible top-level import names
_DIST_TO_IMPORTS: dict[str, set[str]] = {
    "pillow": {"pil"},
    "opencv-python": {"cv2"},
    "scikit-learn": {"sklearn"},
    "pyyaml": {"yaml"},
    "beautifulsoup4": {"bs4"},
    "attrs": {"attr", "attrs"},
    "pymupdf": {"fitz"},
    "python-docx": {"docx"},
    "python-pptx": {"pptx"},
    "pyserial": {"serial"},
    "gitpython": {"git"},
    "pyjwt": {"jwt"},
    "python-dotenv": {"dotenv"},
}


def _canonicalize(name: str) -> str:
    """Normalize a package name (lowercase, replace underscores with hyphens)."""
    return name.lower().replace("_", "-").strip()


def _clean_req_name(line: str) -> str | None:
    """Extract and normalize distribution name from a requirement string.

    Ignores comments, empty lines, environment markers, extras, and pip options.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None

    # Strip inline comment
    if " #" in line:
        line = line.split(" #", 1)[0].strip()

    # Strip environment markers
    if ";" in line:
        line = line.split(";", 1)[0].strip()

    # Strip version specifiers or extras
    match = re.match(r"^([A-Za-z0-9_.\-]+)", line)
    if match:
        name = match.group(1).rstrip("-.")
        return _canonicalize(name)
    return None


class DependencyAnalyzer:
    """Analyses declared vs imported dependencies and vulnerabilities.

    Supports:
    * ``requirements.txt``, ``requirements-dev.txt``, ``requirements/*.txt``
    * ``pyproject.toml`` (PEP 621 dependencies & optional-dependencies)
    * ``setup.cfg`` ([options] install_requires & extras_require)
    * ``setup.py`` (static extraction only, never executes code)

    Args:
        root: Root directory to analyse.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def analyze(self) -> DependencyResult:
        """Run dependency analysis across the project directory."""
        py_files = self._collect_py_files()

        # 1. Parse declared dependencies
        prod_declared, dev_or_opt_declared = self._parse_declarations()

        # 2. Extract imported top-level modules
        imports_by_file, all_imports, fallback_imports = self._extract_imports(py_files)

        # 3. Detect local project package names
        local_packages = self._detect_local_packages()

        # 4. Standard-library filter
        third_party_imports = {
            imp for imp in all_imports
            if imp not in _STDLIB_MODULES and imp not in local_packages
        }

        # 5. Installed packages metadata
        all_pkgs = prod_declared | dev_or_opt_declared | third_party_imports
        installed = self._get_installed_packages(all_pkgs)

        # 6. Heuristic unused dependency check
        potentially_unused: list[str] = []
        issues: list[Issue] = []

        all_declared = prod_declared | dev_or_opt_declared

        for pkg in sorted(prod_declared):
            possible_imports = _DIST_TO_IMPORTS.get(pkg, {pkg.replace("-", "_"), pkg})
            if not any(imp in third_party_imports for imp in possible_imports):
                potentially_unused.append(pkg)
                issues.append(
                    Issue(
                        category="dependencies",
                        severity=Severity.LOW,
                        code="PYH201",
                        message=f"Potentially unused dependency: {pkg}",
                        tool="pyhealth",
                        suggestion=(
                            f"Verify whether {pkg} is required indirectly, "
                            "dynamically, through plugins, generated code, "
                            "or optional features."
                        ),
                    )
                )

        # 7. Heuristic missing dependency check
        potentially_missing: list[str] = []

        for imp in sorted(third_party_imports):
            if imp in fallback_imports:
                continue

            dist_candidate = _IMPORT_TO_DIST.get(imp, _canonicalize(imp))
            if dist_candidate not in all_declared and imp not in all_declared:
                # Find first file importing this package
                first_file = next(
                    (str(fp) for fp, imps in imports_by_file.items() if imp in imps),
                    None,
                )
                potentially_missing.append(dist_candidate)
                issues.append(
                    Issue(
                        category="dependencies",
                        severity=Severity.HIGH,
                        code="PYH202",
                        message=f"Potentially undeclared dependency: {dist_candidate}",
                        file=first_file,
                        tool="pyhealth",
                        suggestion=(
                            "Declare the dependency in pyproject.toml "
                            "or the appropriate requirements file."
                        ),
                    )
                )

        # 8. pip-audit vulnerability check
        audit_issues, vuln_count = self._run_pip_audit(installed)
        issues.extend(audit_issues)

        return DependencyResult(
            python_files=len(py_files),
            issues=issues,
            declared_dependencies=sorted(prod_declared),
            imported_packages=sorted(third_party_imports),
            potentially_unused=sorted(potentially_unused),
            potentially_missing=sorted(potentially_missing),
            installed_packages=installed,
            vulnerabilities_count=vuln_count,
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

    def _parse_declarations(self) -> tuple[set[str], set[str]]:
        """Parse all project dependency declarations into (prod, dev_or_optional)."""
        prod: set[str] = set()
        dev_or_opt: set[str] = set()

        # pyproject.toml
        pyproject_file = self.root / "pyproject.toml"
        if pyproject_file.is_file():
            p_prod, p_dev = self._parse_pyproject(pyproject_file)
            prod.update(p_prod)
            dev_or_opt.update(p_dev)

        # requirements.txt & requirements/*.txt
        req_file = self.root / "requirements.txt"
        if req_file.is_file():
            prod.update(self._parse_req_file(req_file))

        req_dev_file = self.root / "requirements-dev.txt"
        if req_dev_file.is_file():
            dev_or_opt.update(self._parse_req_file(req_dev_file))

        req_dir = self.root / "requirements"
        if req_dir.is_dir():
            for child in req_dir.glob("*.txt"):
                name_low = child.name.lower()
                if "dev" in name_low or "test" in name_low:
                    dev_or_opt.update(self._parse_req_file(child))
                else:
                    prod.update(self._parse_req_file(child))

        # setup.cfg
        setup_cfg = self.root / "setup.cfg"
        if setup_cfg.is_file():
            s_prod, s_dev = self._parse_setup_cfg(setup_cfg)
            prod.update(s_prod)
            dev_or_opt.update(s_dev)

        # setup.py (static extraction only)
        setup_py = self.root / "setup.py"
        if setup_py.is_file():
            s_prod, s_dev = self._parse_setup_py_static(setup_py)
            prod.update(s_prod)
            dev_or_opt.update(s_dev)

        return prod, dev_or_opt

    def _parse_req_file(self, path: Path) -> set[str]:
        reqs: set[str] = set()
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return reqs

        for line in content.splitlines():
            cleaned = _clean_req_name(line)
            if cleaned:
                reqs.add(cleaned)
        return reqs

    def _parse_pyproject(self, path: Path) -> tuple[set[str], set[str]]:
        prod: set[str] = set()
        dev: set[str] = set()
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return prod, dev

        data: dict = {}
        if tomllib is not None:
            try:
                data = tomllib.loads(content)
            except Exception:  # noqa: BLE001
                pass

        if not data and "dependencies" in content:
            return self._parse_pyproject_fallback_regex(content)

        project_sec = data.get("project", {})
        if isinstance(project_sec, dict):
            prod.update(self._parse_pyproject_project_deps(project_sec))
            dev.update(self._parse_pyproject_opt_deps(project_sec))

        return prod, dev

    def _parse_pyproject_fallback_regex(
        self, content: str
    ) -> tuple[set[str], set[str]]:
        """Regex fallback for pyproject.toml when tomllib is not available."""
        prod: set[str] = set()
        for match in re.finditer(r'["\']([A-Za-z0-9_.\-\[\]><~!=]+)["\']', content):
            cleaned = _clean_req_name(match.group(1))
            if cleaned:
                prod.add(cleaned)
        return prod, set()

    @staticmethod
    def _parse_pyproject_project_deps(project_sec: dict) -> set[str]:  # type: ignore[type-arg]
        """Extract production dependencies from a pyproject [project] section dict."""
        prod: set[str] = set()
        deps = project_sec.get("dependencies", [])
        if isinstance(deps, list):
            for dep in deps:
                cleaned = _clean_req_name(str(dep))
                if cleaned:
                    prod.add(cleaned)
        return prod

    @staticmethod
    def _parse_pyproject_opt_deps(project_sec: dict) -> set[str]:  # type: ignore[type-arg]
        """Extract optional/dev dependencies from a pyproject [project] section dict."""
        dev: set[str] = set()
        opt_deps = project_sec.get("optional-dependencies", {})
        if isinstance(opt_deps, dict):
            for group_list in opt_deps.values():
                if isinstance(group_list, list):
                    for dep in group_list:
                        cleaned = _clean_req_name(str(dep))
                        if cleaned:
                            dev.add(cleaned)
        return dev

    def _parse_setup_cfg(self, path: Path) -> tuple[set[str], set[str]]:
        prod: set[str] = set()
        dev: set[str] = set()
        config = configparser.ConfigParser()
        try:
            config.read(path, encoding="utf-8")
        except Exception:  # noqa: BLE001
            return prod, dev

        if config.has_section("options"):
            install_reqs = config.get("options", "install_requires", fallback="")
            for line in install_reqs.splitlines():
                cleaned = _clean_req_name(line)
                if cleaned:
                    prod.add(cleaned)

        if config.has_section("options.extras_require"):
            for _, val in config.items("options.extras_require"):
                for line in val.splitlines():
                    cleaned = _clean_req_name(line)
                    if cleaned:
                        dev.add(cleaned)

        return prod, dev

    def _parse_setup_py_static(self, path: Path) -> tuple[set[str], set[str]]:
        """Safely extract dependencies from setup.py without executing code."""
        prod: set[str] = set()
        dev: set[str] = set()
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return prod, dev

        # Regex search for install_requires=[...]
        match = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if match:
            for item in re.finditer(r'["\']([^"\'\n]+)["\']', match.group(1)):
                cleaned = _clean_req_name(item.group(1))
                if cleaned:
                    prod.add(cleaned)

        return prod, dev

    def _extract_imports(
        self, py_files: list[Path]
    ) -> tuple[dict[Path, set[str]], set[str], set[str]]:
        imports_by_file: dict[Path, set[str]] = {}
        all_imports: set[str] = set()
        fallback_imports: set[str] = set()

        class ImportVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.file_imports: set[str] = set()
                self.file_fallbacks: set[str] = set()
                self.in_fallback_block = False

            def visit_Try(self, node: ast.Try) -> None:
                # Check if this Try block has an except ImportError/ModuleNotFoundError
                is_fallback = False
                for handler in node.handlers:
                    if isinstance(handler.type, ast.Name):
                        if handler.type.id in ("ImportError", "ModuleNotFoundError"):
                            is_fallback = True
                    elif isinstance(handler.type, ast.Tuple):
                        for elt in handler.type.elts:
                            if isinstance(elt, ast.Name) and elt.id in (
                                "ImportError",
                                "ModuleNotFoundError",
                            ):
                                is_fallback = True

                if is_fallback:
                    old = self.in_fallback_block
                    self.in_fallback_block = True
                    # Visit the try body
                    for stmt in node.body:
                        self.visit(stmt)
                    # Visit the except handlers (e.g. except ImportError: import tomli)
                    for handler in node.handlers:
                        self.visit(handler)
                    self.in_fallback_block = old

                    # Visit else and finally normally
                    for stmt in node.orelse:
                        self.visit(stmt)
                    for stmt in node.finalbody:
                        self.visit(stmt)
                else:
                    self.generic_visit(node)

            def _add_import(self, top: str) -> None:
                if top == "__future__":
                    return
                canon = _canonicalize(top)
                self.file_imports.add(canon)
                if self.in_fallback_block:
                    self.file_fallbacks.add(canon)

            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    self._add_import(top)
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                if node.level == 0 and node.module:
                    top = node.module.split(".")[0]
                    self._add_import(top)
                self.generic_visit(node)

        for fp in py_files:
            try:
                source = fp.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                continue

            visitor = ImportVisitor()
            visitor.visit(tree)

            imports_by_file[fp] = visitor.file_imports
            all_imports.update(visitor.file_imports)
            fallback_imports.update(visitor.file_fallbacks)

        return imports_by_file, all_imports, fallback_imports

    def _detect_local_packages(self) -> set[str]:
        local: set[str] = set()

        # Files directly in root
        for entry in self.root.iterdir():
            if entry.is_file() and entry.suffix == ".py":
                local.add(_canonicalize(entry.stem))
            elif entry.is_dir() and entry.name not in IGNORED_DIRS:
                if (entry / "__init__.py").exists() or any(entry.glob("*.py")):
                    local.add(_canonicalize(entry.name))

        # src directory layout
        src_dir = self.root / "src"
        if src_dir.is_dir():
            for entry in src_dir.iterdir():
                if entry.is_file() and entry.suffix == ".py":
                    local.add(_canonicalize(entry.stem))
                elif entry.is_dir() and entry.name not in IGNORED_DIRS:
                    local.add(_canonicalize(entry.name))

        return local

    def _get_installed_packages(self, packages: set[str]) -> dict[str, str]:
        installed: dict[str, str] = {}
        for pkg in packages:
            try:
                ver = importlib.metadata.version(pkg)
                installed[pkg] = ver
            except (importlib.metadata.PackageNotFoundError, ValueError):
                pass
        return installed

    def _write_requirements_tmpfile(
        self, installed: dict[str, str]
    ) -> str | None:
        """Write a pip requirements tempfile for pip-audit; returns path or None."""
        import os
        import tempfile

        fd, temp_path = tempfile.mkstemp(suffix=".txt", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for pkg, ver in installed.items():
                    if ver:
                        f.write(f"{pkg}=={ver}\n")
        except OSError:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            return None
        return temp_path

    def _exec_pip_audit(
        self, temp_path: str, base_cmd: list[str]
    ) -> subprocess.CompletedProcess | None:  # type: ignore[type-arg]
        """Execute pip-audit against a requirements file; returns
        CompletedProcess or None."""
        import os

        cmd = base_cmd + ["-r", temp_path]
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.root),
                timeout=120,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return None
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    @staticmethod
    def _parse_pip_audit_vuln(
        pkg_name: str, pkg_ver: str, vuln: dict  # type: ignore[type-arg]
    ) -> Issue | None:
        """Convert a single pip-audit vulnerability dict into an Issue, or None."""
        if not isinstance(vuln, dict):
            return None
        vuln_id = vuln.get("id") or "VULN"
        raw_sum = vuln.get("description") or vuln.get("summary")
        summary = raw_sum or "Known vulnerability"
        fix_versions = vuln.get("fix_versions", [])
        fix_str = (
            f" (fixed in {', '.join(fix_versions)})"
            if fix_versions
            else ""
        )
        msg = (
            f"Vulnerability in {pkg_name} {pkg_ver}: "
            f"{vuln_id} \u2014 {summary}"
        )
        return Issue(
            category="dependencies",
            severity=Severity.HIGH,
            code="PYH203",
            message=msg,
            tool="pip-audit",
            suggestion=(
                f"Upgrade {pkg_name} to a non-vulnerable"
                f" version{fix_str}."
            ),
        )

    def _run_pip_audit(self, installed: dict[str, str]) -> tuple[list[Issue], int]:
        """Run pip-audit on specific project dependencies via temp file."""
        if not installed:
            return [], 0

        pip_audit_exe = shutil.which("pip-audit")
        base_cmd: list[str] = (
            [pip_audit_exe, "-f", "json"]
            if pip_audit_exe
            else [sys.executable, "-m", "pip_audit", "-f", "json"]
        )

        temp_path = self._write_requirements_tmpfile(installed)
        if temp_path is None:
            return [], 0

        proc = self._exec_pip_audit(temp_path, base_cmd)
        if proc is None:
            return [], 0

        stdout = proc.stdout.strip()
        if not stdout:
            return [], 0

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return [], 0

        if not isinstance(data, dict):
            return [], 0

        dependencies = data.get("dependencies", [])
        if not isinstance(dependencies, list):
            return [], 0

        issues: list[Issue] = []
        vuln_count = 0

        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            pkg_name = dep.get("name") or "unknown"
            pkg_ver = dep.get("version") or ""
            vulns = dep.get("vulns", [])
            if not isinstance(vulns, list):
                continue

            for vuln in vulns:
                issue = self._parse_pip_audit_vuln(pkg_name, pkg_ver, vuln)
                if issue is not None:
                    vuln_count += 1
                    issues.append(issue)

        return issues, vuln_count
