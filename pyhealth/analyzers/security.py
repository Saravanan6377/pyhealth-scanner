"""Security analyser for PyHealth.

Combines Bandit (via subprocess JSON output) with conservative native pattern
matching to detect hardcoded secrets — without ever including secret values in
any :class:`~pyhealth.models.Issue` field.

Secret privacy is a first-class constraint:

* No discovered value is stored, printed, or logged.
* Only the **variable name** and a generic description appear in messages.
* Bandit ``issue_text`` strings that could contain literal secret values are
  sanitized before being stored.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

from pyhealth.models import Issue, SecurityResult, Severity
from pyhealth.scanner import IGNORED_DIRS

# ---------------------------------------------------------------------------
# Bandit → PyHealth severity mapping
# ---------------------------------------------------------------------------

_BANDIT_SEVERITY: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}

# ---------------------------------------------------------------------------
# Bandit clean message map
# Pre-defined messages avoid relying on Bandit's ``issue_text`` which can
# contain the actual secret value (e.g. "Possible hardcoded password: 'abc'").
# ---------------------------------------------------------------------------

_BANDIT_MESSAGES: dict[str, str] = {
    "B101": "Use of assert statement",
    "B102": "Use of exec",
    "B103": "Setting insecure file permissions",
    "B104": "Binding to all interfaces (0.0.0.0)",
    "B105": "Possible hardcoded password",
    "B106": "Possible hardcoded password in function call",
    "B107": "Possible hardcoded password in function argument",
    "B108": "Probable insecure usage of temporary file or directory",
    "B110": "Try/except/pass detected",
    "B112": "Try/except/continue detected",
    "B201": "Flask application running with debug=True",
    "B301": "Pickle or related module usage detected",
    "B302": "Use of marshal module",
    "B303": "Use of insecure MD5 or SHA1 hash function",
    "B304": "Use of deprecated cipher mode",
    "B305": "Use of deprecated cipher",
    "B307": "Use of possibly insecure function eval",
    "B308": "Use of mark_safe",
    "B310": "Audit URL open for permitted schemes",
    "B311": "Use of random for security purposes",
    "B312": "Telnet-related function usage",
    "B314": "Blacklisted XML module",
    "B320": "Blacklisted XML module",
    "B324": "Use of weak cryptographic hash",
    "B325": "Use of weak cryptographic hash",
    "B401": "Import of telnetlib module",
    "B403": "Import of pickle module",
    "B404": "Import of subprocess module",
    "B501": "Request with certificate verification disabled",
    "B502": "Use of insecure SSL/TLS protocol version",
    "B503": "Use of insecure cipher suite",
    "B506": "Use of yaml.load",
    "B601": "Possible shell injection via Popen with shell=True",
    "B602": "Subprocess popen with shell=True",
    "B603": "Subprocess without shell=True",
    "B604": "Function call with shell=True",
    "B605": "Starting a process with a shell",
    "B606": "Starting a process without a shell",
    "B607": "Starting a process with a partial path",
    "B608": "Possible SQL injection via string-based query construction",
    "B701": "Jinja2 autoescape disabled",
    "B702": "Use of mako templates",
}

# ---------------------------------------------------------------------------
# Bandit remediation suggestions
# ---------------------------------------------------------------------------

_BANDIT_RECOMMENDATIONS: dict[str, str] = {
    "B101": "Avoid assert in production code; use explicit error handling.",
    "B105": (
        "Move credentials to environment variables or a secure"
        " configuration mechanism."
    ),
    "B106": (
        "Move credentials to environment variables or a secure"
        " configuration mechanism."
    ),
    "B107": (
        "Move credentials to environment variables or a secure"
        " configuration mechanism."
    ),
    "B110": "Catch specific exceptions instead of using a bare except with pass.",
    "B201": "Disable Flask debug mode in production environments.",
    "B301": (
        "Avoid pickle with untrusted data; use json or a safer"
        " serialization format."
    ),
    "B303": "Use SHA-256 or stronger; MD5 and SHA-1 are cryptographically weak.",
    "B307": (
        "Avoid eval() with untrusted input; use ast.literal_eval or a safer"
        " alternative."
    ),
    "B311": "Use the secrets module for cryptographically secure random values.",
    "B501": "Never disable SSL certificate verification in production.",
    "B502": "Use TLS 1.2 or higher; avoid SSLv2, SSLv3, and TLS 1.0/1.1.",
    "B506": (
        "Use yaml.safe_load instead of yaml.load to prevent arbitrary code"
        " execution."
    ),
    "B601": "Shell injection risk; avoid shell=True and pass arguments as a list.",
    "B602": "Shell injection risk; avoid shell=True and pass arguments as a list.",
    "B605": "shell=True is a security risk; pass arguments as a list instead.",
    "B608": "Possible SQL injection; use parameterized queries or an ORM.",
}

# ---------------------------------------------------------------------------
# Native secret detection — constants
# ---------------------------------------------------------------------------

# Substrings that indicate a variable name may hold a secret.
_SENSITIVE_SUBSTRINGS: tuple[str, ...] = (
    "api_key", "apikey",
    "secret_key", "secretkey",
    "secret_token", "secrettoken",
    "access_key", "accesskey",
    "private_key", "privatekey",
    "auth_key", "authkey",
    "master_key",
    "api_secret", "apisecret",
    "app_secret", "appsecret",
    "client_secret", "clientsecret",
    "access_token", "accesstoken",
    "auth_token", "authtoken",
    "api_token", "apitoken",
    "refresh_token", "refreshtoken",
    "session_token", "sessiontoken",
    "bearer_token", "bearertoken",
    "password", "passwd",
    "secret", "token",
)

# Variable names that are sensitive when the whole lowercased name matches exactly.
_SENSITIVE_EXACT: frozenset[str] = frozenset({"token", "secret", "pwd", "key"})

# Minimum value length below which we assume it's a stub/placeholder.
_MIN_SECRET_LEN = 8

# Substrings in a value that indicate it is a placeholder, not a real secret.
_PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "example",
    "dummy",
    "placeholder",
    "changeme", "change_me",
    "replaceme", "replace_me",
    "your_api_key", "your_secret", "your_token", "your_password",
    "test_secret", "test_key", "test_token",
    "sample_",
    "foobar",
)

# Substrings that indicate the right-hand side sources from an env-var lookup
# OR that the line is a test-fixture construction call (not a real assignment).
_ENV_VAR_PATTERNS: tuple[str, ...] = (
    "os.getenv",
    "os.environ",
    "environ.get",
    "getenv(",
    "environ[",
    # Lines like: (tmp_path / "x.py").write_text('API_KEY = "..."')
    # The string inside write_text is being written *as a file*, not assigned.
    ".write_text(",
    ".write_bytes(",
)

# Captures: VARNAME = "VALUE" or VARNAME = 'VALUE' (with optional string prefixes)
_ASSIGNMENT_RE = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[bBrRuUfF]*["']([^"'\n]*)["']"""
)

# Private key headers in PEM format.
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
    re.IGNORECASE,
)

# JWT-like tokens: three base64url segments; real JWTs always start with 'eyJ'
# (base64url for '{"') so this is highly specific.
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"
)


# ---------------------------------------------------------------------------
# Native secret detection — helpers
# ---------------------------------------------------------------------------


# Variable name suffixes used in test fixtures that hold *code strings*, not secrets.
# E.g. `token_code = 'SECRET_TOKEN = "ghp_..."'`  — the value is source code text.
_TEST_VAR_SUFFIXES: tuple[str, ...] = (
    "_code",
    "_data",
    "_val",
    "_content",
    "_source",
    "_text",
)


def _is_sensitive_varname(name: str) -> bool:
    """Return ``True`` if *name* (lowercased) suggests a secret-holding variable."""
    low = name.lower()
    # Variables whose names are test-fixture containers (holding source code as a
    # string) are excluded even if the name also contains a sensitive keyword.
    if any(low.endswith(suf) for suf in _TEST_VAR_SUFFIXES):
        return False
    if low in _SENSITIVE_EXACT:
        return True
    return any(sub in low for sub in _SENSITIVE_SUBSTRINGS)


def _is_likely_placeholder(value: str) -> bool:
    """Return ``True`` if *value* looks like a placeholder rather than a real secret."""
    if len(value) < _MIN_SECRET_LEN:
        return True
    low = value.lower()
    return any(sub in low for sub in _PLACEHOLDER_SUBSTRINGS)


def _sanitize_bandit_message(raw: str) -> str:
    """Strip potential secret values from a raw Bandit ``issue_text`` string.

    Bandit sometimes appends the literal secret to its message, e.g.:

        ``"Possible hardcoded password: 'mysecret'"``

    This function strips everything from the first ``": '"`` or ``": "``
    separator onward, preventing the secret from appearing in stored Issue
    messages.
    """
    for sep in (": '", ': "', ": "):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx].strip()
    return raw.strip()


def _check_secrets_in_source(source: str, filename: str) -> list[Issue]:
    """Detect hardcoded secrets in *source* without including values in Issues.

    For each source line the following checks run in priority order (at most
    one Issue per line):

    1. **PYS002** — private key headers (``-----BEGIN ... PRIVATE KEY-----``)
    2. **PYS003** — JWT-like tokens (``eyJ…<seg2>…<sig>``)
    3. **PYS001** — sensitive variable assignments (name check + value check)

    Lines that start with ``#`` or that contain environment-variable lookups
    (e.g. ``os.getenv``) are skipped.

    **Secret privacy guarantee**: the matched secret *value* is accessed only
    inside ``_is_likely_placeholder()`` for filtering and is never placed into
    any ``Issue`` field.
    """
    issues: list[Issue] = []

    for lineno, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()

        # Skip pure comment lines
        if stripped.startswith("#"):
            continue

        # Skip lines that clearly source from environment-variable lookups
        if any(pat in line for pat in _ENV_VAR_PATTERNS):
            continue

        # PYS002: private key material
        if _PRIVATE_KEY_RE.search(line):
            issues.append(
                Issue(
                    category="security",
                    severity=Severity.CRITICAL,
                    code="PYS002",
                    message="Private key material detected",
                    file=filename,
                    line=lineno,
                    tool="pyhealth",
                    suggestion=(
                        "Never commit private keys to source control. "
                        "Store them in environment variables or a secrets manager."
                    ),
                )
            )
            continue

        # PYS003: JWT-like token
        if _JWT_RE.search(line):
            issues.append(
                Issue(
                    category="security",
                    severity=Severity.HIGH,
                    code="PYS003",
                    message="JWT-like token detected",
                    file=filename,
                    line=lineno,
                    tool="pyhealth",
                    suggestion=(
                        "Never hardcode JWT tokens. "
                        "Load them from environment variables or a secrets manager."
                    ),
                )
            )
            continue

        # PYS001: sensitive variable assignment
        for match in _ASSIGNMENT_RE.finditer(line):
            varname = match.group(1)
            value = match.group(2)

            if not _is_sensitive_varname(varname):
                continue
            if not value:
                continue
            if _is_likely_placeholder(value):
                continue

            # The actual *value* is intentionally excluded from the Issue message.
            issues.append(
                Issue(
                    category="security",
                    severity=Severity.HIGH,
                    code="PYS001",
                    message=f"Potential hardcoded secret in variable '{varname}'",
                    file=filename,
                    line=lineno,
                    tool="pyhealth",
                    suggestion=(
                        "Move credentials to environment variables "
                        "or a secure configuration mechanism."
                    ),
                )
            )
            break  # at most one PYS001 per line

    return issues


# ---------------------------------------------------------------------------
# SecurityAnalyzer
# ---------------------------------------------------------------------------


class SecurityAnalyzer:
    """Analyses security within a project directory.

    Combines two detection strategies:

    * **Bandit** — static analysis for common Python security pitfalls,
      invoked via ``python -m bandit`` with machine-readable JSON output.
    * **Native detector** — conservative regex / pattern matching for
      hardcoded secrets (PYS001), private key material (PYS002), and
      JWT-like tokens (PYS003).

    All findings are normalised into :class:`~pyhealth.models.Issue` objects.
    Secret values are **never** included in any Issue field.

    Args:
        root: Root directory to analyse.

    Example::

        from pathlib import Path
        from pyhealth.analyzers.security import SecurityAnalyzer

        result = SecurityAnalyzer(Path(".")).analyze()
        print(f"{result.total_findings} security findings")
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> SecurityResult:
        """Run all security checks.

        Returns a :class:`~pyhealth.models.SecurityResult`.
        """
        py_files = self._collect_py_files()
        issues: list[Issue] = []
        bandit_count = 0
        secret_count = 0

        # Bandit static analysis
        bandit_issues = self._run_bandit()
        bandit_count = len(bandit_issues)
        issues.extend(bandit_issues)

        # Native secret detection (per file; never includes secret values)
        for fp in py_files:
            source = self._read_source(fp)
            if source is None:
                continue
            secret_issues = _check_secrets_in_source(source, str(fp))
            secret_count += len(secret_issues)
            issues.extend(secret_issues)

        return SecurityResult(
            python_files=len(py_files),
            issues=issues,
            bandit_findings=bandit_count,
            secret_findings=secret_count,
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
        """Return the text of *path* decoded as UTF-8, or ``None`` on any read error."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def _exec_bandit_subprocess(
        self, exclude_parts: list[str]
    ) -> subprocess.CompletedProcess | None:  # type: ignore[type-arg]
        """Build and run the bandit command, returning the CompletedProcess or None."""
        bandit_exe = shutil.which("bandit")
        cmd: list[str] = (
            [bandit_exe, "-r", "-f", "json"]
            if bandit_exe
            else [sys.executable, "-m", "bandit", "-r", "-f", "json"]
        )
        if exclude_parts:
            cmd += ["--exclude", ",".join(exclude_parts)]
        cmd.append(str(self.root))

        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return None

    def _parse_bandit_finding(self, finding: dict) -> Issue | None:  # type: ignore[type-arg]
        """Convert a single Bandit JSON result dict into an Issue, or None."""
        if not isinstance(finding, dict):
            return None

        test_id = str(finding.get("test_id") or "")
        issue_text = str(finding.get("issue_text") or "")
        severity_str = str(finding.get("issue_severity") or "LOW").upper()
        filename = finding.get("filename") or ""
        line_number = finding.get("line_number")

        severity = _BANDIT_SEVERITY.get(severity_str, Severity.LOW)
        clean_msg = (
            _BANDIT_MESSAGES.get(test_id)
            or _sanitize_bandit_message(issue_text)
        )
        message = f"{test_id} — {clean_msg}" if test_id else clean_msg

        return Issue(
            category="security",
            severity=severity,
            code=test_id,
            message=message,
            file=str(filename) if filename else None,
            line=line_number,
            tool="bandit",
            suggestion=_BANDIT_RECOMMENDATIONS.get(test_id),
        )

    def _run_bandit(self) -> list[Issue]:
        """Run ``bandit -r -f json`` and return normalised security Issues.

        Safe subprocess requirements satisfied:

        * No ``shell=True``.
        * Arguments passed as a list.
        * stdout/stderr captured separately.
        * Non-zero exit (expected when findings exist) handled gracefully.
        * Missing Bandit (``FileNotFoundError``, ``SubprocessError``) → ``[]``.
        * Malformed JSON → ``[]``.

        Directories in :data:`~pyhealth.scanner.IGNORED_DIRS` that exist under
        :attr:`root` are passed to Bandit via ``--exclude`` so that virtual
        environments, caches, and build artefacts are skipped.

        Bandit ``issue_text`` values that may contain literal secret material
        are sanitized via :func:`_sanitize_bandit_message` before being stored
        in any Issue field.
        """
        # Exclude directories that Bandit should not scan
        exclude_parts = [
            str(self.root / d)
            for d in sorted(IGNORED_DIRS)
            if (self.root / d).is_dir()
        ]

        proc = self._exec_bandit_subprocess(exclude_parts)
        if proc is None:
            return []

        stdout = proc.stdout.strip()
        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        if not isinstance(data, dict):
            return []

        results = data.get("results", [])
        if not isinstance(results, list):
            return []

        return [
            issue
            for finding in results
            if (issue := self._parse_bandit_finding(finding)) is not None
        ]
