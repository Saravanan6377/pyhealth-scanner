"""Tests for the PyHealth security analyser (Stage 4).

All tests use isolated project trees via ``tmp_path`` or mocked subprocess calls.
No secret values should ever appear in any Issue fields or messages.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from pyhealth.analyzers.security import _BANDIT_SEVERITY, SecurityAnalyzer
from pyhealth.cli import app
from pyhealth.models import Issue, SecurityResult, Severity

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1. SecurityResult creation
# ---------------------------------------------------------------------------


def test_security_result_creation() -> None:
    """SecurityResult fields are stored correctly."""
    result = SecurityResult(
        python_files=10,
        issues=[],
        bandit_findings=2,
        secret_findings=1,
    )
    assert result.python_files == 10
    assert result.total_findings == 0
    assert result.bandit_findings == 2
    assert result.secret_findings == 1


# ---------------------------------------------------------------------------
# 2. Severity counts
# ---------------------------------------------------------------------------


def test_security_severity_counts() -> None:
    """severity_counts correctly aggregates findings by severity."""
    issues = [
        Issue(
            category="security",
            severity=Severity.HIGH,
            code="B105",
            message="pwd",
        ),
        Issue(
            category="security",
            severity=Severity.HIGH,
            code="PYS001",
            message="key",
        ),
        Issue(
            category="security",
            severity=Severity.MEDIUM,
            code="B307",
            message="eval",
        ),
    ]
    result = SecurityResult(python_files=3, issues=issues)
    assert result.total_findings == 3
    counts = result.severity_counts
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.MEDIUM] == 1
    assert counts[Severity.LOW] == 0
    assert counts[Severity.CRITICAL] == 0


# ---------------------------------------------------------------------------
# 3. Bandit JSON -> Issue conversion
# ---------------------------------------------------------------------------


def test_bandit_json_to_issue_conversion(tmp_path: Path) -> None:
    """Bandit findings in JSON are correctly converted into Issue objects."""
    bandit_data = {
        "results": [
            {
                "test_id": "B105",
                "issue_text": "Possible hardcoded password: 'secret123'",
                "issue_severity": "HIGH",
                "filename": str(tmp_path / "auth.py"),
                "line_number": 45,
            }
        ]
    }
    mock_proc = MagicMock()
    mock_proc.stdout = json.dumps(bandit_data)
    mock_proc.returncode = 1

    with patch("pyhealth.analyzers.security.subprocess.run", return_value=mock_proc):
        issues = SecurityAnalyzer(tmp_path)._run_bandit()

    assert len(issues) == 1
    assert issues[0].code == "B105"
    assert issues[0].tool == "bandit"
    assert issues[0].severity == Severity.HIGH
    assert issues[0].line == 45
    assert issues[0].suggestion is not None


# ---------------------------------------------------------------------------
# 4. Bandit severity mapping
# ---------------------------------------------------------------------------


def test_bandit_severity_mapping() -> None:
    """_BANDIT_SEVERITY correctly maps Bandit severities."""
    assert _BANDIT_SEVERITY["HIGH"] == Severity.HIGH
    assert _BANDIT_SEVERITY["MEDIUM"] == Severity.MEDIUM
    assert _BANDIT_SEVERITY["LOW"] == Severity.LOW


# ---------------------------------------------------------------------------
# 5. Bandit non-zero exit with findings
# ---------------------------------------------------------------------------


def test_bandit_nonzero_exit_with_findings(tmp_path: Path) -> None:
    """Bandit non-zero returncode (exit code 1 on findings) is handled correctly."""
    bandit_data = {
        "results": [
            {
                "test_id": "B307",
                "issue_text": "Use of possibly insecure function - eval",
                "issue_severity": "MEDIUM",
                "filename": str(tmp_path / "calc.py"),
                "line_number": 12,
            }
        ]
    }
    mock_proc = MagicMock()
    mock_proc.stdout = json.dumps(bandit_data)
    mock_proc.returncode = 1

    with patch("pyhealth.analyzers.security.subprocess.run", return_value=mock_proc):
        issues = SecurityAnalyzer(tmp_path)._run_bandit()

    assert len(issues) == 1
    assert issues[0].code == "B307"
    assert issues[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# 6. Missing Bandit handling
# ---------------------------------------------------------------------------


def test_missing_bandit_handling(tmp_path: Path) -> None:
    """Missing Bandit executable is handled gracefully without raising."""
    with patch(
        "pyhealth.analyzers.security.subprocess.run",
        side_effect=FileNotFoundError("bandit not found"),
    ):
        issues = SecurityAnalyzer(tmp_path)._run_bandit()

    assert issues == []


# ---------------------------------------------------------------------------
# 7. Malformed JSON handling
# ---------------------------------------------------------------------------


def test_malformed_bandit_json_handling(tmp_path: Path) -> None:
    """Malformed Bandit output is handled gracefully."""
    mock_proc = MagicMock()
    mock_proc.stdout = "NOT VALID JSON {"
    mock_proc.returncode = 0

    with patch("pyhealth.analyzers.security.subprocess.run", return_value=mock_proc):
        issues = SecurityAnalyzer(tmp_path)._run_bandit()

    assert issues == []


# ---------------------------------------------------------------------------
# 8. API key detection
# ---------------------------------------------------------------------------


def test_api_key_detection(tmp_path: Path) -> None:
    """Hardcoded API key assignment is detected as PYS001."""
    (tmp_path / "config.py").write_text('API_KEY = "ak_live_998877665544332211"\n')

    result = SecurityAnalyzer(tmp_path).analyze()

    pys001 = [i for i in result.issues if i.code == "PYS001"]
    assert len(pys001) == 1
    assert pys001[0].severity == Severity.HIGH
    assert "API_KEY" in pys001[0].message
    assert "ak_live_998877665544332211" not in pys001[0].message


# ---------------------------------------------------------------------------
# 9. Password detection
# ---------------------------------------------------------------------------


def test_password_detection(tmp_path: Path) -> None:
    """Hardcoded password assignment is detected as PYS001."""
    (tmp_path / "auth.py").write_text('PASSWORD = "SuperSecretPassword123!"\n')

    result = SecurityAnalyzer(tmp_path).analyze()

    pys001 = [i for i in result.issues if i.code == "PYS001"]
    assert len(pys001) == 1
    assert "PASSWORD" in pys001[0].message


# ---------------------------------------------------------------------------
# 10. Token detection
# ---------------------------------------------------------------------------


def test_token_detection(tmp_path: Path) -> None:
    """Hardcoded token assignment is detected as PYS001."""
    token_code = 'SECRET_TOKEN = "ghp_1234567890abcdef1234567890"\n'
    (tmp_path / "token.py").write_text(token_code)

    result = SecurityAnalyzer(tmp_path).analyze()

    pys001 = [i for i in result.issues if i.code == "PYS001"]
    assert len(pys001) == 1
    assert "SECRET_TOKEN" in pys001[0].message


# ---------------------------------------------------------------------------
# 11. Private key detection
# ---------------------------------------------------------------------------


def test_private_key_detection(tmp_path: Path) -> None:
    """PEM private key header is detected as PYS002 with CRITICAL severity."""
    key_data = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n"
    (tmp_path / "key.py").write_text(f'KEY = """{key_data}"""\n')

    result = SecurityAnalyzer(tmp_path).analyze()

    pys002 = [i for i in result.issues if i.code == "PYS002"]
    assert len(pys002) == 1
    assert pys002[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# 12. JWT detection
# ---------------------------------------------------------------------------


def test_jwt_detection(tmp_path: Path) -> None:
    """JWT token is detected as PYS003 with HIGH severity."""
    jwt_val = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    (tmp_path / "jwt_mod.py").write_text(f'raw = "{jwt_val}"\n')

    result = SecurityAnalyzer(tmp_path).analyze()

    pys003 = [i for i in result.issues if i.code == "PYS003"]
    assert len(pys003) == 1
    assert pys003[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# 13. Environment variable lookup is ignored
# ---------------------------------------------------------------------------


def test_env_var_lookup_ignored(tmp_path: Path) -> None:
    """os.getenv or os.environ lookups are not flagged as secrets."""
    code = (
        'import os\n'
        'API_KEY = os.getenv("API_KEY")\n'
        'PASSWORD = os.environ.get("DB_PASSWORD")\n'
    )
    (tmp_path / "env_config.py").write_text(code)

    result = SecurityAnalyzer(tmp_path).analyze()

    secret_issues = [i for i in result.issues if i.code.startswith("PYS")]
    assert len(secret_issues) == 0


# ---------------------------------------------------------------------------
# 14. Empty values are ignored
# ---------------------------------------------------------------------------


def test_empty_values_ignored(tmp_path: Path) -> None:
    """Empty strings or None are not flagged."""
    code = 'API_KEY = ""\nPASSWORD = ""\n'
    (tmp_path / "empty.py").write_text(code)

    result = SecurityAnalyzer(tmp_path).analyze()

    secret_issues = [i for i in result.issues if i.code.startswith("PYS")]
    assert len(secret_issues) == 0


# ---------------------------------------------------------------------------
# 15. Placeholder / example values are ignored
# ---------------------------------------------------------------------------


def test_placeholder_values_ignored(tmp_path: Path) -> None:
    """Obvious placeholder values are not flagged."""
    code = (
        'API_KEY = "your_api_key_here"\n'
        'PASSWORD = "example_password"\n'
        'TOKEN = "dummy_token_12345"\n'
    )
    (tmp_path / "placeholders.py").write_text(code)

    result = SecurityAnalyzer(tmp_path).analyze()

    secret_issues = [i for i in result.issues if i.code.startswith("PYS")]
    assert len(secret_issues) == 0


# ---------------------------------------------------------------------------
# 16. Normal strings are not flagged
# ---------------------------------------------------------------------------


def test_normal_strings_not_flagged(tmp_path: Path) -> None:
    """Normal variable assignments and strings are not flagged."""
    code = 'NAME = "PyHealth Analyzer"\nDESCRIPTION = "Security analysis module"\n'
    (tmp_path / "normal.py").write_text(code)

    result = SecurityAnalyzer(tmp_path).analyze()

    secret_issues = [i for i in result.issues if i.code.startswith("PYS")]
    assert len(secret_issues) == 0


# ---------------------------------------------------------------------------
# 17. Secret values never appear in Issue messages
# ---------------------------------------------------------------------------


def test_secret_values_never_in_messages(tmp_path: Path) -> None:
    """Literal secret value must never appear in Issue.message or any field."""
    secret_val = "SuperSecretValue123456789"
    (tmp_path / "secret.py").write_text(f'SECRET_KEY = "{secret_val}"\n')

    result = SecurityAnalyzer(tmp_path).analyze()

    for issue in result.issues:
        assert secret_val not in issue.message
        if issue.suggestion:
            assert secret_val not in issue.suggestion


# ---------------------------------------------------------------------------
# 18. .venv is ignored
# ---------------------------------------------------------------------------


def test_venv_dir_ignored(tmp_path: Path) -> None:
    """Files inside .venv are ignored."""
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "secret.py").write_text('API_KEY = "ak_live_12345678901234567890"\n')

    result = SecurityAnalyzer(tmp_path).analyze()

    assert result.python_files == 0
    assert len(result.issues) == 0


# ---------------------------------------------------------------------------
# 19. .git is ignored
# ---------------------------------------------------------------------------


def test_git_dir_ignored(tmp_path: Path) -> None:
    """Files inside .git are ignored."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "secret.py").write_text('API_KEY = "ak_live_12345678901234567890"\n')

    result = SecurityAnalyzer(tmp_path).analyze()

    assert result.python_files == 0
    assert len(result.issues) == 0


# ---------------------------------------------------------------------------
# 20. Non-UTF8 file does not crash analyzer
# ---------------------------------------------------------------------------


def test_non_utf8_file_handling(tmp_path: Path) -> None:
    """Files with non-UTF8 binary data do not crash the analyzer."""
    (tmp_path / "binary.py").write_bytes(b"\x80\x81\x82\xff\xfe\xfd")

    result = SecurityAnalyzer(tmp_path).analyze()

    assert result.python_files == 1


# ---------------------------------------------------------------------------
# 21. pyhealth security <tmp-path>
# ---------------------------------------------------------------------------


def test_cli_security_command(tmp_path: Path) -> None:
    """``pyhealth security PATH`` executes successfully."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["security", str(tmp_path)])

    assert res.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in res.output
    assert "SECURITY" in res.output
    assert "Security analysis completed" in res.output


# ---------------------------------------------------------------------------
# 22. pyhealth scan <tmp-path> still works
# ---------------------------------------------------------------------------


def test_cli_scan_command_with_security(tmp_path: Path) -> None:
    """``pyhealth scan PATH`` includes all report sections."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["scan", str(tmp_path)])

    assert res.exit_code == 0
    assert "PROJECT STATISTICS" in res.output
    assert "CODE QUALITY" in res.output
    assert "SECURITY" in res.output
    assert "Scan completed successfully" in res.output


# ---------------------------------------------------------------------------
# 23. pyhealth quality <tmp-path> still works
# ---------------------------------------------------------------------------


def test_cli_quality_command_still_works(tmp_path: Path) -> None:
    """``pyhealth quality PATH`` still works as expected."""
    (tmp_path / "main.py").write_text("x = 1\n")

    res = runner.invoke(app, ["quality", str(tmp_path)])

    assert res.exit_code == 0
    assert "CODE QUALITY" in res.output


# ---------------------------------------------------------------------------
# 24. pyhealth version remains 2.0.0
# ---------------------------------------------------------------------------


def test_version_remains_2_0_0() -> None:
    """Version command displays PyHealth Scanner 2.0.0."""
    res = runner.invoke(app, ["version"])

    assert res.exit_code == 0
    assert "PyHealth Scanner 2.0.0" in res.output


# ---------------------------------------------------------------------------
# 25. write_text fixture lines are NOT flagged as secrets
# ---------------------------------------------------------------------------


def test_write_text_fixture_not_flagged(tmp_path: Path) -> None:
    """Lines constructing test files via write_text() are not flagged as PYS001.

    This is a regression test for the false-positive that occurred when the
    scanner saw `(path).write_text('API_KEY = "..."')` and incorrectly
    matched the embedded string content as a live credential assignment.
    """
    source = (
        "(tmp_path / \"config.py\")"
        ".write_text('API_KEY = \"ak_live_998877665544332211\"\\n')\n"
    )
    (tmp_path / "test_fixture.py").write_text(source)

    result = SecurityAnalyzer(tmp_path).analyze()

    pys001 = [i for i in result.issues if i.code == "PYS001"]
    assert len(pys001) == 0, (
        f"Expected no PYS001 on a write_text() line, got: {pys001}"
    )


# ---------------------------------------------------------------------------
# 26. _code / _val suffix variable names are NOT flagged as secrets
# ---------------------------------------------------------------------------


def test_code_suffix_varname_not_flagged(tmp_path: Path) -> None:
    """Variable names ending in _code or _val holding source code strings are
    not flagged as PYS001, even if the name also contains 'token' or 'secret'.

    E.g. `token_code = 'SECRET_TOKEN = "ghp_..."'` is a test variable
    holding source code, not an actual credential assignment.
    """
    source = 'token_code = \'SECRET_TOKEN = "ghp_1234567890abcdef1234567890"\\n\'\n'
    (tmp_path / "test_fixture.py").write_text(source)

    result = SecurityAnalyzer(tmp_path).analyze()

    pys001 = [i for i in result.issues if i.code == "PYS001"]
    assert len(pys001) == 0, (
        f"Expected no PYS001 on a _code suffix variable, got: {pys001}"
    )


# ---------------------------------------------------------------------------
# 27. Real credentials in normal source files ARE still detected
# ---------------------------------------------------------------------------


def test_real_credential_in_source_detected(tmp_path: Path) -> None:
    """A genuine hardcoded API key in a non-fixture source file is still detected.

    Regression test: test-fixture exceptions must not cause false negatives
    for real production code that hardcodes credentials.
    """
    (tmp_path / "config.py").write_text(
        'API_KEY = "sk_live_AbCdEf12345678XyZ098765"\n'
    )

    result = SecurityAnalyzer(tmp_path).analyze()

    pys001 = [i for i in result.issues if i.code == "PYS001"]
    assert len(pys001) == 1, (
        f"Expected 1 PYS001 for hardcoded API key, got: {pys001}"
    )
    assert "API_KEY" in pys001[0].message
    assert "sk_live_AbCdEf12345678XyZ098765" not in pys001[0].message
