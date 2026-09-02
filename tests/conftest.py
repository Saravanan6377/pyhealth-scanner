from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_subprocess_run():
    """Mock subprocess.run for all tests to prevent actual pip-audit execution."""
    with patch("pyhealth.analyzers.dependencies.subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.stdout = "{}"
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        yield mock_run
