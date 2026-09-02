"""Base protocol interface for all PyHealth report generators.

All reporters consume ONLY a ProjectReport instance and must not rerun analyzers,
inspect source files, or execute external subprocesses.
"""

from __future__ import annotations

from typing import Protocol

from pyhealth.models import ProjectReport


class Reporter(Protocol):
    """Protocol for PyHealth report format renderers."""

    def render(self, report: ProjectReport) -> str:
        """Render a ProjectReport into a formatted string output."""
        ...
