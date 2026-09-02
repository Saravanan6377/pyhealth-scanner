"""CSV Report Generator for PyHealth."""

from __future__ import annotations

import csv
import io

from pyhealth.models import ProjectReport
from pyhealth.reports.base import Reporter


class CsvReporter(Reporter):
    """Renders a ProjectReport into CSV format."""

    HEADERS: list[str] = [
        "category",
        "severity",
        "code",
        "message",
        "file",
        "line",
        "column",
        "tool",
        "suggestion",
    ]

    def render(self, report: ProjectReport) -> str:
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(self.HEADERS)

        for issue in report.all_issues():
            s_obj = issue.severity
            s_val = s_obj.value if hasattr(s_obj, "value") else s_obj
            sev = str(s_val)
            writer.writerow(
                [
                    issue.category,
                    sev,
                    issue.code,
                    issue.message,
                    issue.file or "",
                    issue.line or "",
                    issue.column or "",
                    issue.tool or "",
                    issue.suggestion or "",
                ]
            )

        return output.getvalue()
