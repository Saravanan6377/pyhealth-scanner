"""SARIF (v2.1.0) Report Generator for PyHealth."""

from __future__ import annotations

import json
from typing import Any

from pyhealth.models import ProjectReport, Severity
from pyhealth.reports.base import Reporter

_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}


def _get_sarif_level(sev: Severity) -> str:
    return _SEVERITY_TO_SARIF_LEVEL.get(sev, "warning")


class SarifReporter(Reporter):
    """Renders a ProjectReport into valid SARIF v2.1.0 JSON."""

    def render(self, report: ProjectReport) -> str:
        all_issues = report.all_issues()

        # Build rules table for unique issue codes
        rules_map: dict[str, dict[str, Any]] = {}
        for issue in all_issues:
            code = issue.code
            if code not in rules_map:
                rules_map[code] = {
                    "id": code,
                    "name": code,
                    "shortDescription": {
                        "text": f"PyHealth {issue.category.capitalize()} Rule {code}"
                    },
                    "fullDescription": {
                        "text": issue.suggestion or issue.message
                    },
                    "defaultConfiguration": {
                        "level": _get_sarif_level(issue.severity)
                    },
                }

        # Sort rules deterministically by rule ID
        sorted_rules = [rules_map[k] for k in sorted(rules_map.keys())]

        # Build results
        results: list[dict[str, Any]] = []
        for issue in all_issues:
            res: dict[str, Any] = {
                "ruleId": issue.code,
                "level": _get_sarif_level(issue.severity),
                "message": {
                    "text": issue.message,
                },
            }

            if issue.file:
                # Normalize relative URI with forward slashes for SARIF standard
                clean_path = issue.file.replace("\\", "/")
                location: dict[str, Any] = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": clean_path,
                        }
                    }
                }
                region: dict[str, Any] = {}
                if issue.line and issue.line > 0:
                    region["startLine"] = issue.line
                if issue.column and issue.column > 0:
                    region["startColumn"] = issue.column

                if region:
                    location["physicalLocation"]["region"] = region

                res["locations"] = [location]

            results.append(res)

        sarif_doc: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PyHealth Scanner",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/pyhealth-scanner/pyhealth-scanner",
                            "rules": sorted_rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_doc, indent=2)
