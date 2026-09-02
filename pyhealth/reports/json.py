"""JSON Report Generator for PyHealth."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pyhealth.models import Issue, ProjectReport
from pyhealth.reports.base import Reporter


def _issue_to_dict(issue: Issue) -> dict[str, Any]:
    sev = issue.severity.value if hasattr(issue.severity, "value") else issue.severity
    return {
        "category": str(issue.category),
        "severity": str(sev),
        "code": issue.code,
        "message": issue.message,
        "file": issue.file,
        "line": issue.line,
        "column": issue.column,
        "tool": issue.tool,
        "suggestion": issue.suggestion,
    }


def _path_to_str(val: Any) -> Any:
    if isinstance(val, Path):
        return str(val)
    if isinstance(val, list):
        return [_path_to_str(item) for item in val]
    if isinstance(val, dict):
        return {k: _path_to_str(v) for k, v in val.items()}
    return val


class JsonReporter(Reporter):
    """Renders a ProjectReport into a deterministic JSON string."""

    def render(self, report: ProjectReport) -> str:
        project_name = report.project_path.name or str(report.project_path)

        data: dict[str, Any] = {
            "project": project_name,
            "project_path": str(report.project_path),
        }

        # Health
        if report.health:
            data["health"] = {
                "overall_score": report.health.overall_score,
                "grade": report.health.grade,
                "categories": [
                    {
                        "name": c.name,
                        "score": c.score,
                        "weight": c.weight,
                        "available": c.available,
                    }
                    for c in report.health.categories
                ],
                "priority_issues": [
                    _issue_to_dict(i) for i in report.health.priority_issues
                ],
                "recommendations": report.health.recommendations,
            }
        else:
            data["health"] = None

        # Scan
        if report.scan:
            data["scan"] = {
                "total_files": report.scan.total_files,
                "python_files": report.scan.python_files,
                "directories": report.scan.directories,
                "total_lines": report.scan.total_lines,
                "total_size_bytes": report.scan.total_size_bytes,
                "large_files": [str(f) for f in report.scan.large_files],
                "empty_directories": [str(d) for d in report.scan.empty_directories],
                "duplicate_files": [
                    [str(f) for f in group] for group in report.scan.duplicate_files
                ],
            }
        else:
            data["scan"] = None

        # Quality
        if report.quality:
            data["quality"] = {
                "python_files": report.quality.python_files,
                "total_findings": report.quality.total_findings,
                "ruff_findings": report.quality.ruff_findings,
                "long_functions": report.quality.long_functions,
                "deep_nesting": report.quality.deep_nesting,
                "todo_fixme_count": report.quality.todo_fixme_count,
                "duplicate_function_count": report.quality.duplicate_function_count,
                "issues": [_issue_to_dict(i) for i in report.quality.issues],
            }
        else:
            data["quality"] = None

        # Security
        if report.security:
            data["security"] = {
                "python_files": report.security.python_files,
                "total_findings": report.security.total_findings,
                "issues": [_issue_to_dict(i) for i in report.security.issues],
            }
        else:
            data["security"] = None

        # Complexity
        if report.complexity:
            data["complexity"] = {
                "python_files": report.complexity.python_files,
                "functions_analyzed": report.complexity.functions_analyzed,
                "classes_analyzed": report.complexity.classes_analyzed,
                "maintainability_index": report.complexity.maintainability_index,
                "average_complexity": report.complexity.average_complexity,
                "max_complexity": report.complexity.max_complexity,
                "high_complexity_findings": report.complexity.high_complexity_findings,
                "issues": [_issue_to_dict(i) for i in report.complexity.issues],
            }
        else:
            data["complexity"] = None

        # Dependencies
        if report.dependencies:
            data["dependencies"] = {
                "python_files": report.dependencies.python_files,
                "declared_dependencies": report.dependencies.declared_dependencies,
                "imported_packages": report.dependencies.imported_packages,
                "installed_packages_count": len(report.dependencies.installed_packages),
                "potentially_missing": report.dependencies.potentially_missing,
                "potentially_unused": report.dependencies.potentially_unused,
                "vulnerabilities_count": report.dependencies.vulnerabilities_count,
                "issues": [_issue_to_dict(i) for i in report.dependencies.issues],
            }
        else:
            data["dependencies"] = None

        # Documentation
        if report.documentation:
            data["documentation"] = {
                "files_analyzed": report.documentation.files_analyzed,
                "public_modules": report.documentation.public_modules,
                "public_classes": report.documentation.public_classes,
                "public_functions": report.documentation.public_functions,
                "documented_objects": report.documentation.documented_objects,
                "docstring_coverage": report.documentation.docstring_coverage,
                "readme_exists": report.documentation.readme_exists,
                "license_exists": report.documentation.license_exists,
                "changelog_exists": report.documentation.changelog_exists,
                "contributing_exists": report.documentation.contributing_exists,
                "issues": [_issue_to_dict(i) for i in report.documentation.issues],
            }
        else:
            data["documentation"] = None

        # Git
        if report.git and report.git.repository_detected:
            data["git"] = {
                "repository_detected": True,
                "gitignore_exists": report.git.gitignore_exists,
                "repo_root": (
                    str(report.git.repo_root) if report.git.repo_root else None
                ),
                "tracked_files_count": report.git.tracked_files_count,
                "untracked_files_count": report.git.untracked_files_count,
                "large_tracked_files": [
                    {"path": path, "size_bytes": size}
                    for path, size in report.git.large_tracked_files
                ],
                "sensitive_tracked_files": report.git.sensitive_tracked_files,
                "branch_name": report.git.branch_name,
                "commit_count": report.git.commit_count,
                "issues": [_issue_to_dict(i) for i in report.git.issues],
            }
        else:
            data["git"] = {
                "repository_detected": False,
            }

        return json.dumps(data, indent=2, sort_keys=False)
