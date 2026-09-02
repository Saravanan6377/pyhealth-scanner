"""Markdown Report Generator for PyHealth."""

from __future__ import annotations

from pyhealth.models import ProjectReport
from pyhealth.reports.base import Reporter


class MarkdownReporter(Reporter):
    """Renders a ProjectReport into a GitHub Flavored Markdown document."""

    def render(self, report: ProjectReport) -> str:
        project_name = report.project_path.name or str(report.project_path)
        lines: list[str] = []

        lines.append(f"# PyHealth Scanner Report: {project_name}")
        lines.append("")

        # Executive Summary / Health Score
        if report.health:
            score_int = int(round(report.health.overall_score))
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(f"- **Overall Health Score**: `{score_int}/100`")
            lines.append(f"- **PyHealth Grade**: `{report.health.grade}`")
            lines.append("")

            lines.append("### Category Scores")
            lines.append("")
            lines.append("| Category | Score | Weight | Status |")
            lines.append("|---|---|---|---|")
            for c in report.health.categories:
                cat_name = c.name.capitalize()
                score_str = f"`{int(round(c.score))}/100`" if c.available else "`N/A`"
                weight_str = f"{c.weight:.2f}"
                status_str = "Available" if c.available else "Excluded"
                lines.append(
                    f"| {cat_name} | {score_str} | {weight_str} | {status_str} |"
                )
            lines.append("")

            if report.health.recommendations:
                lines.append("### Top Priority Recommendations")
                lines.append("")
                for idx, rec in enumerate(report.health.recommendations, start=1):
                    lines.append(f"{idx}. {rec}")
                lines.append("")

        # Project Statistics
        if report.scan:
            lines.append("## Project Statistics")
            lines.append("")
            lines.append(f"- **Total Files**: {report.scan.total_files}")
            lines.append(f"- **Python Files**: {report.scan.python_files}")
            lines.append(f"- **Directories**: {report.scan.directories}")
            lines.append(f"- **Lines of Code**: {report.scan.total_lines}")
            size_kb = report.scan.total_size_bytes / 1024.0
            lines.append(f"- **Project Size**: {size_kb:.1f} KB")
            lines.append("")

        # Analyzer Summaries
        lines.append("## Analyzer Summaries")
        lines.append("")

        if report.quality:
            lines.append("### Code Quality")
            lines.append(f"- Total Findings: {report.quality.total_findings}")
            lines.append(f"- Ruff Findings: {report.quality.ruff_findings}")
            lines.append(f"- Long Functions: {report.quality.long_functions}")
            lines.append(f"- Deep Nesting: {report.quality.deep_nesting}")
            lines.append(f"- TODO/FIXME: {report.quality.todo_fixme_count}")
            lines.append(
                f"- Duplicate Functions: {report.quality.duplicate_function_count}"
            )
            lines.append("")

        if report.security:
            lines.append("### Security")
            lines.append(f"- Total Security Findings: {report.security.total_findings}")
            sev_map = report.security.severity_counts
            high_c = sev_map.get("high", 0)
            med_c = sev_map.get("medium", 0)
            low_c = sev_map.get("low", 0)
            lines.append(f"- High: {high_c}, Medium: {med_c}, Low: {low_c}")
            lines.append("")

        if report.complexity:
            lines.append("### Complexity")
            mi = report.complexity.maintainability_index
            avg_c = report.complexity.average_complexity
            max_c = report.complexity.max_complexity
            high_comp = report.complexity.high_complexity_findings
            lines.append(f"- Maintainability Index: {mi:.1f}/100")
            lines.append(f"- Average Complexity: {avg_c:.1f}")
            lines.append(f"- Maximum Complexity: {max_c}")
            lines.append(f"- High Complexity Findings: {high_comp}")
            lines.append("")

        if report.dependencies:
            lines.append("### Dependencies")
            decl = len(report.dependencies.declared_dependencies)
            imp = len(report.dependencies.imported_packages)
            un = len(report.dependencies.potentially_unused)
            ms = len(report.dependencies.potentially_missing)
            vuln = report.dependencies.vulnerabilities_count
            lines.append(f"- Declared Dependencies: {decl}")
            lines.append(f"- Imported Third-Party: {imp}")
            lines.append(f"- Potentially Unused: {un}")
            lines.append(f"- Potentially Missing: {ms}")
            lines.append(f"- Vulnerabilities: {vuln}")
            lines.append("")

        if report.documentation:
            lines.append("### Documentation")
            cov = report.documentation.docstring_coverage
            mod_c = report.documentation.public_modules
            cls_c = report.documentation.public_classes
            fn_c = report.documentation.public_functions
            lines.append(f"- Docstring Coverage: {cov:.1f}%")
            lines.append(f"- Public Modules: {mod_c}")
            lines.append(f"- Public Classes: {cls_c}")
            lines.append(f"- Public Functions: {fn_c}")
            lines.append("")

        if report.git:
            lines.append("### Git Health")
            is_repo = "Yes" if report.git.repository_detected else "No"
            lines.append(f"- Repository Detected: {is_repo}")
            if report.git.repository_detected:
                has_ignore = "Yes" if report.git.gitignore_exists else "No"
                lines.append(f"- `.gitignore` Exists: {has_ignore}")
                lines.append(f"- Tracked Files: {report.git.tracked_files_count}")
                lines.append(f"- Untracked Files: {report.git.untracked_files_count}")
            lines.append("")

        # Detailed Findings List
        all_issues = report.all_issues()
        if all_issues:
            lines.append("## Detailed Findings")
            lines.append("")
            lines.append("| Category | Severity | Code | Location | Message |")
            lines.append("|---|---|---|---|---|")
            for issue in all_issues[:100]:
                cat = issue.category.capitalize()
                s_obj = issue.severity
                sev_val = s_obj.value if hasattr(s_obj, "value") else str(s_obj)
                sev = str(sev_val).upper()
                if issue.file and issue.line:
                    loc = f"`{issue.file}:{issue.line}`"
                else:
                    loc = issue.file or "-"
                msg = issue.message.replace("|", "\\|")
                lines.append(f"| {cat} | {sev} | `{issue.code}` | {loc} | {msg} |")
            if len(all_issues) > 100:
                lines.append("")
                lines.append(f"*...and {len(all_issues) - 100} more findings.*")
            lines.append("")

        return "\n".join(lines)
