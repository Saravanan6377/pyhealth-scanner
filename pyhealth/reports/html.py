"""HTML Report Generator for PyHealth."""

from __future__ import annotations

import jinja2

from pyhealth.models import ProjectReport
from pyhealth.reports.base import Reporter

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PyHealth Report - {{ project_name }}</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --success: #22c55e;
      --warning: #eab308;
      --danger: #ef4444;
      --info: #a855f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI',
        Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2rem 1rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    header {
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
    }
    h1 { font-size: 2rem; color: var(--primary); margin-bottom: 0.5rem; }
    .subtitle { color: var(--text-muted); font-size: 0.95rem; }

    .hero {
      display: flex;
      flex-wrap: wrap;
      gap: 1.5rem;
      align-items: center;
      background: var(--card-bg);
      padding: 1.5rem 2rem;
      border-radius: 12px;
      border: 1px solid var(--border);
      margin-bottom: 2rem;
    }
    .score-box {
      text-align: center;
      padding-right: 2rem;
      border-right: 1px solid var(--border);
    }
    .score-value {
      font-size: 3.5rem;
      font-weight: 800;
      color: var(--primary);
      line-height: 1;
    }
    .score-label {
      color: var(--text-muted);
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-top: 0.25rem;
    }
    .grade-badge {
      display: inline-block;
      padding: 0.35rem 1rem;
      border-radius: 9999px;
      font-weight: 700;
      font-size: 1.1rem;
      background: var(--primary);
      color: #0f172a;
      margin-top: 0.5rem;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }
    .card-title {
      color: var(--text-muted);
      font-size: 0.85rem;
      text-transform: uppercase;
      margin-bottom: 0.5rem;
    }
    .card-val { font-size: 1.5rem; font-weight: 700; }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
      background: var(--card-bg);
      border-radius: 8px;
      overflow: hidden;
    }
    th, td {
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 0.9rem;
    }
    th {
      background: #0f172a;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
    }
    tr:last-child td { border-bottom: none; }

    .badge {
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
    }
    .badge-critical { background: #7f1d1d; color: #fca5a5; }
    .badge-high { background: #991b1b; color: #fca5a5; }
    .badge-medium { background: #713f12; color: #fef08a; }
    .badge-low { background: #14532d; color: #86efac; }
    .badge-info { background: #581c87; color: #e9d5ff; }

    .rec-list { list-style: none; padding: 0; }
    .rec-item {
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 0.75rem 1rem;
      border-radius: 6px;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .rec-num {
      background: var(--primary);
      color: #0f172a;
      font-weight: 700;
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.8rem;
    }

    section { margin-bottom: 2.5rem; }
    h2 {
      font-size: 1.4rem;
      margin-bottom: 1rem;
      color: var(--text);
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.85rem;
      background: #0f172a;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🩺 PyHealth Report</h1>
      <div class="subtitle">
        Project: <code>{{ project_name }}</code> | Scanned: {{ project_path }}
      </div>
    </header>

    {% if report.health %}
    <section>
      <div class="hero">
        <div class="score-box">
          <div class="score-value">
            {{ report.health.overall_score | round | int }}
          </div>
          <div class="score-label">Overall Health</div>
          <div class="grade-badge">{{ report.health.grade }}</div>
        </div>
        <div style="flex: 1;">
          <h3 style="margin-bottom: 0.75rem; color: var(--text-muted);
            font-size: 0.9rem; text-transform: uppercase;">
            Category Breakdown
          </h3>
          <div style="display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 0.75rem;">
            {% for cat in report.health.categories %}
            <div style="background: #0f172a; padding: 0.5rem 0.75rem;
              border-radius: 6px; border: 1px solid var(--border);">
              <div style="font-size: 0.75rem; color: var(--text-muted);
                text-transform: capitalize;">{{ cat.name }}</div>
              <div style="font-weight: 700; font-size: 1.1rem;">
                {% if cat.available %}
                  {{ cat.score | round | int }}/100
                {% else %}
                  N/A
                {% endif %}
              </div>
            </div>
            {% endfor %}
          </div>
        </div>
      </div>
    </section>

    {% if report.health.recommendations %}
    <section>
      <h2>Top Priority Recommendations</h2>
      <ul class="rec-list">
        {% for rec in report.health.recommendations %}
        <li class="rec-item">
          <div class="rec-num">{{ loop.index }}</div>
          <div>{{ rec }}</div>
        </li>
        {% endfor %}
      </ul>
    </section>
    {% endif %}
    {% endif %}

    {% if report.scan %}
    <section>
      <h2>Project Overview</h2>
      <div class="grid">
        <div class="card">
          <div class="card-title">Total Files</div>
          <div class="card-val">{{ report.scan.total_files }}</div>
        </div>
        <div class="card">
          <div class="card-title">Python Files</div>
          <div class="card-val">{{ report.scan.python_files }}</div>
        </div>
        <div class="card">
          <div class="card-title">Lines of Code</div>
          <div class="card-val">{{ report.scan.total_lines }}</div>
        </div>
        <div class="card">
          <div class="card-title">Total Size</div>
          <div class="card-val">
            {{ (report.scan.total_size_bytes / 1024) | round(1) }} KB
          </div>
        </div>
      </div>
    </section>
    {% endif %}

    {% if all_issues %}
    <section>
      <h2>Detailed Findings ({{ all_issues | length }})</h2>
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Severity</th>
            <th>Code</th>
            <th>Location</th>
            <th>Finding</th>
          </tr>
        </thead>
        <tbody>
          {% for issue in all_issues[:150] %}
          <tr>
            <td style="text-transform: capitalize; color: var(--text-muted);">
              {{ issue.category }}
            </td>
            <td>
              <span class="badge badge-{{ issue.severity | string | lower }}">
                {{ issue.severity | string | upper }}
              </span>
            </td>
            <td><code>{{ issue.code }}</code></td>
            <td>
              {% if issue.file %}
                <code>{{ issue.file }}
                {% if issue.line %}:{{ issue.line }}{% endif %}</code>
              {% else %}
                -
              {% endif %}
            </td>
            <td>{{ issue.message }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% if all_issues | length > 150 %}
      <p style="margin-top: 0.75rem; color: var(--text-muted);
        font-size: 0.85rem;">
        Showing top 150 of {{ all_issues | length }} issues.
      </p>
      {% endif %}
    </section>
    {% endif %}
  </div>
</body>
</html>
"""


class HtmlReporter(Reporter):
    """Renders a ProjectReport into a self-contained, offline HTML string."""

    def render(self, report: ProjectReport) -> str:
        project_name = report.project_path.name or str(report.project_path)
        all_issues = report.all_issues()

        template = jinja2.Template(_HTML_TEMPLATE)
        return template.render(
            project_name=project_name,
            project_path=str(report.project_path),
            report=report,
            all_issues=all_issues,
        )
