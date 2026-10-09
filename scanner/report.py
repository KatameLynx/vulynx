import json
from datetime import datetime
from html import escape

_SEVERITY_COLORS = {
    "critical": "#7a1f1f",
    "high": "#c0392b",
    "medium": "#d68910",
    "low": "#2471a3",
    "info": "#5d6d7e",
}


def write_json_report(collector, target_url, path):
    data = {
        "target": target_url,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": collector.count_by_severity(),
        "findings": [f.to_dict() for f in collector.all()],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def write_html_report(collector, target_url, path):
    findings = collector.all()
    summary = collector.count_by_severity()

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    summary_html = "".join(
        f'<span class="badge" style="background:{_SEVERITY_COLORS.get(sev, "#888")}">'
        f'{sev.upper()}: {count}</span>'
        for sev, count in sorted(summary.items(), key=lambda x: -order.get(x[0], 0))
    )

    rows = []
    for f in findings:
        color = _SEVERITY_COLORS.get(f.severity, "#888")
        rows.append(f"""
        <tr>
          <td><span class="sev" style="background:{color}">{escape(f.severity.upper())}</span></td>
          <td>{escape(f.category)}</td>
          <td class="url">{escape(f.url)}</td>
          <td class="cwe">{escape(f.cwe)}<br><span class="owasp">{escape(f.owasp)}</span></td>
          <td>{escape(f.parameter)}</td>
          <td class="payload">{escape(f.payload)}</td>
          <td>{escape(f.evidence)}</td>
          <td>{escape(f.description)}</td>
          <td>{escape(f.source)}</td>
        </tr>""")

    if findings:
        table_html = (
            "<table><thead><tr>"
            "<th>Severity</th><th>Category</th><th>URL</th><th>CWE / OWASP</th><th>Parameter</th>"
            "<th>Payload</th><th>Evidence</th><th>Description</th><th>Source</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    else:
        table_html = '<div class="empty">No vulnerabilities detected by the checks that ran.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Web Vulnerability Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #222; background: #f7f7f8; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #666; margin-bottom: 1.5rem; }}
  .badge {{ display: inline-block; color: #fff; padding: 4px 10px; border-radius: 12px; margin-right: 8px; font-size: 0.85rem; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 0.88rem; vertical-align: top; }}
  th {{ background: #2c3e50; color: #fff; }}
  .sev {{ color: #fff; padding: 2px 8px; border-radius: 8px; font-size: 0.78rem; font-weight: 700; }}
  .url {{ max-width: 260px; word-break: break-all; }}
  .payload {{ font-family: monospace; max-width: 220px; word-break: break-all; color: #a33; }}
  .cwe {{ font-size: 0.8rem; color: #555; white-space: nowrap; }}
  .owasp {{ font-size: 0.75rem; color: #888; }}
  tr:hover {{ background: #fafafa; }}
  .empty {{ padding: 2rem; text-align: center; color: #666; }}
</style>
</head>
<body>
  <h1>Web Vulnerability Scan Report</h1>
  <div class="meta">
    Target: <strong>{escape(target_url)}</strong> &nbsp;|&nbsp;
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
    Total findings: {len(findings)}
  </div>
  <div>{summary_html if findings else ''}</div>
  <br>
  {table_html}
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)