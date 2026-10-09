import json
from datetime import datetime
from html import escape

# Dark Orchid severity palette (standard security colors on an orchid canvas)
_SEVERITY_COLORS = {
    "critical": "#FF5370",
    "high": "#FF9F43",
    "medium": "#F2D35E",
    "low": "#63D6A0",
    "info": "#B3A6BF",
}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


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

    # ---- Severity stat cards ----
    summary_html = "".join(
        f'<div class="stat">'
        f'<span class="dot" style="background:{_SEVERITY_COLORS.get(sev, "#B3A6BF")}"></span>'
        f'<span class="stat-label">{sev.capitalize()}</span>'
        f'<span class="stat-count">{count}</span>'
        f'</div>'
        for sev, count in sorted(summary.items(), key=lambda x: -_SEVERITY_ORDER.get(x[0], 0))
    )
    stats_block = f'<div class="stats">{summary_html}</div>' if findings else ""

    # ---- Findings rows ----
    rows = []
    for f in findings:
        color = _SEVERITY_COLORS.get(f.severity, "#B3A6BF")
        rows.append(f"""
        <tr>
          <td><span class="sev" style="background:{color}">{escape(f.severity.upper())}</span></td>
          <td>{escape(f.category)}</td>
          <td class="url">{escape(f.url)}</td>
          <td class="cwe">{escape(f.cwe)}<span class="owasp">{escape(f.owasp)}</span></td>
          <td>{escape(f.parameter)}</td>
          <td class="payload">{escape(f.payload)}</td>
          <td>{escape(f.evidence)}</td>
          <td>{escape(f.description)}</td>
          <td>{escape(f.source)}</td>
        </tr>""")

    if findings:
        table_html = (
            '<div class="card"><table><thead><tr>'
            "<th>Severity</th><th>Category</th><th>URL</th><th>CWE / OWASP</th>"
            "<th>Parameter</th><th>Payload</th><th>Evidence</th><th>Description</th><th>Source</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
        )
    else:
        table_html = '<div class="empty">No vulnerabilities detected by the checks that ran.</div>'

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulynx — Scan Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}

  body {{
    margin: 0;
    padding: 2.5rem 2rem 4rem;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 15px;
    line-height: 1.55;
    color: #F1ECF7;
    background: #100D16;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }}

  .wrap {{ max-width: 1400px; margin: 0 auto; }}

  header {{ margin-bottom: 2rem; }}

  h1 {{
    margin: 0 0 0.5rem;
    font-size: 1.85rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: #F1ECF7;
  }}

  h1 .accent {{ color: #A970FF; }}

  .meta {{
    color: #B3A6BF;
    font-size: 0.92rem;
  }}
  .meta strong {{ color: #D9C0FF; font-weight: 600; }}
  .meta .sep {{ color: #50336A; margin: 0 0.5rem; }}

  /* ---- Severity summary cards ---- */
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.75rem;
  }}

  .stat {{
    display: flex;
    align-items: center;
    gap: 0.65rem;
    padding: 0.9rem 1rem;
    background: #21152D;
    border: 1px solid #50336A;
    border-radius: 10px;
    font-size: 0.9rem;
  }}

  .stat .dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
    box-shadow: 0 0 0 3px rgba(169, 112, 255, 0.08);
  }}

  .stat-label {{ color: #B3A6BF; font-weight: 500; }}

  .stat-count {{
    margin-left: auto;
    color: #F1ECF7;
    font-weight: 700;
    font-size: 1.05rem;
  }}

  /* ---- Findings card + table ---- */
  .card {{
    background: #21152D;
    border: 1px solid #50336A;
    border-radius: 14px;
    overflow: hidden;
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.4);
  }}

  table {{
    border-collapse: collapse;
    width: 100%;
  }}

  thead th {{
    background: #1A1029;
    color: #B3A6BF;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 1rem;
    text-align: left;
    border-bottom: 1px solid #50336A;
  }}

  tbody td {{
    padding: 1rem;
    border-bottom: 1px solid #30203F;
    font-size: 0.88rem;
    vertical-align: top;
    color: #F1ECF7;
  }}

  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr {{ transition: background 120ms ease; }}
  tbody tr:hover {{ background: #30203F; }}

  .sev {{
    display: inline-block;
    padding: 0.25rem 0.7rem;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 800;
    letter-spacing: 0.05em;
    color: #100D16;
  }}

  .url {{
    max-width: 280px;
    word-break: break-all;
    color: #D9C0FF;
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 0.82rem;
  }}

  .payload {{
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    max-width: 220px;
    word-break: break-all;
    color: #FF9F43;
    font-size: 0.82rem;
  }}

  .cwe {{
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 0.82rem;
    color: #D9C0FF;
    white-space: nowrap;
    font-weight: 600;
  }}

  .cwe .owasp {{
    display: block;
    font-family: inherit;
    font-size: 0.72rem;
    color: #B3A6BF;
    font-weight: 400;
    margin-top: 3px;
  }}

  .empty {{
    padding: 3.5rem 2rem;
    text-align: center;
    color: #B3A6BF;
    background: #21152D;
    border: 1px solid #50336A;
    border-radius: 14px;
    font-size: 0.95rem;
  }}
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>Vulynx <span class="accent">Scan Report</span></h1>
      <div class="meta">
        Target: <strong>{escape(target_url)}</strong>
        <span class="sep">·</span>
        Generated: <strong>{generated_at}</strong>
        <span class="sep">·</span>
        Total findings: <strong>{len(findings)}</strong>
      </div>
    </header>

    {stats_block}

    {table_html}
  </div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)