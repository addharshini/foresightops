"""HTML report generator for ForesightOps."""

from pathlib import Path
from .analyzer import AnalysisResult


RISK_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
}

RISK_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH": "#fff7ed",
    "MEDIUM": "#fffbeb",
    "LOW": "#f0fdf4",
}


def _gauge_svg(score: int, label: str) -> str:
    color = RISK_COLORS.get(label, "#6b7280")
    # Simple arc gauge using SVG
    r = 60
    cx, cy = 80, 80
    circumference = 3.14159 * r
    dash = (score / 100) * circumference
    return f"""
    <svg viewBox="0 0 160 100" xmlns="http://www.w3.org/2000/svg" style="width:180px">
      <path d="M 20 80 A {r} {r} 0 0 1 140 80" fill="none" stroke="#e5e7eb" stroke-width="14" stroke-linecap="round"/>
      <path d="M 20 80 A {r} {r} 0 0 1 140 80" fill="none" stroke="{color}" stroke-width="14"
            stroke-linecap="round"
            stroke-dasharray="{dash:.1f} {circumference:.1f}"
            transform="rotate(180, {cx}, {cy})"/>
      <text x="{cx}" y="72" text-anchor="middle" font-size="22" font-weight="bold" fill="{color}">{score}</text>
      <text x="{cx}" y="88" text-anchor="middle" font-size="11" fill="#6b7280">{label}</text>
    </svg>
    """


def generate_html_report(result: AnalysisResult, output_path: str) -> str:
    label_color = RISK_COLORS.get(result.risk_label, "#6b7280")
    label_bg = RISK_BG.get(result.risk_label, "#f9fafb")

    # Permission findings table rows
    findings_rows = ""
    for f in sorted(result.permission_findings, key=lambda x: -["LOW","MEDIUM","HIGH","CRITICAL"].index(x.risk)):
        risk_color = RISK_COLORS.get(f.risk, "#6b7280")
        risk_bg = RISK_BG.get(f.risk, "#f9fafb")
        capabilities = "<br>".join(f"• {c}" for c in f.attacker_can)
        lateral = "Yes ⚠️" if f.lateral_movement else "No"
        lateral_targets = "<br>".join(f"→ {t}" for t in f.lateral_targets) if f.lateral_movement else "—"
        findings_rows += f"""
        <tr>
          <td style="font-family:monospace;font-weight:600">{f.permission}</td>
          <td><span style="background:{risk_bg};color:{risk_color};padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px">{f.risk}</span></td>
          <td style="font-size:13px;color:#374151">{capabilities}</td>
          <td style="font-size:13px;color:#6b7280">{lateral}</td>
          <td style="font-size:12px;color:#6b7280">{lateral_targets}</td>
        </tr>"""

    # Lateral movement table
    lateral_rows = ""
    for lp in result.lateral_paths:
        risk_color = RISK_COLORS.get(lp.risk, "#6b7280")
        risk_bg = RISK_BG.get(lp.risk, "#f9fafb")
        lateral_rows += f"""
        <tr>
          <td style="font-family:monospace;font-size:13px">{lp.from_permission}</td>
          <td style="font-size:13px;color:#374151">{lp.description}</td>
          <td style="font-size:13px;color:#6b7280">{lp.target}</td>
          <td><span style="background:{risk_bg};color:{risk_color};padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px">{lp.risk}</span></td>
        </tr>"""

    if not lateral_rows:
        lateral_rows = '<tr><td colspan="4" style="text-align:center;color:#16a34a;padding:12px">✓ No lateral movement paths identified</td></tr>'

    # Secrets table
    secrets_rows = ""
    for s in result.exposed_secrets:
        scope_color = "#dc2626" if s.scope == "org" else "#ea580c"
        secrets_rows += f"""
        <tr>
          <td style="font-family:monospace;font-weight:600">{s.name}</td>
          <td><span style="color:{scope_color};font-weight:600">{s.scope.upper()}</span></td>
          <td>{s.environment or "—"}</td>
        </tr>"""

    if not secrets_rows:
        secrets_rows = '<tr><td colspan="3" style="text-align:center;color:#16a34a;padding:12px">✓ No secrets detected in scope</td></tr>'

    # Remediation cards
    remediation_cards = ""
    priority_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sorted_rems = sorted(result.remediations, key=lambda r: priority_order.index(r.priority) if r.priority in priority_order else 99)
    for rem in sorted_rems:
        r_color = RISK_COLORS.get(rem.priority, "#6b7280")
        r_bg = RISK_BG.get(rem.priority, "#f9fafb")
        code_block = ""
        if rem.code_example:
            code_block = f'<pre style="background:#1f2937;color:#f9fafb;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;margin-top:8px">{rem.code_example}</pre>'
        remediation_cards += f"""
        <div style="border:1px solid {r_color}33;border-left:4px solid {r_color};background:{r_bg};border-radius:6px;padding:14px;margin-bottom:12px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            <span style="background:{r_bg};color:{r_color};padding:2px 8px;border-radius:4px;font-weight:700;font-size:11px;border:1px solid {r_color}44">{rem.priority}</span>
            <span style="font-weight:600;color:#111827;font-size:14px">{rem.finding}</span>
          </div>
          <p style="color:#374151;font-size:13px;margin:4px 0">{rem.action}</p>
          {code_block}
        </div>"""

    # Summary stats
    critical_count = sum(1 for f in result.permission_findings if f.risk == "CRITICAL")
    high_count = sum(1 for f in result.permission_findings if f.risk == "HIGH")
    lateral_count = len(result.lateral_paths)

    permissions_default_warning = ""
    if result.using_default_permissions:
        permissions_default_warning = """
        <div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:12px;margin-bottom:16px;display:flex;gap:10px;align-items:center">
          <span style="font-size:20px">⚠️</span>
          <div>
            <strong style="color:#dc2626">Default Permissions Active</strong>
            <p style="color:#7f1d1d;font-size:13px;margin:2px 0">
              No explicit <code>permissions:</code> block found in the workflow YAML.
              GitHub's over-permissive defaults were used — this is the most common supply chain attack vector.
            </p>
          </div>
        </div>"""

    id_token_warning = ""
    if result.has_id_token:
        id_token_warning = """
        <div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:12px;margin-bottom:16px;display:flex;gap:10px;align-items:center">
          <span style="font-size:20px">🔑</span>
          <div>
            <strong style="color:#dc2626">OIDC Cloud Token Exposure</strong>
            <p style="color:#7f1d1d;font-size:13px;margin:2px 0">
              <code>id-token: write</code> is set. An attacker could mint cloud credentials (AWS/GCP/Azure) directly from this run.
            </p>
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ForesightOps — Blast Radius Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f3f4f6; color: #111827; }}
    .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); color: white; padding: 32px 48px; }}
    .header h1 {{ font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }}
    .header h1 span {{ color: #38bdf8; }}
    .header p {{ color: #94a3b8; margin-top: 4px; font-size: 14px; }}
    .badge {{ display: inline-block; background: #0ea5e9; color: white; padding: 2px 10px; border-radius: 99px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; margin-left: 8px; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
    .card {{ background: white; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 24px; }}
    .card h2 {{ font-size: 16px; font-weight: 700; color: #1f2937; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #e5e7eb; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ text-align: left; font-size: 12px; font-weight: 600; color: #6b7280; padding: 8px 12px; background: #f9fafb; border-bottom: 1px solid #e5e7eb; text-transform: uppercase; letter-spacing: 0.5px; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
    .stat {{ background: white; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    .stat-num {{ font-size: 32px; font-weight: 800; }}
    .stat-label {{ font-size: 12px; color: #6b7280; margin-top: 2px; }}
    .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
    .meta-row {{ display: flex; gap: 8px; font-size: 13px; padding: 4px 0; }}
    .meta-key {{ color: #6b7280; min-width: 140px; }}
    .meta-val {{ color: #111827; font-weight: 500; }}
    .footer {{ text-align: center; padding: 24px; color: #9ca3af; font-size: 12px; }}
    code {{ font-family: 'SFMono-Regular', Consolas, monospace; background: #f3f4f6; padding: 1px 5px; border-radius: 3px; font-size: 12px; }}
    a {{ color: #0ea5e9; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>

<div class="header">
  <h1>Foresight<span>Ops</span> <span class="badge">v1.0</span></h1>
  <p>CI/CD Blast Radius Analyzer — Automated Remediation Before Vulnerability Reaches Code</p>
</div>

<div class="container">

  <!-- Summary Stats -->
  <div class="stat-grid">
    <div class="stat">
      {_gauge_svg(result.risk_score, result.risk_label)}
      <div class="stat-label">Overall Risk Score</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:{RISK_COLORS.get('CRITICAL','#dc2626')}">{critical_count}</div>
      <div class="stat-label">Critical Findings</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:{RISK_COLORS.get('HIGH','#ea580c')}">{high_count}</div>
      <div class="stat-label">High Findings</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:{RISK_COLORS.get('HIGH','#ea580c') if lateral_count else '#16a34a'}">{lateral_count}</div>
      <div class="stat-label">Lateral Movement Paths</div>
    </div>
  </div>

  <!-- Run Metadata -->
  <div class="card">
    <h2>Workflow Run Details</h2>
    {permissions_default_warning}
    {id_token_warning}
    <div class="meta-grid">
      <div class="meta-row"><span class="meta-key">Repository</span><span class="meta-val">{result.owner}/{result.repo}</span></div>
      <div class="meta-row"><span class="meta-key">Run ID</span><span class="meta-val"><a href="{result.run_url}" target="_blank">#{result.run_id}</a></span></div>
      <div class="meta-row"><span class="meta-key">Workflow</span><span class="meta-val">{result.workflow_name}</span></div>
      <div class="meta-row"><span class="meta-key">Triggered By</span><span class="meta-val">{result.triggered_by}</span></div>
      <div class="meta-row"><span class="meta-key">Started At</span><span class="meta-val">{result.run_started_at}</span></div>
      <div class="meta-row"><span class="meta-key">Permissions Source</span><span class="meta-val">{'⚠️ GitHub Defaults' if result.using_default_permissions else '✓ Explicit workflow YAML'}</span></div>
      <div class="meta-row"><span class="meta-key">OIDC Token</span><span class="meta-val">{'🔴 Enabled (cloud access risk)' if result.has_id_token else '✓ Not enabled'}</span></div>
      <div class="meta-row"><span class="meta-key">Secrets in Scope</span><span class="meta-val">{len(result.exposed_secrets)}</span></div>
      <div class="meta-row"><span class="meta-key">Analysis Time</span><span class="meta-val">{result.analysis_timestamp}</span></div>
    </div>
  </div>

  <!-- Permission Findings -->
  <div class="card">
    <h2>Token Permission Analysis — What an Attacker Could Do</h2>
    <table>
      <thead>
        <tr>
          <th>Permission</th><th>Risk</th><th>Attacker Capabilities</th><th>Lateral Movement</th><th>Movement Targets</th>
        </tr>
      </thead>
      <tbody>{findings_rows}</tbody>
    </table>
  </div>

  <!-- Lateral Movement -->
  <div class="card">
    <h2>Lateral Movement Paths</h2>
    <table>
      <thead><tr><th>Source Permission</th><th>Attack Vector</th><th>Reachable Target</th><th>Risk</th></tr></thead>
      <tbody>{lateral_rows}</tbody>
    </table>
  </div>

  <!-- Exposed Secrets -->
  <div class="card">
    <h2>Exposed Secrets ({len(result.exposed_secrets)} in scope)</h2>
    <table>
      <thead><tr><th>Secret Name</th><th>Scope</th><th>Environment</th></tr></thead>
      <tbody>{secrets_rows}</tbody>
    </table>
  </div>

  <!-- Remediations -->
  <div class="card">
    <h2>Remediation Steps — Prioritized</h2>
    {remediation_cards}
  </div>

</div>

<div class="footer">
  Generated by <strong>ForesightOps</strong> v1.0 &nbsp;·&nbsp; {result.analysis_timestamp} &nbsp;·&nbsp;
  Not another scanner — automated blast radius analysis before the vulnerability reaches your code.
</div>

</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
