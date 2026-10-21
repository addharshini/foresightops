"""HTML report generator for ForesightOps."""

import html as html_lib
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

# ---------------------------------------------------------------------------
# Known supply chain attacks — hardcoded from socket.dev/blog research
# Last updated: 2026-10-18
# ---------------------------------------------------------------------------
KNOWN_ATTACKS = [
    {
        "id": "keyv-cacheable",
        "name": "keyv & cacheable — Self-Propagating Worm",
        "date": "Aug 4, 2026",
        "severity": "CRITICAL",
        "source_url": "https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain",
        "packages": ["keyv", "cacheable", "flat-cache", "file-entry-cache", "cacheable-request", "cache-manager"],
        "dangerous_permissions": ["packages", "id-token"],
        "what_happened": "Compromised jaredwray npm account pushed malicious keyv, cacheable, flat-cache and 6 more packages. Payload stole npm tokens and republished trojanized versions of other packages — a self-propagating worm. Hit indirectly via: eslint → file-entry-cache → flat-cache → keyv.",
        "what_stolen": "npm publish tokens, AWS/GCP/Azure creds, GitHub OIDC tokens, Vault tokens, all CI env vars",
        "generic_remediation": "Scope packages: write and id-token: write to the publish job only. Rotate all secrets from any run that installed these packages.",
        "specific_remediation": "keyv@4.5.4  |  flat-cache@3.2.0  |  file-entry-cache@6.0.1  |  cacheable-request@10.2.14\nMalicious: keyv@6.0.0, cacheable@2.5.1 — check lockfile.",
        "code_example": (
            "jobs:\n"
            "  build:\n"
            "    permissions:\n"
            "      contents: read      # no packages: write here\n"
            "  publish:\n"
            "    permissions:\n"
            "      packages: write\n"
            "      id-token: write"
        ),
    },
    {
        "id": "jscrambler",
        "name": "jscrambler — Native Infostealer in npm Package",
        "date": "Jul 11, 2026",
        "severity": "CRITICAL",
        "source_url": "https://socket.dev/blog/jscrambler-supply-chain-attack",
        "packages": ["jscrambler"],
        "dangerous_permissions": ["packages", "id-token"],
        "what_happened": "Stolen npm credential used to publish jscrambler@8.14.0 with a Rust native binary infostealer. Later versions moved the dropper into dist/index.js to bypass --ignore-scripts. ~15,800 weekly downloads.",
        "what_stolen": "All CI env vars, AWS/GCP/Azure creds, Claude Desktop MCP config, crypto wallet keys",
        "generic_remediation": "Pin all npm packages to exact versions. No ^ or ~ ranges for packages in secret-bearing CI workflows.",
        "specific_remediation": "Safe: jscrambler@8.22.0\nMalicious: 8.14.0, 8.16.0–8.18.0, 8.20.0",
        "code_example": (
            '# package.json\n'
            '"jscrambler": "8.22.0"   # not "^8.13.0"\n\n'
            "# workflow\n"
            "- run: npm install jscrambler@8.22.0"
        ),
    },
    {
        "id": "github-actions-cpanel",
        "name": "GitHub Actions Abuse — CI Runners as Attack Infrastructure",
        "date": "Jul 22, 2026",
        "severity": "CRITICAL",
        "source_url": "https://socket.dev/blog/github-actions-abuse-powers-cpanel-and-whm-exploitation",
        "packages": [],
        "dangerous_permissions": ["actions", "contents"],
        "what_happened": "583 malicious workflow files injected into 10 Packagist packages. Workflows ran on GitHub runners with 350-min timeouts to exploit CVE-2026-41940 (cPanel/WHM) using CI as free attack infrastructure.",
        "what_stolen": "AWS keys, GitHub/GitLab tokens, Stripe keys, SSH material, DB credentials from cPanel servers",
        "generic_remediation": "Pin all actions to full commit SHAs. Set timeout-minutes ≤ 15 on every job.",
        "specific_remediation": "actions/checkout@v4  →  actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "code_example": (
            "jobs:\n"
            "  build:\n"
            "    timeout-minutes: 15\n"
            "    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2"
        ),
    },
    {
        "id": "asyncapi",
        "name": "AsyncAPI — Miasma Botnet via OIDC Trusted Publishing",
        "date": "Jul 14, 2026",
        "severity": "CRITICAL",
        "source_url": "https://socket.dev/blog/asyncapi-supply-chain-attack",
        "packages": ["@asyncapi/generator", "@asyncapi/generator-helpers", "@asyncapi/generator-components", "@asyncapi/specs"],
        "dangerous_permissions": ["id-token", "packages"],
        "what_happened": "4 @asyncapi/* packages compromised via stolen GitHub OIDC token (id-token: write). Malware ran at import time (not install). Stage 2 from IPFS installed the Miasma persistent botnet.",
        "what_stolen": "All CI runner secrets, persistent C2 access, npm tokens for further propagation",
        "generic_remediation": "Never set id-token: write at workflow level — scope it to the publish job only, behind a protected-tag condition.",
        "specific_remediation": "Malicious: @asyncapi/generator@3.3.1, @asyncapi/specs@6.11.2\nSafe: @asyncapi/generator@3.3.0, @asyncapi/specs@6.11.1",
        "code_example": (
            "jobs:\n"
            "  publish:\n"
            "    if: startsWith(github.ref, 'refs/tags/v')\n"
            "    permissions:\n"
            "      id-token: write   # scoped here only\n"
            "      contents: read"
        ),
    },
    {
        "id": "mastra",
        "name": "Mastra — 141 Packages via Rogue npm Account",
        "date": "Jun 17, 2026",
        "severity": "CRITICAL",
        "source_url": "https://socket.dev/blog/mastra-npm-packages-compromised",
        "packages": ["@mastra/core", "@mastra/rag", "@mastra/memory", "@mastra/cli"],
        "dangerous_permissions": ["packages", "contents"],
        "what_happened": "Rogue npm account (ehindero) mass-published 141 @mastra/* packages bypassing CI. Typosquatted dep easy-day-js@1.11.22 (fake dayjs) injected weaponized postinstall. @mastra/core has 918K+ weekly downloads.",
        "what_stolen": "CI runner env, 160+ crypto wallet browser extensions targeted, cross-platform persistence",
        "generic_remediation": "Enable npm provenance. Allowlist permitted publish accounts. Commit your lockfile.",
        "specific_remediation": "Check lockfile for easy-day-js (should not exist).\nPin: @mastra/core@0.10.5  (not ^0.10.5)",
        "code_example": (
            "# Audit transitive deps\n"
            "npm ls easy-day-js   # should return nothing\n\n"
            '"@mastra/core": "0.10.5"'
        ),
    },
    {
        "id": "miasma-leoplatform",
        "name": "Miasma / LeoPlatform — EDR Evasion + GITHUB_TOKEN Theft",
        "date": "Jun 25, 2026",
        "severity": "CRITICAL",
        "source_url": "https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem",
        "packages": ["@leo-platform/sdk", "rstreams-flow", "leo-connector-common", "codfish/semantic-release-action"],
        "dangerous_permissions": ["packages", "id-token", "actions"],
        "what_happened": "23 LeoPlatform npm packages + codfish/semantic-release-action compromised. 'Phantom Gyp' hid trigger in binding.gyp (no visible preinstall). Payload bypassed Node.js hooks via Bun, evaded CrowdStrike/SentinelOne/Defender, targeted GITHUB_TOKEN explicitly.",
        "what_stolen": "GITHUB_TOKEN, npm/PyPI tokens, AWS/Azure/GCP creds, SSH keys, .env files, Kubernetes configs",
        "generic_remediation": "Pin codfish/semantic-release-action to a full SHA immediately and rotate npm publish tokens.",
        "specific_remediation": "uses: codfish/semantic-release-action@v3  →  @<verified-SHA>\nCheck for .claude/setup.mjs (malware persistence hook).",
        "code_example": (
            "# Audit for persistence\n"
            "ls .claude/setup.mjs          # should not exist\n"
            "crontab -l | grep -i bun      # should return nothing\n\n"
            "- uses: codfish/semantic-release-action@<SHA>"
        ),
    },
    {
        "id": "joyfill",
        "name": "Joyfill — DEV#POPPER RAT, Blockchain C2 (DPRK)",
        "date": "Jul 28, 2026",
        "severity": "HIGH",
        "source_url": "https://socket.dev/blog/joyfill-npm-beta-releases-compromised",
        "packages": ["@joyfill/components", "@joyfill/layouts"],
        "dangerous_permissions": ["contents", "packages"],
        "what_happened": "Beta versions of @joyfill/* compromised with DEV#POPPER RAT. Activates at import (--ignore-scripts useless). C2 resolved via Tron blockchain. Full remote shell via Socket.IO. Linked to North Korea / PolinRider.",
        "what_stolen": "Full remote shell on CI runner, all accessible files, clipboard",
        "generic_remediation": "Never use beta/rc npm tags in CI. Gate production secrets behind named environments with approval.",
        "specific_remediation": "Malicious: @joyfill/components@4.0.0-rc24-2773-beta.4, @joyfill/layouts@0.1.2-2773.beta.0\nRemove all beta/rc versions and rotate secrets.",
        "code_example": (
            '"@joyfill/components": "3.x.x"   # not beta tags\n\n'
            "jobs:\n"
            "  deploy:\n"
            "    environment: production   # approval gate"
        ),
    },
    {
        "id": "polinrider",
        "name": "PolinRider — DPRK Campaign, 162 Malicious Artifacts",
        "date": "Jul 1, 2026",
        "severity": "CRITICAL",
        "source_url": "https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands",
        "packages": ["sevenspan/", "7span/"],
        "dangerous_permissions": ["contents", "packages"],
        "what_happened": "162 malicious artifacts across npm, Packagist, 80 Go modules, and a Chrome extension (DPRK / Contagious Interview). Accounts compromised via expired domain takeover. Git history rewritten with anti-dated force pushes. JS obfuscated beyond screen width or hidden in fake .woff2 files.",
        "what_stolen": "Developer workstation creds, CI runner env, all workflow secrets",
        "generic_remediation": "Pin all deps to exact versions or SHAs. Enable branch protection to block force pushes to main.",
        "specific_remediation": "Settings → Branches → Disallow force pushes\ngit reflog show origin/main | head -20  # audit rewrite history",
        "code_example": (
            "# Detect anti-dated commits\n"
            "git log --format='%ai %H %s' origin/main | head -20\n\n"
            "git config --global tag.gpgSign true"
        ),
    },
    {
        "id": "injective-sdk",
        "name": "Injective SDK — Key Derivation Hooked at Build Time",
        "date": "Jul 9, 2026",
        "severity": "HIGH",
        "source_url": "https://socket.dev/blog/compromised-injective-sdk-npm-package",
        "packages": ["@injectivelabs/sdk-ts", "@injectivelabs/wallet-ts", "@injectivelabs/networks"],
        "dangerous_permissions": ["id-token", "packages"],
        "what_happened": "Contributor account compromised; @injectivelabs/sdk-ts@1.20.21 published hooking fromMnemonic() and fromHex(). 17 downstream @injectivelabs/* packages auto-pinned the malicious version. Exfil blended with legit traffic. 310 downloads in ~20 min before revocation.",
        "what_stolen": "Blockchain wallet private keys and mnemonics captured at build/test time",
        "generic_remediation": "Require code review for all commits to main. Add npm audit --audit-level=high to CI.",
        "specific_remediation": "Malicious: @injectivelabs/sdk-ts@1.20.21  →  Safe: @1.20.20\nRotate any wallet keys used in CI tests.",
        "code_example": (
            "npm audit --audit-level=high\n\n"
            '"@injectivelabs/sdk-ts": "1.20.20"'
        ),
    },
    {
        "id": "alibaba-rat",
        "name": "Alibaba RAT — Dependency Confusion, 3 Months Undetected",
        "date": "Jul 28, 2026",
        "severity": "HIGH",
        "source_url": "https://socket.dev/blog/npm-rat-targets-alibaba",
        "packages": ["lib-mtop", "aone-cloud-cli", "cloud-config-fetcher", "local-config-parser"],
        "dangerous_permissions": ["contents", "packages"],
        "what_happened": "15 npm packages impersonated private @ali-scoped Alibaba packages, active undetected Apr–Jul 2026. Public version silently shadowed internal package in CI. VM sandbox escape via items.constructor.constructor. DingTalk lateral movement for internal pivot.",
        "what_stolen": "3 months of CI runner access, source code, all injected secrets, DingTalk messaging",
        "generic_remediation": "Force @ali/* packages to use internal registry via .npmrc so public npm cannot shadow them.",
        "specific_remediation": "Remove: lib-mtop, aone-cloud-cli, cloud-config-fetcher, local-config-parser\nAdd to .npmrc: @ali:registry=https://your-internal-registry",
        "code_example": (
            "# .npmrc\n"
            "@ali:registry=https://registry.internal.example.com\n\n"
            "npm ls lib-mtop   # should return nothing"
        ),
    },
]

THREAT_INTEL_LAST_UPDATED = "2026-10-18"


def _e(value) -> str:
    """HTML-escape a value so user-controlled strings cannot inject markup."""
    return html_lib.escape(str(value), quote=True)


def _check_attack(attack: dict, workflow_yaml: str, permissions_used: dict) -> tuple[str, str]:
    """
    Returns (status, reason).
    status: "COMPROMISED" | "AT RISK" | "SAFE"
    """
    yaml_lower = workflow_yaml.lower() if workflow_yaml else ""
    pkg_hits = [p for p in attack["packages"] if p.lower() in yaml_lower]
    package_found = len(pkg_hits) > 0

    perm_risky = any(
        permissions_used.get(p, "").lower() == "write"
        for p in attack["dangerous_permissions"]
    )

    if package_found and perm_risky:
        found_str = ", ".join(pkg_hits[:2])
        perm_str = ", ".join(
            f"{p}: write" for p in attack["dangerous_permissions"]
            if permissions_used.get(p, "").lower() == "write"
        )
        return "COMPROMISED", f"Package '{found_str}' found in workflow AND {perm_str} active"
    elif package_found:
        found_str = ", ".join(pkg_hits[:2])
        return "AT RISK", f"Package '{found_str}' found in workflow — check permissions and rotate secrets if recently installed"
    elif perm_risky:
        perm_str = ", ".join(
            f"{p}: write" for p in attack["dangerous_permissions"]
            if permissions_used.get(p, "").lower() == "write"
        )
        return "AT RISK", f"Dangerous permissions present ({perm_str}) — this workflow could be targeted by this attack pattern"
    else:
        return "SAFE", "Neither vulnerable packages nor dangerous permissions detected"


def _gauge_svg(score: int, label: str) -> str:
    color = RISK_COLORS.get(label, "#6b7280")
    r = 58
    cx, cy = 80, 82
    # Arc goes from left (22,82) to right (138,82) — left-to-right sweep
    # circumference of a half-circle
    circumference = 3.14159 * r
    dash = (score / 100) * circumference
    gap = circumference - dash
    return (
        f'<svg viewBox="0 0 160 105" xmlns="http://www.w3.org/2000/svg" style="width:190px">'
        # track (grey)
        f'<path d="M 22 82 A {r} {r} 0 0 1 138 82" fill="none" stroke="#e5e7eb" stroke-width="16" stroke-linecap="round"/>'
        # filled arc — starts from the left end of the track
        f'<path d="M 22 82 A {r} {r} 0 0 1 138 82" fill="none" stroke="{color}" stroke-width="16" '
        f'stroke-linecap="round" '
        f'stroke-dasharray="{dash:.1f} {circumference:.1f}" '
        f'stroke-dashoffset="0"/>'
        f'<text x="{cx}" y="74" text-anchor="middle" font-size="26" font-weight="800" fill="{color}">{score}</text>'
        f'<text x="{cx}" y="92" text-anchor="middle" font-size="12" font-weight="700" fill="{color}" letter-spacing="1">{_e(label)}</text>'
        f'</svg>'
    )


def _build_threat_intel_section(result: AnalysisResult) -> tuple[str, int, int, int]:
    """
    Returns (html_section, compromised_count, at_risk_count, safe_count).
    """
    compromised, at_risk, safe = 0, 0, 0
    cards_html = ""

    for attack in KNOWN_ATTACKS:
        status, reason = _check_attack(attack, result.workflow_yaml_content, result.permissions_used)
        if status == "COMPROMISED":
            compromised += 1
            status_color = "#dc2626"
            status_bg = "#fef2f2"
            status_border = "#fca5a5"
            status_icon = "&#x2716;"
        elif status == "AT RISK":
            at_risk += 1
            status_color = "#ea580c"
            status_bg = "#fff7ed"
            status_border = "#fed7aa"
            status_icon = "&#x26A0;"
        else:
            safe += 1
            status_color = "#16a34a"
            status_bg = "#f0fdf4"
            status_border = "#86efac"
            status_icon = "&#x2713;"

        sev_color = RISK_COLORS.get(attack["severity"], "#6b7280")
        sev_bg = RISK_BG.get(attack["severity"], "#f9fafb")

        code_html = ""
        if attack.get("code_example"):
            code_html = (
                f'<pre style="background:#1f2937;color:#f9fafb;padding:12px;border-radius:6px;'
                f'font-size:11px;overflow-x:auto;margin-top:8px;white-space:pre-wrap">'
                f'{_e(attack["code_example"])}</pre>'
            )

        cards_html += f"""
<div class="ti-card" id="ti-{_e(attack['id'])}">
  <div class="ti-card-header" onclick="toggleTI(this)">
    <div style="display:flex;align-items:flex-start;gap:12px;flex:1;min-width:0">
      <span style="background:{sev_bg};color:{sev_color};padding:2px 8px;border-radius:4px;
             font-weight:700;font-size:10px;white-space:nowrap;margin-top:2px;flex-shrink:0">
        {_e(attack['severity'])}
      </span>
      <div style="min-width:0">
        <div style="font-weight:700;font-size:14px;color:#111827;line-height:1.3">{_e(attack['name'])}</div>
        <div style="font-size:11px;color:#6b7280;margin-top:3px">{_e(attack['date'])} &nbsp;&middot;&nbsp;
          <a href="{_e(attack['source_url'])}" target="_blank" rel="noopener" style="color:#0ea5e9">
            Source &rarr;
          </a>
        </div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
      <span style="background:{status_bg};color:{status_color};border:1px solid {status_border};
             padding:4px 12px;border-radius:99px;font-weight:700;font-size:11px;white-space:nowrap">
        {status_icon} {_e(status)}
      </span>
      <span class="ti-chevron" style="color:#6b7280;font-size:14px;transition:transform .2s">&#x203A;</span>
    </div>
  </div>
  <div class="ti-card-body">
    <div style="background:{status_bg};border:1px solid {status_border};border-radius:6px;
         padding:10px 14px;margin-bottom:14px;font-size:13px;color:{status_color};font-weight:500">
      {_e(reason)}
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px">
      <div>
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
             color:#6b7280;margin-bottom:6px">What Happened</div>
        <p style="font-size:13px;color:#374151;line-height:1.6">{_e(attack['what_happened'])}</p>
      </div>
      <div>
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
             color:#6b7280;margin-bottom:6px">What Was Stolen</div>
        <p style="font-size:13px;color:#374151;line-height:1.6">{_e(attack['what_stolen'])}</p>
      </div>
    </div>
    <div style="border-top:1px solid #e5e7eb;padding-top:12px;margin-top:4px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
           color:#6b7280;margin-bottom:6px">Generic Remediation</div>
      <p style="font-size:13px;color:#374151;margin-bottom:10px;line-height:1.6">{_e(attack['generic_remediation'])}</p>
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
           color:#6b7280;margin-bottom:6px">Attack-Specific Fix</div>
      <p style="font-size:13px;color:#374151;margin-bottom:6px;white-space:pre-line">{_e(attack['specific_remediation'])}</p>
      {code_html}
    </div>
  </div>
</div>"""

    summary_bar = f"""
<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px">
  <div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:12px 20px;text-align:center;flex:1;min-width:80px">
    <div style="font-size:28px;font-weight:800;color:#dc2626">{compromised}</div>
    <div style="font-size:11px;color:#7f1d1d;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Compromised</div>
  </div>
  <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:12px 20px;text-align:center;flex:1;min-width:80px">
    <div style="font-size:28px;font-weight:800;color:#ea580c">{at_risk}</div>
    <div style="font-size:11px;color:#7c2d12;font-weight:600;text-transform:uppercase;letter-spacing:.5px">At Risk</div>
  </div>
  <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:12px 20px;text-align:center;flex:1;min-width:80px">
    <div style="font-size:28px;font-weight:800;color:#16a34a">{safe}</div>
    <div style="font-size:11px;color:#14532d;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Safe</div>
  </div>
  <div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;padding:12px 20px;text-align:center;flex:1;min-width:80px">
    <div style="font-size:28px;font-weight:800;color:#0284c7">{len(KNOWN_ATTACKS)}</div>
    <div style="font-size:11px;color:#075985;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Attacks Checked</div>
  </div>
</div>
<div style="font-size:11px;color:#6b7280;margin-bottom:16px">
  <strong>How this works:</strong>
  COMPROMISED = vulnerable package found in workflow YAML AND dangerous permission active &nbsp;&middot;&nbsp;
  AT RISK = either condition &nbsp;&middot;&nbsp;
  SAFE = neither &nbsp;&middot;&nbsp;
  Last updated: {THREAT_INTEL_LAST_UPDATED} &nbsp;&middot;&nbsp;
  Source: <a href="https://socket.dev/blog" target="_blank" rel="noopener" style="color:#0ea5e9">socket.dev/blog</a>
</div>"""

    section_html = f"""
<div class="card" id="section-threatintel">
  <h2>Recent Supply Chain Attacks &mdash; Is Your Workflow Affected?</h2>
  {summary_bar}
  <div id="ti-cards">{cards_html}</div>
</div>"""

    return section_html, compromised, at_risk, safe


def generate_html_report(result: AnalysisResult, output_path: str) -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    # Permission findings rows
    findings_rows = ""
    for f in sorted(result.permission_findings,
                    key=lambda x: -["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x.risk)):
        rc = RISK_COLORS.get(f.risk, "#6b7280")
        rb = RISK_BG.get(f.risk, "#f9fafb")
        capabilities = "<br>".join(f"&bull; {_e(c)}" for c in f.attacker_can)
        findings_rows += (
            f'<tr>'
            f'<td style="font-family:monospace;font-weight:600">{_e(f.permission)}</td>'
            f'<td><span style="background:{rb};color:{rc};padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px">{_e(f.risk)}</span></td>'
            f'<td style="font-size:13px;color:#374151">{capabilities}</td>'
            f'</tr>'
        )

    # Lateral movement rows
    lateral_rows = ""
    for lp in result.lateral_paths:
        rc = RISK_COLORS.get(lp.risk, "#6b7280")
        rb = RISK_BG.get(lp.risk, "#f9fafb")
        lateral_rows += (
            f'<tr>'
            f'<td style="font-family:monospace;font-size:13px">{_e(lp.from_permission)}</td>'
            f'<td style="font-size:13px;color:#374151">{_e(lp.description)}</td>'
            f'<td style="font-size:13px;color:#6b7280">{_e(lp.target)}</td>'
            f'<td style="font-size:12px;color:#6b7280">{_e(lp.scope)}</td>'
            f'<td><span style="background:{rb};color:{rc};padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px">{_e(lp.risk)}</span></td>'
            f'</tr>'
        )
    if not lateral_rows:
        lateral_rows = '<tr><td colspan="5" style="text-align:center;color:#16a34a;padding:12px">&#x2713; No lateral movement paths identified</td></tr>'

    # Secrets rows
    secrets_rows = ""
    for s in result.exposed_secrets:
        scope_color = "#dc2626" if s.scope == "org" else ("#7c3aed" if s.scope == "environment" else "#ea580c")
        env_label = _e(s.environment) if s.environment else "&mdash;"
        secrets_rows += (
            f'<tr>'
            f'<td style="font-family:monospace;font-weight:600">{_e(s.name)}</td>'
            f'<td><span style="color:{scope_color};font-weight:600">{_e(s.scope.upper())}</span></td>'
            f'<td>{env_label}</td>'
            f'</tr>'
        )
    if not secrets_rows:
        no_secrets_note = ""
        if result.secrets_note:
            no_secrets_note = f' <span style="color:#d97706;font-size:12px">({_e(result.secrets_note)})</span>'
        secrets_rows = f'<tr><td colspan="3" style="text-align:center;color:#16a34a;padding:12px">&#x2713; No secrets detected in scope{no_secrets_note}</td></tr>'

    # Remediations — git-diff style
    priority_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    remediation_cards = ""
    for rem in sorted(result.remediations,
                      key=lambda r: priority_order.index(r.priority) if r.priority in priority_order else 99):
        rc = RISK_COLORS.get(rem.priority, "#6b7280")
        rb = RISK_BG.get(rem.priority, "#f9fafb")

        # Build git-diff block: - red (current/bad), + green (fixed), space = context
        diff_html = ""
        if rem.code_example:
            lines = rem.code_example.split("\n")
            diff_lines = ""
            for line in lines:
                escaped = _e(line)
                if line.startswith("-"):
                    diff_lines += (
                        f'<span style="display:block;background:#3d1212;color:#ff8080;'
                        f'padding:1px 14px;margin:0 -14px">{escaped}</span>'
                    )
                elif line.startswith("+"):
                    diff_lines += (
                        f'<span style="display:block;background:#0d2b1a;color:#7ee787;'
                        f'padding:1px 14px;margin:0 -14px">{escaped}</span>'
                    )
                elif line.startswith("@@"):
                    diff_lines += (
                        f'<span style="display:block;color:#79c0ff;padding:1px 0">{escaped}</span>'
                    )
                else:
                    diff_lines += (
                        f'<span style="display:block;color:#c9d1d9;padding:1px 0">{escaped}</span>'
                    )
            diff_html = (
                f'<div style="margin-top:12px;border-radius:6px;overflow:hidden;'
                f'border:1px solid #30363d;font-family:SFMono-Regular,Consolas,monospace">'
                f'<div style="background:#161b22;padding:6px 14px;border-bottom:1px solid #30363d;'
                f'font-size:11px;color:#8b949e">diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml</div>'
                f'<pre style="background:#0d1117;padding:14px;margin:0;font-size:12px;'
                f'overflow-x:auto;line-height:1.7">{diff_lines}</pre>'
                f'</div>'
            )

        remediation_cards += (
            f'<div style="border:1px solid {rc}33;border-left:4px solid {rc};background:{rb};'
            f'border-radius:6px;padding:14px 16px;margin-bottom:14px">'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
            f'<span style="background:{rc};color:white;padding:2px 10px;border-radius:4px;'
            f'font-weight:700;font-size:11px;letter-spacing:.5px">{_e(rem.priority)}</span>'
            f'<span style="font-weight:700;color:var(--text);font-size:15px">{_e(rem.finding)}</span>'
            f'</div>'
            f'<p style="color:var(--text2);font-size:14px;margin:4px 0 0">{_e(rem.action)}</p>'
            f'{diff_html}'
            f'</div>'
        )

    critical_count = sum(1 for f in result.permission_findings if f.risk == "CRITICAL")
    high_count = sum(1 for f in result.permission_findings if f.risk == "HIGH")
    lateral_count = len(result.lateral_paths)

    # Threat intel section
    threat_intel_html, ti_compromised, ti_at_risk, ti_safe = _build_threat_intel_section(result)
    ti_badge_count = ti_compromised + ti_at_risk
    ti_badge_class = "ok" if ti_badge_count == 0 else ""

    # Permission source banner
    source_banner = ""
    if result.permission_source == "default":
        source_banner = (
            '<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:12px;margin-bottom:16px">'
            '<strong style="color:#dc2626">Default Permissions Active</strong>'
            '<p style="color:#7f1d1d;font-size:13px;margin:4px 0">'
            'No explicit <code>permissions:</code> block found. GitHub&rsquo;s defaults were applied.</p></div>'
        )
    elif result.permission_source == "write-all":
        source_banner = (
            '<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:12px;margin-bottom:16px">'
            '<strong style="color:#dc2626">permissions: write-all &mdash; Maximum Write Access</strong>'
            '<p style="color:#7f1d1d;font-size:13px;margin:4px 0">All permission scopes granted at write level.</p></div>'
        )
    elif result.is_safe_explicit:
        source_banner = (
            '<div style="background:#f0fdf4;border:1px solid #86efac;border-radius:6px;padding:12px;margin-bottom:16px">'
            '<strong style="color:#16a34a">Minimal Permissions Set</strong>'
            '<p style="color:#14532d;font-size:13px;margin:4px 0">'
            f'Workflow uses <code>permissions: {_e(result.permission_source)}</code> &mdash; this is the correct practice.</p></div>'
        )

    oidc_banner = ""
    if result.has_id_token:
        oidc_banner = (
            '<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:12px;margin-bottom:16px">'
            '<strong style="color:#dc2626">OIDC Cloud Token Exposure</strong>'
            '<p style="color:#7f1d1d;font-size:13px;margin:4px 0">'
            '<code>id-token: write</code> allows minting cloud credentials (AWS/GCP/Azure) without stored keys.</p></div>'
        )

    secrets_api_warning = ""
    if result.secrets_note:
        secrets_api_warning = (
            f'<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:10px;margin-bottom:16px;font-size:13px;color:#92400e">'
            f'<strong>Secrets data may be incomplete:</strong> {_e(result.secrets_note)}</div>'
        )

    repo_perm_note = ""
    if result.repo_default_workflow_permissions:
        color = "#16a34a" if result.repo_default_workflow_permissions == "read" else "#ea580c"
        repo_perm_note = f'<span style="color:{color};font-weight:600">{_e(result.repo_default_workflow_permissions)} (repo setting)</span>'
    else:
        repo_perm_note = '<span style="color:#6b7280">unknown (API inaccessible)</span>'

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ForesightOps &mdash; Blast Radius Report</title>
  <style>
    /* ---- Theme tokens ---- */
    :root[data-theme="light"] {{
      --bg: #f3f4f6;
      --surface: #ffffff;
      --surface2: #f9fafb;
      --border: #e5e7eb;
      --text: #111827;
      --text2: #374151;
      --muted: #6b7280;
      --header-bg: linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);
      --navbar-bg: #1e293b;
      --nav-btn-border: #334155;
      --nav-btn-color: #94a3b8;
      --code-bg: #f3f4f6;
      --th-bg: #f9fafb;
      --footer-color: #9ca3af;
    }}
    :root[data-theme="dark"] {{
      --bg: #0d1117;
      --surface: #161b22;
      --surface2: #21262d;
      --border: #30363d;
      --text: #e6edf3;
      --text2: #c9d1d9;
      --muted: #8b949e;
      --header-bg: linear-gradient(135deg,#010409 0%,#0d1117 100%);
      --navbar-bg: #010409;
      --nav-btn-border: #21262d;
      --nav-btn-color: #8b949e;
      --code-bg: #161b22;
      --th-bg: #161b22;
      --footer-color: #6e7681;
    }}
    /* ---- Base ---- */
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.6;background:var(--bg);color:var(--text);transition:background .2s,color .2s}}
    .header{{background:var(--header-bg);color:white;padding:32px 48px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}}
    .header h1{{font-size:28px;font-weight:800;letter-spacing:-.5px}}
    .header h1 span{{color:#38bdf8}}
    .header p{{color:#e2e8f0;margin-top:6px;font-size:14px;max-width:640px;line-height:1.5}}
    .header-actions{{display:flex;gap:8px;align-items:center}}
    .badge{{display:inline-block;background:#0ea5e9;color:white;padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700;letter-spacing:.5px;margin-left:8px}}
    /* ---- Toolbar buttons (theme toggle + export) ---- */
    .hdr-btn{{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);color:white;padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .15s}}
    .hdr-btn:hover{{background:rgba(255,255,255,.2)}}
    /* ---- Sticky nav ---- */
    .navbar{{position:sticky;top:0;z-index:100;background:var(--navbar-bg);display:flex;gap:4px;padding:10px 24px;overflow-x:auto}}
    .nav-btn{{background:transparent;border:1px solid var(--nav-btn-border);color:var(--nav-btn-color);padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .15s}}
    .nav-btn:hover,.nav-btn.active{{background:#0ea5e9;border-color:#0ea5e9;color:white}}
    .nav-badge{{display:inline-block;background:#dc2626;color:white;border-radius:99px;font-size:10px;padding:0 5px;margin-left:4px;font-weight:700}}
    .nav-badge.ok{{background:#16a34a}}
    /* ---- Layout ---- */
    .container{{max-width:1100px;margin:0 auto;padding:32px 24px}}
    .card{{background:var(--surface);border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:28px;margin-bottom:24px;scroll-margin-top:60px;border:1px solid var(--border)}}
    .card h2{{font-size:19px;font-weight:700;color:var(--text);margin-bottom:18px;padding-bottom:10px;border-bottom:2px solid var(--border);letter-spacing:-.2px}}
    table{{width:100%;border-collapse:collapse}}
    th{{text-align:left;font-size:13px;font-weight:600;color:var(--muted);padding:10px 14px;background:var(--th-bg);border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.5px}}
    td{{padding:12px 14px;border-bottom:1px solid var(--border);vertical-align:top;color:var(--text2);font-size:14px}}
    tr:last-child td{{border-bottom:none}}
    .stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}}
    .stat{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08);cursor:pointer;transition:box-shadow .15s}}
    .stat:hover{{box-shadow:0 4px 12px rgba(0,0,0,.15)}}
    .stat-num{{font-size:32px;font-weight:800}}
    .stat-label{{font-size:13px;color:var(--muted);margin-top:4px;font-weight:500}}
    .meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}
    .meta-row{{display:flex;gap:8px;font-size:14px;padding:5px 0}}
    .meta-key{{color:var(--muted);min-width:170px;font-weight:500}}
    .meta-val{{color:var(--text);font-weight:600}}
    .footer{{text-align:center;padding:24px;color:var(--footer-color);font-size:12px}}
    code{{font-family:'SFMono-Regular',Consolas,monospace;background:var(--code-bg);padding:1px 5px;border-radius:3px;font-size:12px;color:var(--text)}}
    a{{color:#0ea5e9;text-decoration:none}}
    a:hover{{text-decoration:underline}}
    .highlight{{animation:flashcard .8s ease-out}}
    @keyframes flashcard{{0%{{box-shadow:0 0 0 4px #38bdf8}}100%{{box-shadow:0 1px 3px rgba(0,0,0,.1)}}}}
    /* ---- Threat Intel cards ---- */
    .ti-card{{border:1px solid var(--border);border-radius:8px;margin-bottom:10px;overflow:hidden;background:var(--surface)}}
    .ti-card-header{{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:14px 18px;cursor:pointer;transition:background .15s}}
    .ti-card-header:hover{{background:var(--surface2)}}
    .ti-card-body{{display:none;border-top:1px solid var(--border);padding:16px 18px 18px}}
    .ti-card-body.open{{display:block}}
    .ti-chevron.open{{transform:rotate(90deg)}}
    @media(max-width:640px){{
      .stat-grid{{grid-template-columns:repeat(2,1fr)}}
      .meta-grid{{grid-template-columns:1fr}}
      .header{{padding:24px}}
    }}
  </style>
  <script>
    function goTo(id){{
      var el=document.getElementById(id);
      if(el){{el.scrollIntoView({{behavior:'smooth',block:'start'}});el.classList.remove('highlight');void el.offsetWidth;el.classList.add('highlight');}}
      document.querySelectorAll('.nav-btn').forEach(function(b){{b.classList.remove('active')}});
      var btn=document.querySelector('[data-target="'+id+'"]');
      if(btn)btn.classList.add('active');
    }}
    function toggleTI(header){{
      var body=header.nextElementSibling;
      var chev=header.querySelector('.ti-chevron');
      var open=body.classList.contains('open');
      body.classList.toggle('open',!open);
      chev.classList.toggle('open',!open);
    }}
    function toggleTheme(){{
      var html=document.documentElement;
      var isDark=html.getAttribute('data-theme')==='dark';
      html.setAttribute('data-theme',isDark?'light':'dark');
      document.getElementById('theme-btn').textContent=isDark?'Dark Mode':'Light Mode';
    }}
    function exportReport(){{
      var blob=new Blob([document.documentElement.outerHTML],{{type:'text/html'}});
      var a=document.createElement('a');
      a.href=URL.createObjectURL(blob);
      a.download='foresightops_report_{result.run_id}.html';
      a.click();
      URL.revokeObjectURL(a.href);
    }}
  </script>
</head>
<body>
<div class="header">
  <div>
    <h1>Foresight<span>Ops</span> <span class="badge">v1.0</span></h1>
    <p>Know exactly what an attacker can reach the moment a workflow token is compromised &mdash; before the vulnerability hits your code.</p>
  </div>
  <div class="header-actions">
    <button class="hdr-btn" id="theme-btn" onclick="toggleTheme()">Dark Mode</button>
    <button class="hdr-btn" onclick="exportReport()">&#x2B07; Export HTML</button>
  </div>
</div>
<nav class="navbar">
  <button class="nav-btn active" data-target="section-overview" onclick="goTo('section-overview')">Overview</button>
  <button class="nav-btn" data-target="section-run" onclick="goTo('section-run')">Run Details</button>
  <button class="nav-btn" data-target="section-permissions" onclick="goTo('section-permissions')">Permissions <span class="nav-badge" id="badge-perms">{critical_count + high_count}</span></button>
  <button class="nav-btn" data-target="section-lateral" onclick="goTo('section-lateral')">Lateral Movement <span class="nav-badge {'ok' if not lateral_count else ''}" id="badge-lateral">{lateral_count}</span></button>
  <button class="nav-btn" data-target="section-secrets" onclick="goTo('section-secrets')">Secrets <span class="nav-badge {'ok' if not result.exposed_secrets else ''}" id="badge-secrets">{len(result.exposed_secrets)}</span></button>
  <button class="nav-btn" data-target="section-remediation" onclick="goTo('section-remediation')">Remediation</button>
  <button class="nav-btn" data-target="section-threatintel" onclick="goTo('section-threatintel')">Recent Supply Chain Attacks <span class="nav-badge {ti_badge_class}" id="badge-ti">{ti_badge_count}</span></button>
</nav>
<div class="container">
  <div class="stat-grid" id="section-overview">
    <div class="stat" onclick="goTo('section-run')" title="View run details">
      {_gauge_svg(result.risk_score, result.risk_label)}
      <div class="stat-label">Overall Risk Score</div>
    </div>
    <div class="stat" onclick="goTo('section-permissions')" title="View permission findings">
      <div class="stat-num" style="color:{RISK_COLORS['CRITICAL']}">{critical_count}</div>
      <div class="stat-label">Critical Findings &rarr;</div>
    </div>
    <div class="stat" onclick="goTo('section-permissions')" title="View permission findings">
      <div class="stat-num" style="color:{RISK_COLORS['HIGH']}">{high_count}</div>
      <div class="stat-label">High Findings &rarr;</div>
    </div>
    <div class="stat" onclick="goTo('section-lateral')" title="View lateral movement paths">
      <div class="stat-num" style="color:{RISK_COLORS['HIGH'] if lateral_count else '#16a34a'}">{lateral_count}</div>
      <div class="stat-label">Lateral Paths &rarr;</div>
    </div>
  </div>

  <div class="card" id="section-run">
    <h2>Workflow Run Details</h2>
    {source_banner}
    {oidc_banner}
    {secrets_api_warning}
    <div class="meta-grid">
      <div class="meta-row"><span class="meta-key">Repository</span><span class="meta-val">{_e(result.owner)}/{_e(result.repo)}</span></div>
      <div class="meta-row"><span class="meta-key">Run ID</span><span class="meta-val"><a href="{_e(result.run_url)}" target="_blank" rel="noopener">#{result.run_id}</a></span></div>
      <div class="meta-row"><span class="meta-key">Workflow</span><span class="meta-val">{_e(result.workflow_name)}</span></div>
      <div class="meta-row"><span class="meta-key">Triggered By</span><span class="meta-val">{_e(result.triggered_by)}</span></div>
      <div class="meta-row"><span class="meta-key">Started At</span><span class="meta-val">{_e(result.run_started_at)}</span></div>
      <div class="meta-row"><span class="meta-key">Permissions Source</span><span class="meta-val">{_e(result.permission_source)}</span></div>
      <div class="meta-row"><span class="meta-key">Repo Default Perms</span><span class="meta-val">{repo_perm_note}</span></div>
      <div class="meta-row"><span class="meta-key">OIDC id-token</span><span class="meta-val">{'<span style="color:#dc2626;font-weight:600">Enabled (cloud risk)</span>' if result.has_id_token else '<span style="color:#16a34a">Not enabled</span>'}</span></div>
      <div class="meta-row"><span class="meta-key">Secrets in Scope</span><span class="meta-val">{len(result.exposed_secrets)}</span></div>
      <div class="meta-row"><span class="meta-key">Analysis Time</span><span class="meta-val">{_e(result.analysis_timestamp)}</span></div>
    </div>
  </div>

  <div class="card" id="section-permissions">
    <h2>Token Permission Analysis &mdash; Attacker Capabilities</h2>
    <table>
      <thead><tr><th>Permission</th><th>Risk</th><th>Attacker Can</th></tr></thead>
      <tbody>{findings_rows if findings_rows else '<tr><td colspan="3" style="text-align:center;color:#16a34a;padding:12px">&#x2713; No risky permissions found</td></tr>'}</tbody>
    </table>
  </div>

  <div class="card" id="section-lateral">
    <h2>Lateral Movement Paths</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Note: GITHUB_TOKEN cannot reach other repositories directly. Lateral movement shown is within this repo, via supply chain (packages), or via cloud credentials (OIDC).</p>
    <table>
      <thead><tr><th>Source Permission</th><th>First Attack Step</th><th>Reachable Target</th><th>Scope</th><th>Risk</th></tr></thead>
      <tbody>{lateral_rows}</tbody>
    </table>
  </div>

  <div class="card" id="section-secrets">
    <h2>Secrets in Scope ({len(result.exposed_secrets)})</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Secret values are never exposed by GitHub&apos;s API. Names shown are sufficient to assess impact.</p>
    <table>
      <thead><tr><th>Secret Name</th><th>Scope</th><th>Environment</th></tr></thead>
      <tbody>{secrets_rows}</tbody>
    </table>
  </div>

  <div class="card" id="section-remediation">
    <h2>Remediation Steps &mdash; Prioritized</h2>
    {'<div style="background:#f0fdf4;border:1px solid #86efac;border-radius:6px;padding:10px;margin-bottom:14px;font-size:13px;color:#14532d"><strong>&#x2713; No permission findings</strong> &mdash; permissions are minimal. The steps below are best-practice hardening recommendations that apply regardless of permission level.</div>' if not result.permission_findings else ''}
    {remediation_cards if remediation_cards else '<p style="color:#16a34a;font-size:14px;text-align:center;padding:12px">&#x2713; No remediation required</p>'}
  </div>

  {threat_intel_html}

</div>
<div class="footer">
  Generated by <strong>ForesightOps</strong> v1.0 &nbsp;&middot;&nbsp; {_e(result.analysis_timestamp)} &nbsp;&middot;&nbsp;
  Not another scanner &mdash; automated blast radius analysis before the vulnerability reaches your code.
</div>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
