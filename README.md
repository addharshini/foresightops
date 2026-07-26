# ForesightOps

**Automate Remediation Before the Vulnerability Reaches Code**

> *Not another security scanner.*

ForesightOps answers the question defenders actually need answered after a CI/CD supply chain compromise:

> **"What could the attacker actually gain, given the affected workflow run's token scope and permissions?"**

---

## The Problem

When a GitHub Actions workflow is compromised — through a malicious dependency, a `pull_request_target` attack, a poisoned action, or a stolen token — security teams scramble to answer:

- What token scope did that run have?
- What repositories, secrets, and cloud accounts were reachable?
- Could the attacker move laterally to other workflows or repos?
- What's the real blast radius?

Today this is done **manually**, repo by repo, workflow by workflow. ForesightOps **automates it**.

---

## What ForesightOps Does

Given a GitHub Actions workflow run ID, ForesightOps:

| Step | What Happens |
|------|-------------|
| **Permission Mapping** | Reads explicit `permissions:` from the workflow YAML, or detects dangerous GitHub defaults |
| **Capability Analysis** | Maps each permission to concrete attacker actions (e.g., `packages: write` → supply chain poisoning) |
| **Secret Exposure** | Lists every secret in scope: repo-level, org-level, and environment-scoped |
| **Lateral Movement** | Determines whether the attacker could pivot to other workflows, repos, or cloud accounts |
| **OIDC Detection** | Flags `id-token: write` — the permission that lets attackers mint cloud credentials with no stored keys |
| **Risk Scoring** | Produces a 0–100 blast radius risk score |
| **Remediation** | Generates prioritized, code-level fixes (not just "be more secure") |
| **HTML Report** | Outputs a shareable, visual report for incident response and security reviews |

---

## Quick Start

### Requirements

- Python 3.11+
- A GitHub Personal Access Token (PAT) with `repo` scope — or use Demo Mode (no token needed)

### Install

```bash
git clone https://github.com/YOUR_USERNAME/foresightops
cd foresightops
pip install -r requirements.txt
```

### Demo Mode (No Token Required)

Perfect for conference demos and evaluation:

```bash
python -m foresightops.cli demo --open
```

This generates a realistic attack scenario report showing:
- A `pull_request` trigger with dangerous default permissions
- `id-token: write` → AWS production account reachable
- `packages: write` → supply chain poisoning possible
- 7 secrets in scope including `STRIPE_SECRET_KEY` and `DATABASE_URL`
- Full prioritized remediation steps

### Analyze a Real Run

```bash
export GITHUB_TOKEN=ghp_your_token_here

python -m foresightops.cli analyze \
  --owner your-org \
  --repo your-repo \
  --run-id 9182736450 \
  --output report.html \
  --open
```

---

## Example Output

```
Risk Score:  94/100  [CRITICAL]

Findings:
  CRITICAL: 3   HIGH: 3   MEDIUM: 0

Secrets in scope: 7
Lateral movement paths: 3

[!] OIDC id-token enabled -- cloud credential exposure risk!
[!] No explicit permissions set -- GitHub defaults are too broad!
```

The HTML report includes:
- Visual risk gauge
- Permission-by-permission capability breakdown
- Lateral movement path diagram
- Exposed secrets inventory
- Prioritized remediations with copy-paste YAML fixes

---

## Key Attack Scenarios Detected

### 1. Default Permission Blast Radius
Most GitHub Actions workflows never set an explicit `permissions:` block.
GitHub's defaults include `contents: write`, `packages: write`, `checks: write`, and more.
ForesightOps detects this and shows the full attack surface.

### 2. OIDC Cloud Credential Theft
`id-token: write` allows a workflow to request a JWT from GitHub's OIDC provider
and authenticate directly to AWS, GCP, or Azure — no stored credentials needed.
ForesightOps identifies this and recommends trust policy hardening.

### 3. Supply Chain Poisoning via Package Registry
`packages: write` lets an attacker overwrite published npm, Maven, or Docker packages.
ForesightOps identifies all downstream consumers at risk.

### 4. Security Control Bypass
`checks: write` + `security-events: write` allows an attacker to silence SAST findings,
mark scans as passed, and merge malicious code undetected.

### 5. Lateral Movement via Actions Triggers
`actions: write` enables triggering arbitrary workflows — attackers can pivot
to other workflows with wider permissions.

---

## Remediation Philosophy

ForesightOps does not just flag issues — it generates **code-level YAML fixes**:

```yaml
# ForesightOps Recommended: Minimal permissions
permissions:
  contents: read      # was: write (default)
  # Remove packages: write unless this workflow publishes
  # Remove id-token: write unless this workflow deploys to cloud
```

```yaml
# OIDC trust policy hardening (AWS)
"StringEquals": {
  "token.actions.githubusercontent.com:sub":
  "repo:YOUR_ORG/YOUR_REPO:ref:refs/heads/main"
}
```

---

## Architecture

```
foresightops/
├── cli.py           # CLI entry point (analyze / demo commands)
├── analyzer.py      # Core orchestration: fetch → score → findings
├── github_client.py # GitHub REST API wrapper
├── permissions.py   # Permission → attacker capability mapping
├── report.py        # HTML report generator
└── demo_mode.py     # Synthetic demo scenario (no token needed)
```

---

## Research Background

This tool is presented as part of original security research on CI/CD supply chain blast radius analysis. The core contribution is the **systematic mapping of GitHub Actions token permissions to attacker capabilities**, combined with automated lateral movement path analysis — enabling defenders to answer "what could the attacker reach?" in seconds rather than hours.

**Key insight:** The security question after a CI/CD compromise is not *"was my repo affected?"* — it is *"given this run's token, what was the maximum attacker reach?"* This reframing drives the entire tool design.

---

## Related Work & References

- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [CISA: Defending CI/CD Environments](https://www.cisa.gov/resources-tools/resources/defending-cicd-environments)
- [Praetorian: GitHub Actions Attack Surfaces](https://www.praetorian.com/blog/github-actions-hacking-reusable-workflows/)
- [Legit Security: Supply Chain Attack via GitHub Actions](https://www.legitsecurity.com/blog/github-actions-security)

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Author

ForesightOps — Security Research Project  
Presented at [Conference Name]
