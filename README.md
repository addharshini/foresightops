# ForesightOps

**Know exactly what an attacker can reach the moment a workflow token is compromised — before the vulnerability hits your code.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)

---

## The Problem

When a GitHub Actions workflow is compromised — through a malicious dependency, a poisoned action, or a stolen token — security teams scramble to answer:

- What could the attacker actually reach with that token?
- Which secrets were in scope? Which cloud accounts?
- Could they move laterally to other workflows, registries, or repos?
- What is the **real blast radius**?

Today this is done **manually**, repo by repo, workflow by workflow — taking hours when it should take seconds.

---

## What ForesightOps Does

Give it a GitHub Actions run ID. It tells you everything an attacker could have done with that token.

| Step | What Happens |
|------|-------------|
| **Permission Mapping** | Reads the workflow YAML at that exact commit — detects dangerous defaults if no `permissions:` block exists |
| **Capability Analysis** | Maps each permission to concrete attacker actions (e.g. `packages: write` → publish poisoned package to downstream consumers) |
| **Secret Exposure** | Lists every secret in scope: repo-level, org-level, environment-scoped |
| **Lateral Movement** | Determines whether the attacker could pivot to other workflows, cloud accounts, or the supply chain |
| **OIDC Detection** | Flags `id-token: write` — the permission that mints cloud credentials with no stored keys |
| **Threat Intel** | Checks your workflow against 10 confirmed 2026 supply chain attacks and tells you if you were affected |
| **Risk Score** | 0–100 blast radius score with CRITICAL / HIGH / MEDIUM / LOW classification |
| **HTML Report** | Shareable visual report with copy-paste YAML remediation — dark/light mode, export to file |

---

## Quick Start

### Requirements

- Python 3.11+
- A GitHub Personal Access Token — or use **Demo Mode** (no token needed)

### Install

```bash
git clone https://github.com/YOUR_USERNAME/foresightops
cd foresightops
pip install -r requirements.txt
```

### Try it instantly — Demo Mode

No token, no setup. Generates a full CRITICAL report from a synthetic scenario:

```bash
python -m foresightops.cli demo --open
```

The demo shows a realistic release workflow with:
- 5 compromised packages from real 2026 attacks (keyv, jscrambler, @asyncapi/generator, @mastra/core, codfish/semantic-release-action)
- `id-token: write` → AWS production account reachable via OIDC
- `packages: write` → supply chain poisoning to downstream consumers
- 7 secrets in scope including `STRIPE_SECRET_KEY` and `DATABASE_URL`
- Full prioritized remediation with copy-paste YAML

### Analyze a real workflow run

```bash
export GITHUB_TOKEN=ghp_your_token_here

python -m foresightops.cli analyze \
  --owner your-org \
  --repo your-repo \
  --run-id 9182736450 \
  --output report.html \
  --open
```

**Token permissions needed** (fine-grained PAT, read-only):

| Permission | Why |
|---|---|
| `Actions: read` | Fetch run metadata and workflow YAML |
| `Secrets: read` | List secret names in scope (values are never exposed by GitHub) |
| `Contents: read` | Read workflow YAML at the exact commit SHA |
| `Metadata: read` | Repository info |

---

## Try It on the Demo Repo

Want to run ForesightOps against a real GitHub Actions run without setting up your own repo?

We maintain a demo victim repo with two workflows — one deliberately vulnerable, one hardened — so you can see the contrast:

```bash
# Vulnerable workflow run — expect CRITICAL, 5 COMPROMISED attacks
python -m foresightops.cli analyze \
  --owner foresightops-demo \
  --repo acme-api \
  --run-id VULNERABLE_RUN_ID \
  --output vulnerable_report.html \
  --open

# Hardened workflow run — expect LOW/SAFE, 0 COMPROMISED attacks
python -m foresightops.cli analyze \
  --owner foresightops-demo \
  --repo acme-api \
  --run-id HARDENED_RUN_ID \
  --output hardened_report.html \
  --open
```

> Run IDs and a read-only demo token are pinned in the [demo repo README](https://github.com/foresightops-demo/acme-api).

---

## Example Report Output

```
ForesightOps — Blast Radius Report
====================================
Repository:   acme-corp/api-service
Run ID:       9182736450
Workflow:     Release and Publish

Risk Score:   100 / 100  [CRITICAL]

Findings
  CRITICAL  3   HIGH  3   MEDIUM  0   LOW  0

Permissions
  contents: write    CRITICAL  — push to any unprotected branch, overwrite releases
  packages: write    CRITICAL  — publish malicious package versions to downstream consumers
  id-token: write    CRITICAL  — mint AWS/GCP/Azure credentials via OIDC (no stored key needed)
  checks: write      HIGH      — forge passing CI status, bypass required checks
  security-events: write  HIGH — erase SAST findings, suppress alerts
  pull-requests: write    HIGH — approve PRs without human review

Secrets in scope: 7
  AWS_ACCESS_KEY_ID       (repo)
  AWS_SECRET_ACCESS_KEY   (repo)
  NPM_PUBLISH_TOKEN       (org)
  DOCKER_HUB_TOKEN        (org)
  SLACK_WEBHOOK_URL       (repo)
  DATABASE_URL            (environment: production)
  STRIPE_SECRET_KEY       (environment: production)

Lateral movement paths: 3
  contents: write   → push malicious commit to main
  packages: write   → poison downstream npm consumers
  id-token: write   → AWS production account via OIDC

Recent Supply Chain Attacks
  COMPROMISED  keyv & cacheable (Aug 2026) — package found + packages: write active
  COMPROMISED  jscrambler (Jul 2026)       — package found + id-token: write active
  COMPROMISED  AsyncAPI (Jul 2026)         — @asyncapi/generator found + id-token: write active
  COMPROMISED  Mastra (Jun 2026)           — @mastra/core found + packages: write active
  COMPROMISED  Miasma/LeoPlatform (Jun 2026) — codfish/semantic-release-action found
  AT RISK      5 more attacks — dangerous permissions match known attack patterns
```

---

## The Threat Intel Tab

ForesightOps checks your workflow against **10 confirmed supply chain attacks from 2026** sourced from [socket.dev/blog](https://socket.dev/blog).

For each attack it checks two signals:
1. **Package scan** — does the compromised package name appear in your workflow YAML?
2. **Permission match** — does your workflow have the dangerous permission that amplifies this attack?

| Result | Meaning |
|---|---|
| 🔴 **COMPROMISED** | Vulnerable package found AND dangerous permission active |
| 🟠 **AT RISK** | Either signal present — review required |
| 🟢 **SAFE** | Neither package nor permission detected |

Attacks covered (all confirmed 2026):

| Attack | Date | Severity |
|---|---|---|
| keyv & cacheable — self-propagating worm | Aug 2026 | CRITICAL |
| jscrambler — native binary infostealer | Jul 2026 | CRITICAL |
| GitHub Actions abuse — CI as attack infra | Jul 2026 | CRITICAL |
| AsyncAPI — Miasma botnet via OIDC | Jul 2026 | CRITICAL |
| Mastra — 141 packages via rogue npm account | Jun 2026 | CRITICAL |
| Miasma/LeoPlatform — EDR evasion + GITHUB_TOKEN theft | Jun 2026 | CRITICAL |
| Joyfill — DEV#POPPER RAT, blockchain C2 (DPRK) | Jul 2026 | HIGH |
| PolinRider — DPRK campaign, 162 malicious artifacts | Jul 2026 | CRITICAL |
| Injective SDK — key derivation hooked at build time | Jul 2026 | HIGH |
| Alibaba RAT — dependency confusion, 3 months undetected | Jul 2026 | HIGH |

---

## Vulnerable vs. Hardened Workflow

This repo includes two example workflows you can copy into your own repo:

| File | Purpose | Expected Score |
|---|---|---|
| [`.github/workflows/release-vulnerable.yml`](.github/workflows/release-vulnerable.yml) | Deliberately unsafe — broad permissions, known compromised packages | 100 / CRITICAL |
| [`.github/workflows/release-hardened.yml`](.github/workflows/release-hardened.yml) | Best-practice hardened — pinned SHAs, per-job minimal permissions | Low / SAFE |

---

## Architecture

```
foresightops/
├── cli.py           # Entry point — analyze and demo commands
├── analyzer.py      # Orchestration: fetch → score → findings → report
├── github_client.py # GitHub REST API wrapper (paginated, error-handled)
├── permissions.py   # Permission → attacker capability mapping + scoring
├── report.py        # HTML report generator (threat intel, dark mode, export)
└── demo_mode.py     # Synthetic scenario for offline demos
```

---

## Research Background

ForesightOps is original security research on **CI/CD supply chain blast radius analysis**.

The core contribution is a systematic mapping of GitHub Actions GITHUB_TOKEN permission scopes to concrete attacker capabilities, combined with automated lateral movement path analysis and real-time threat intelligence matching against known supply chain compromises.

**The key reframe:** after a CI/CD compromise, the question is not *"was my repo affected?"* — it is *"given this run's token, what was the maximum attacker reach?"* ForesightOps answers that in seconds.

---

## References

- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [CISA: Defending CI/CD Environments](https://www.cisa.gov/resources-tools/resources/defending-cicd-environments)
- [Socket.dev Supply Chain Attack Blog](https://socket.dev/blog)
- [Praetorian: GitHub Actions Attack Surfaces](https://www.praetorian.com/blog/github-actions-hacking-reusable-workflows/)

---

## License

MIT — see [LICENSE](LICENSE)
