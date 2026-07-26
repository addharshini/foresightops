# ForesightOps: Automate Remediation Before the Vulnerability Reaches Code
## Not Another Security Scanner

---

## Talk Abstract (Short — 150 words)

Developers constantly live in fear of CI/CD supply chain attacks causing unrecoverable damage. But the security industry has trained defenders to ask the wrong question. "Was my repository affected?" is not actionable. The real question is: **"Given the token scope and permissions that specific workflow run had, what could an attacker actually reach?"**

Today, answering that question is a manual, repo-by-repo process that can take hours or days — time an attacker uses to deepen their foothold. This talk presents ForesightOps, an open-source tool that automates the entire blast radius analysis: it identifies the exact GITHUB_TOKEN scope that was active during the compromise window, maps every permission to concrete attacker capabilities, enumerates exposed secrets across repo and organization scope, detects OIDC-based cloud credential exposure, and traces lateral movement paths to other workflows, registries, and cloud accounts. The output is a prioritized, code-level remediation plan — not a list of scan findings to triage manually.

---

## Talk Abstract (Full — 500 words)

### The Problem Security Tools Are Not Solving

Modern CI/CD pipelines are not just build systems — they are privileged execution environments with access to source code, cloud credentials, package registries, and deployment infrastructure. When a supply chain attack occurs — whether via a compromised GitHub Action, a poisoned npm dependency, a `pull_request_target` abuse, or a stolen token — the first responder's question is almost always: *"Was my repo affected?"*

This is the wrong question.

Whether a repository was technically in the blast radius of a compromised workflow tells you almost nothing about the actual damage. What matters is: what **token permissions** did that specific run execute with, and what could an attacker with those permissions **actually reach**? The answer depends on a complex intersection of factors: was the `GITHUB_TOKEN` using dangerous defaults? Was `id-token: write` set, exposing a path to AWS or GCP without any stored credentials? Were organization-level secrets in scope? Could the attacker pivot to other workflows or package registries from this single entry point?

Answering these questions today requires a security engineer to manually read workflow YAML files, cross-reference the GitHub permissions model, enumerate secrets at repo and org scope, check OIDC trust policies, and trace potential lateral movement chains — repo by repo. For an organization with hundreds of repositories, this can take days. The attacker meanwhile has seconds.

### The Approach: Automated Blast Radius Analysis

ForesightOps reframes the post-compromise investigation around a single input — a workflow run ID — and automates the full analysis pipeline in four stages:

**Stage 1: Permission Reconstruction.** The tool fetches the workflow run metadata via the GitHub REST API and retrieves the YAML definition at the exact commit SHA that ran during the compromise window. It parses the `permissions:` block if present; if absent, it applies GitHub's documented default permission set — which includes `contents: write`, `packages: write`, `checks: write`, `pull-requests: write`, and `deployments: write`. This is the most common configuration in practice, and the most dangerous.

**Stage 2: Capability Mapping.** Each permission is mapped against a hand-built attacker capability model — not a generic severity tag, but a concrete enumeration of what an attacker holding that permission token can do. `packages: write` means the attacker can overwrite npm, Maven, or Docker packages in GitHub Packages, distributing malware to all downstream consumers. `id-token: write` means the attacker can mint a JWT from GitHub's OIDC provider and authenticate to AWS, GCP, or Azure without any stored credential. `checks: write` means the attacker can forge security scan results and mark compromised code as safe to merge. `security-events: write` means the attacker can delete all open SARIF alerts, erasing the forensic record of the compromise.

**Stage 3: Secret Enumeration and Lateral Movement Tracing.** The tool enumerates all secrets in scope for the affected run: repository-level secrets, organization-level secrets accessible to the repository, and environment-scoped secrets tied to deployment environments. It then constructs lateral movement paths — chains of permissions and capabilities that allow the attacker to pivot beyond the initial repo. An attacker with `contents: write` and `actions: write` can push a workflow change that triggers with elevated permissions in a different repository. An attacker with `id-token: write` can reach cloud infrastructure. An attacker with `packages: write` is already outside the repository entirely, in the supply chain.

**Stage 4: Scored Remediation.** Each finding is scored on a weighted CRITICAL/HIGH/MEDIUM/LOW scale, combined into a 0–100 blast radius risk score, and mapped to a specific code-level fix — an actual YAML snippet to paste into the workflow file, an AWS trust policy condition to add, a branch scoping rule to implement. The output is an HTML report designed for incident responders and security reviews, not another findings list requiring expert interpretation.

### Why This Matters Now

GitHub Actions is now the dominant CI/CD platform, with over 100 million repositories and default configurations that grant far more privilege than any individual workflow needs. The security community has built excellent tools for scanning for known vulnerabilities. What has been missing is tooling that answers the defender's actual post-compromise question: *what was the real blast radius, and what do I do right now to stop it from growing?* ForesightOps is that tool.

---

## Technical Description: Tools, Techniques, and Implementation

### Architecture Overview

ForesightOps is implemented in Python 3.11+ as a four-module CLI tool. The architecture follows a strict pipeline pattern: each stage consumes the output of the previous and is independently testable. There is no persistent state, no database, and no agent running continuously — the tool is invoked on-demand against a specific workflow run ID and produces a self-contained HTML report.

```
Input: (owner, repo, run_id, github_token)
         │
         ▼
┌─────────────────────┐
│   GitHubClient      │  GitHub REST API v2022-11-28
│   (github_client.py)│  Endpoints: /actions/runs, /actions/workflows,
│                     │  /actions/secrets, /environments, /contents
└────────┬────────────┘
         │ Raw API responses
         ▼
┌─────────────────────┐
│  BlastRadiusAnalyzer│  Orchestration layer
│   (analyzer.py)     │  - Fetches run metadata + job list
│                     │  - Retrieves workflow YAML at exact commit SHA
│                     │  - Detects default vs. explicit permissions
│                     │  - Enumerates secrets (repo + org + environment)
└────────┬────────────┘
         │ Structured permission dict
         ▼
┌─────────────────────┐
│  Permission Engine  │  Core contribution of the research
│  (permissions.py)   │  - 13 permission types × read/write levels
│                     │  - Hand-built attacker capability model
│                     │  - Weighted risk scoring (CRITICAL=10, HIGH=7...)
│                     │  - Lateral movement flag + target enumeration
│                     │  - OIDC detection and cloud reach analysis
└────────┬────────────┘
         │ AnalysisResult dataclass
         ▼
┌─────────────────────┐
│   Report Generator  │  Self-contained HTML with inline CSS
│   (report.py)       │  - Visual risk gauge (SVG)
│                     │  - Permission findings table
│                     │  - Lateral movement path table
│                     │  - Secret inventory
│                     │  - Prioritized remediation cards with YAML
└─────────────────────┘
         │
         ▼
Output: foresightops_report.html
```

---

### Core Technique 1: Permission Reconstruction at Compromise-Time

The first and most important technical challenge is determining **which permissions were actually active** during the compromised run — not what the repo has today, but what was set at the exact commit SHA that executed.

The tool solves this by:

1. Calling `GET /repos/{owner}/{repo}/actions/runs/{run_id}` to retrieve the run's `head_sha` and `path` (the workflow file path).
2. Calling `GET /repos/{owner}/{repo}/contents/{path}?ref={head_sha}` to fetch the workflow YAML **at that exact commit** — not the current HEAD.
3. Parsing the YAML with PyYAML to extract the `permissions:` block.

The critical insight is handling the **absent permissions block** case. When no `permissions:` key exists in the workflow YAML, GitHub silently applies its own default set. These defaults — which include `contents: write`, `packages: write`, `checks: write`, `pull-requests: write`, `deployments: write`, and `issues: write` — are what the vast majority of real-world workflows run with, and they represent the most dangerous configuration. The tool detects absence explicitly and applies the documented GitHub defaults, rather than assuming "no configuration means low risk."

```python
# From permissions.py
def default_github_token_permissions() -> dict[str, str]:
    """
    GitHub's default GITHUB_TOKEN permissions when not explicitly set.
    These are the dangerous defaults most repos never restrict.
    """
    return {
        "contents": "write",
        "metadata": "read",
        "packages": "write",
        "pull-requests": "write",
        "issues": "write",
        "checks": "write",
        "statuses": "write",
        "deployments": "write",
        "actions": "read",
        "security-events": "read",
    }
```

The tool also handles the `permissions: write-all` shorthand — a single string value that grants maximum write access to every scope — by expanding it to a full write permission set across all 13 tracked permission types.

---

### Core Technique 2: The Attacker Capability Model

The central contribution of this research is replacing generic severity labels with a structured **attacker capability model** — a mapping from each GitHub permission to the concrete actions an attacker holding that permission token can perform.

Each entry in the model is a `PermissionRisk` dataclass:

```python
@dataclass
class PermissionRisk:
    permission: str          # e.g. "contents: write"
    level: str               # "write" or "read"
    risk: str                # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    attacker_can: list[str]  # concrete attacker actions
    lateral_movement: bool   # does this enable cross-boundary pivoting?
    lateral_targets: list[str]  # what can the attacker reach laterally?
    cve_relevance: str       # known attack class or CVE pattern
```

Selected high-impact entries from the model:

| Permission | Risk | Key Attacker Capability | Lateral Movement |
|---|---|---|---|
| `contents: write` | CRITICAL | Push malicious code, overwrite releases, inject backdoors | Yes — all branches, release pipeline |
| `packages: write` | CRITICAL | Overwrite npm/Docker packages — supply chain poisoning | Yes — all downstream consumers |
| `id-token: write` | CRITICAL | Mint OIDC JWT, authenticate to AWS/GCP/Azure directly | Yes — cloud accounts, no stored creds needed |
| `administration: write` | CRITICAL | Disable branch protection, add attacker as collaborator | Yes — full repo takeover |
| `secrets: write` | CRITICAL | Overwrite secrets with attacker-controlled values | Yes — persists past token expiry |
| `checks: write` | HIGH | Forge security scan results as passed, suppress SAST | No — confined to repo |
| `security-events: write` | HIGH | Delete all SARIF alerts, erase forensic evidence | No — confined to repo |
| `pages: write` | HIGH | Serve malicious JS from trusted github.io domain | Yes — all site visitors |
| `statuses: write` | HIGH | Set commit status to success, bypass branch protections | No — confined to repo |
| `pull-requests: write` | HIGH | Approve PRs without human review, bypass review policy | No — confined to repo |

The model is applied via a weighted scoring function that produces a 0–100 blast radius risk score:

```python
RISK_SCORE_MAP = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

def score_permissions(permissions: dict[str, str]) -> tuple[int, list[PermissionRisk]]:
    raw_score = sum(RISK_SCORE_MAP[f.risk] for f in findings)
    score = min(100, int((raw_score / max_possible) * 100 * 2))
    return score, findings
```

An additional +20 points is applied when `id-token: write` is detected, reflecting the qualitative jump in blast radius when cloud infrastructure is reachable without any stored credentials.

---

### Core Technique 3: Lateral Movement Graph Construction

A key insight of this work is that the blast radius of a single compromised workflow is not bounded by the repository where the workflow runs. The tool explicitly models **lateral movement paths** — edges in a reachability graph from the initial permission set to secondary targets.

```python
@dataclass
class LateralMovementPath:
    from_permission: str   # the permission that enables the pivot
    target: str            # what becomes reachable
    description: str       # the first attacker action that opens the path
    risk: str              # severity of the pivot
```

Lateral movement paths currently modeled:

- **`contents: write`** → all branches → attacker can push workflow changes that trigger with escalated permissions in downstream workflows
- **`packages: write`** → all npm/Maven/Docker/NuGet consumers → full supply chain reach, exiting the repository entirely
- **`id-token: write`** → AWS IAM roles, GCP service accounts, Azure Managed Identities → cloud infrastructure reach with no credential rotation possible until OIDC trust policies are changed
- **`actions: write`** → all workflows in the repository → attacker can trigger workflows that themselves hold higher permissions
- **`deployments: write`** → external deployment targets via webhooks → reach into CD infrastructure outside GitHub
- **`secrets: write`** → all future workflow runs → persistence mechanism; attacker's access survives after the compromised token expires
- **`pages: write`** → github.io domain visitors → phishing/malware distribution from GitHub's trusted infrastructure

---

### Core Technique 4: Secret Scope Enumeration

The tool enumerates secrets in three scopes, each requiring separate API calls:

**Repository-level secrets** — `GET /repos/{owner}/{repo}/actions/secrets`
Available to all workflows in the repository. GitHub returns secret names only (not values), but the names are sufficient for impact assessment — a secret named `STRIPE_SECRET_KEY` or `DATABASE_URL` tells an analyst exactly what the attacker could exfiltrate.

**Organization-level secrets** — `GET /orgs/{org}/actions/secrets`
Secrets shared across multiple repositories. These amplify the blast radius dramatically — compromising one repo's workflow may expose credentials shared with dozens of other repositories.

**Environment-scoped secrets** — via `GET /repos/{owner}/{repo}/environments`
Secrets attached to named deployment environments (`staging`, `production`). These are typically the most sensitive — database URLs, payment processor keys, production API credentials. The tool detects which environments existed and flags them as in-scope if the compromised workflow had deployment permissions.

---

### Core Technique 5: OIDC Cloud Credential Exposure Detection

The most underappreciated attack surface in modern CI/CD is **OpenID Connect (OIDC) token exchange**. When a workflow sets `id-token: write`, it can request a short-lived JWT from GitHub's identity provider and exchange it directly for cloud credentials — bypassing all stored secret management.

The attack chain:
1. Attacker gains code execution inside a workflow (via any supply chain vector)
2. Calls `curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" $ACTIONS_ID_TOKEN_REQUEST_URL` to obtain a signed JWT
3. Exchanges the JWT for AWS temporary credentials via STS AssumeRoleWithWebIdentity — or GCP access tokens via the Workload Identity Federation endpoint
4. Now has cloud access valid for up to 1 hour, with no GitHub token involved

The tool detects this permission explicitly and applies an escalated risk multiplier. Remediation requires hardening the cloud-side OIDC trust policy to restrict which subject claims (specific repos, branches, environments) are permitted to assume the role — changes that must be made in AWS IAM, GCP IAM, or Azure AD, not in the GitHub workflow itself.

---

### Implementation Details

**Language:** Python 3.11+, chosen for YAML parsing reliability (PyYAML), rich standard library data structures, and readability for the security community.

**Dependencies:** Intentionally minimal — only `requests` (GitHub API calls) and `PyYAML` (workflow file parsing). No security-specific frameworks that would add complexity or supply chain risk to the tool itself.

**GitHub API Version:** All calls use the `2022-11-28` stable API version header, ensuring consistent behavior as the GitHub API evolves.

**Authentication:** GitHub Personal Access Token (PAT) or `GITHUB_TOKEN` passed via environment variable. The tool probes the token's actual OAuth scopes via the `X-OAuth-Scopes` response header on the rate-limit endpoint, providing a cross-check against the workflow-declared permissions.

**Permissions Source Precedence:**
1. Explicit `permissions:` block in the workflow YAML at the exact compromise-time commit SHA
2. Job-level `permissions:` override if present (future enhancement)
3. GitHub documented defaults if no explicit block exists

**Report Generation:** Single-file self-contained HTML with inline CSS and SVG. No JavaScript frameworks, no external CDN dependencies — the report can be opened offline, emailed, or included in an incident response ticket without any rendering dependencies.

**Demo Mode:** A fully synthetic `AnalysisResult` representing a realistic high-severity scenario — `pull_request` trigger with default permissions, `id-token: write` exposing AWS production, `packages: write` threatening supply chain, 7 secrets in scope — is built programmatically in `demo_mode.py`. This allows conference demonstration without a live GitHub token or a real compromised repository.

---

### Attack Scenarios Demonstrated

**Scenario 1: The Default Permission Trap**
A workflow with no `permissions:` block — the most common real-world configuration — is analyzed. ForesightOps reveals that GitHub silently granted `contents: write`, `packages: write`, `checks: write`, `pull-requests: write`, and `deployments: write`. Risk score: 72/100 HIGH. Four lateral movement paths identified.

**Scenario 2: The Invisible Cloud Key**
A deploy workflow with `id-token: write` is analyzed. No AWS access keys appear in the secrets list — the team believes their cloud access is well-controlled. ForesightOps reveals the OIDC path: the attacker can mint AWS credentials directly, reaching the production account without any secret rotation being effective. Risk score escalates to 94/100 CRITICAL.

**Scenario 3: Supply Chain Exit**
A release workflow with `packages: write` is analyzed during a `pull_request_target` incident. ForesightOps identifies that the token scope allows publishing to GitHub Packages under the organization's namespace — meaning the attacker could have distributed a malicious version to ~4,000 weekly downstream consumers before the run was detected. Remediation: scope `packages: write` to protected-tag-triggered workflows only.

**Scenario 4: Forensic Evidence Destruction**
A workflow with `security-events: write` and `checks: write` is flagged. ForesightOps surfaces the attacker's capability to dismiss all open SARIF security alerts and forge check results as passed — meaning a sophisticated attacker could have compromised the pipeline, deleted all forensic evidence of the compromise, and merged malicious code through normal review channels.

---

### Remediation Philosophy

Security tools typically produce findings. ForesightOps produces **fixes**. Every finding includes:

- The specific permission or configuration causing the risk
- The exact code change to make (a YAML snippet to paste into the workflow file)
- Where applicable, the cloud-side change required (IAM trust policy, deployment protection rule)
- Priority ordering so the highest-leverage fix is always first

This is deliberate. The tool is designed for incident responders who need to stop a blast radius from growing, not for security teams writing quarterly reports. The output of ForesightOps is a remediation checklist that can be executed in minutes.

---

### Takeaways for the Audience

1. **The default GITHUB_TOKEN permission set is a critical security misconfiguration** affecting the majority of GitHub Actions workflows in production. It should be treated the same way as `chmod 777` on a file — technically functional, and almost always wrong.

2. **`id-token: write` is the most underappreciated blast radius amplifier** in CI/CD security. It bypasses all secret management and gives attackers direct cloud access. Every workflow that sets this permission needs hardened OIDC trust policies on the cloud side.

3. **Blast radius analysis must be automated.** Manual, repo-by-repo permission review is not feasible at the scale organizations run CI/CD today. The defender's answer to "what could the attacker reach?" must be available in seconds, not hours.

4. **The right post-compromise question is not "was my repo affected?" but "given the token that ran, what was the maximum attacker reach?"** ForesightOps operationalizes this reframing as a concrete tool.

---

## Speaker Bio (Template)

**[Name]** is a security researcher focused on CI/CD supply chain security and developer tooling. Their work addresses the gap between vulnerability detection and actionable blast radius analysis in GitHub Actions environments. ForesightOps is an original research contribution presented to help defenders answer the question that matters after a supply chain attack: not whether they were affected, but what the attacker could actually reach. This research is published as open-source at github.com/[username]/foresightops.

---

*ForesightOps v1.0 — Open Source — MIT License*
*github.com/[username]/foresightops*
