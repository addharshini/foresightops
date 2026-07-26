"""
Maps GitHub Actions workflow permissions to attacker-reachable capabilities.

Each permission key maps to what an attacker with that permission can do,
what secrets/resources are exposed, and whether lateral movement is possible.
"""

from dataclasses import dataclass, field
from typing import Optional


WRITE_ACCESS_RISK = "HIGH"
READ_ACCESS_RISK = "MEDIUM"
NONE_RISK = "LOW"


@dataclass
class PermissionRisk:
    permission: str
    level: str           # "write", "read", "none"
    risk: str            # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    attacker_can: list[str] = field(default_factory=list)
    lateral_movement: bool = False
    lateral_targets: list[str] = field(default_factory=list)
    cve_relevance: Optional[str] = None


# Comprehensive permission → risk mapping
PERMISSION_RISK_MAP: dict[str, dict] = {
    "contents": {
        "write": PermissionRisk(
            permission="contents: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Push malicious code to any branch",
                "Overwrite release artifacts",
                "Tamper with source files",
                "Inject backdoors into codebase",
                "Delete or rewrite git history (if branch protections absent)",
            ],
            lateral_movement=True,
            lateral_targets=["All branches in repo", "Protected branches if rules allow Actions"],
            cve_relevance="pwn-request / pull_request_target misuse",
        ),
        "read": PermissionRisk(
            permission="contents: read",
            level="read",
            risk="MEDIUM",
            attacker_can=["Read all source code including private files", "Exfiltrate proprietary code"],
        ),
    },
    "actions": {
        "write": PermissionRisk(
            permission="actions: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Trigger arbitrary workflow runs",
                "Delete workflow run logs (cover tracks)",
                "Cancel in-progress security scans",
                "Approve workflow runs on forks",
            ],
            lateral_movement=True,
            lateral_targets=["Any workflow in the repository"],
        ),
        "read": PermissionRisk(
            permission="actions: read",
            level="read",
            risk="LOW",
            attacker_can=["Read workflow definitions and run history"],
        ),
    },
    "secrets": {
        "write": PermissionRisk(
            permission="secrets: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Overwrite existing secrets with attacker-controlled values",
                "Inject malicious credentials into future workflow runs",
                "Persist access even after initial token expires",
            ],
            lateral_movement=True,
            lateral_targets=["All future workflow runs that consume those secrets"],
        ),
    },
    "packages": {
        "write": PermissionRisk(
            permission="packages: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Publish malicious package versions to GitHub Packages",
                "Overwrite existing package versions (supply chain attack)",
                "Distribute malware to all downstream consumers",
            ],
            lateral_movement=True,
            lateral_targets=["Any consumer of affected package (supply chain)"],
            cve_relevance="Supply chain compromise via package poisoning",
        ),
        "read": PermissionRisk(
            permission="packages: read",
            level="read",
            risk="MEDIUM",
            attacker_can=["Download private packages", "Enumerate internal dependencies"],
        ),
    },
    "id-token": {
        "write": PermissionRisk(
            permission="id-token: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Request OIDC JWT token from GitHub's identity provider",
                "Authenticate to AWS/GCP/Azure without stored credentials",
                "Access cloud infrastructure directly",
                "Escalate to cloud admin depending on trust policy",
            ],
            lateral_movement=True,
            lateral_targets=["AWS accounts", "GCP projects", "Azure subscriptions", "Any OIDC-trusting service"],
            cve_relevance="Cloud credential theft via OIDC token theft",
        ),
    },
    "pull-requests": {
        "write": PermissionRisk(
            permission="pull-requests: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Post comments to exfiltrate data via PR body",
                "Approve pull requests (bypass review requirements)",
                "Merge PRs if branch protection allows",
            ],
            lateral_movement=False,
        ),
        "read": PermissionRisk(
            permission="pull-requests: read",
            level="read",
            risk="LOW",
            attacker_can=["Read PR contents including sensitive code review comments"],
        ),
    },
    "deployments": {
        "write": PermissionRisk(
            permission="deployments: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Create deployment records for attacker-controlled environments",
                "Trigger deployment webhooks to external systems",
                "Mark malicious deployments as successful",
            ],
            lateral_movement=True,
            lateral_targets=["External deployment targets via webhooks"],
        ),
    },
    "issues": {
        "write": PermissionRisk(
            permission="issues: write",
            level="write",
            risk="MEDIUM",
            attacker_can=["Exfiltrate data via issue comments", "Create noise to obscure the attack"],
        ),
    },
    "checks": {
        "write": PermissionRisk(
            permission="checks: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Mark security check runs as passed (bypass gates)",
                "Suppress failing security scans",
                "Forge check results to enable PR merge",
            ],
            lateral_movement=False,
        ),
    },
    "statuses": {
        "write": PermissionRisk(
            permission="statuses: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Set commit status to success on any commit",
                "Bypass status-check branch protection rules",
            ],
            lateral_movement=False,
        ),
    },
    "pages": {
        "write": PermissionRisk(
            permission="pages: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Publish malicious content to GitHub Pages site",
                "Perform phishing attacks from trusted github.io domain",
                "Serve malicious JavaScript to site visitors",
            ],
            lateral_movement=True,
            lateral_targets=["github.io domain visitors"],
        ),
    },
    "repository-projects": {
        "write": PermissionRisk(
            permission="repository-projects: write",
            level="write",
            risk="LOW",
            attacker_can=["Modify project boards — low direct impact"],
        ),
    },
    "security-events": {
        "write": PermissionRisk(
            permission="security-events: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Dismiss SARIF security alerts",
                "Suppress code scanning findings",
                "Hide evidence of compromise in Security tab",
            ],
            lateral_movement=False,
        ),
        "read": PermissionRisk(
            permission="security-events: read",
            level="read",
            risk="MEDIUM",
            attacker_can=["Read all open security vulnerabilities — intelligence for further attacks"],
        ),
    },
    "administration": {
        "write": PermissionRisk(
            permission="administration: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Modify branch protection rules (disable required reviews)",
                "Add attacker as repository collaborator",
                "Change repository visibility to public",
                "Delete repository",
                "Disable security features",
            ],
            lateral_movement=True,
            lateral_targets=["All branches and settings in repository"],
            cve_relevance="Full repository takeover",
        ),
    },
}


RISK_SCORE_MAP = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}


def score_permissions(permissions: dict[str, str]) -> tuple[int, list[PermissionRisk]]:
    """
    Given a dict of {permission_name: level}, return (risk_score, findings).
    risk_score is 0–100.
    """
    findings: list[PermissionRisk] = []
    raw_score = 0

    for perm, level in permissions.items():
        perm_lower = perm.lower().replace("_", "-")
        level_lower = level.lower()

        if perm_lower in PERMISSION_RISK_MAP and level_lower in PERMISSION_RISK_MAP[perm_lower]:
            risk = PERMISSION_RISK_MAP[perm_lower][level_lower]
            findings.append(risk)
            raw_score += RISK_SCORE_MAP.get(risk.risk, 0)

    # Normalize to 0-100, cap at 100
    max_possible = len(PERMISSION_RISK_MAP) * 10
    score = min(100, int((raw_score / max(max_possible, 1)) * 100 * 2))
    return score, findings


def parse_workflow_permissions(yaml_content: str) -> dict[str, str]:
    """Extract the top-level and job-level permissions from workflow YAML."""
    try:
        import yaml
        data = yaml.safe_load(yaml_content)
        if not data:
            return {}

        top_level = data.get("permissions", {})
        if isinstance(top_level, str):
            # "permissions: write-all" or "permissions: read-all"
            if "write" in top_level:
                return {p: "write" for p in PERMISSION_RISK_MAP.keys()}
            return {}
        if isinstance(top_level, dict):
            return {k: v for k, v in top_level.items()}
        return {}
    except Exception:
        return {}


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
