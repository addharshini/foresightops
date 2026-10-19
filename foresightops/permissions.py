"""
Maps GitHub Actions workflow permissions to attacker-reachable capabilities.

Valid GITHUB_TOKEN permission scopes per GitHub docs:
actions, checks, contents, deployments, id-token, issues, discussions,
packages, pages, pull-requests, repository-projects, security-events,
statuses, metadata, environments, administration (only for org tokens).

Note: 'secrets' and 'administration' are NOT valid GITHUB_TOKEN workflow scopes.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PermissionRisk:
    permission: str
    level: str           # "write", "read", "none"
    risk: str            # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    attacker_can: list[str] = field(default_factory=list)
    lateral_movement: bool = False
    lateral_targets: list[str] = field(default_factory=list)
    # within this same repository only — GITHUB_TOKEN cannot reach other repos
    lateral_scope: str = "same-repo"
    cve_relevance: Optional[str] = None


PERMISSION_RISK_MAP: dict[str, dict] = {
    "contents": {
        "write": PermissionRisk(
            permission="contents: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Push malicious commits to any unprotected branch",
                "Overwrite release artifacts and tags",
                "Inject backdoors into source files",
                "Delete git refs if branch protections are absent",
            ],
            lateral_movement=True,
            lateral_targets=["All unprotected branches in this repo", "Release artifacts in this repo"],
            lateral_scope="same-repo",
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
            risk="HIGH",
            attacker_can=[
                "Cancel or re-run workflow runs in this repo",
                "Delete workflow run logs (destroy forensic evidence)",
                "Approve pending workflow runs from forks",
            ],
            lateral_movement=True,
            lateral_targets=["Other workflows in this same repo"],
            lateral_scope="same-repo",
        ),
        "read": PermissionRisk(
            permission="actions: read",
            level="read",
            risk="LOW",
            attacker_can=["Read workflow definitions and run history"],
        ),
    },
    "packages": {
        "write": PermissionRisk(
            permission="packages: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Publish new malicious versions to GitHub Packages",
                "Overwrite existing package versions if immutability not enforced",
                "Distribute malware to downstream consumers of this package",
            ],
            lateral_movement=True,
            lateral_targets=["Downstream consumers of packages published by this repo"],
            lateral_scope="supply-chain",
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
                "Request a signed OIDC JWT from GitHub's identity provider",
                "Exchange JWT for AWS/GCP/Azure credentials via federated identity",
                "Access cloud infrastructure without any stored credentials",
                "Privilege level depends entirely on the cloud-side IAM trust policy",
            ],
            lateral_movement=True,
            lateral_targets=[
                "AWS IAM roles configured to trust this repo/branch",
                "GCP service accounts via Workload Identity Federation",
                "Azure Managed Identities via federated credentials",
            ],
            lateral_scope="cloud",
            cve_relevance="Cloud credential theft via OIDC token abuse",
        ),
    },
    "pull-requests": {
        "write": PermissionRisk(
            permission="pull-requests: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Post comments containing exfiltrated data",
                "Approve pull requests (bypass mandatory review)",
                "Edit PR descriptions to inject malicious content",
            ],
            lateral_movement=False,
        ),
        "read": PermissionRisk(
            permission="pull-requests: read",
            level="read",
            risk="LOW",
            attacker_can=["Read PR contents and code review comments"],
        ),
    },
    "deployments": {
        "write": PermissionRisk(
            permission="deployments: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Create deployment records pointing to attacker-controlled environments",
                "Trigger deployment status webhooks to external systems",
                "Mark malicious deployments as successful",
            ],
            lateral_movement=True,
            lateral_targets=["External systems receiving deployment webhooks"],
            lateral_scope="external-webhook",
        ),
    },
    "issues": {
        "write": PermissionRisk(
            permission="issues: write",
            level="write",
            risk="MEDIUM",
            attacker_can=[
                "Post issue comments to exfiltrate small amounts of data",
                "Create issues to generate noise and obscure the attack",
            ],
        ),
    },
    "checks": {
        "write": PermissionRisk(
            permission="checks: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Create or update check runs with forged 'success' conclusions",
                "Suppress failing security scans by overwriting results",
                "Enable PR merge by satisfying required status checks fraudulently",
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
                "Set commit status to 'success' on any commit SHA",
                "Bypass branch protection rules requiring passing statuses",
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
                "Publish malicious content to this repo's GitHub Pages site",
                "Serve malicious JavaScript from a trusted github.io subdomain",
                "Use trusted domain for phishing or malware delivery",
            ],
            lateral_movement=True,
            lateral_targets=["Visitors of this repo's github.io Pages site"],
            lateral_scope="external-users",
        ),
    },
    "repository-projects": {
        "write": PermissionRisk(
            permission="repository-projects: write",
            level="write",
            risk="LOW",
            attacker_can=["Modify project boards — minimal direct security impact"],
        ),
    },
    "security-events": {
        "write": PermissionRisk(
            permission="security-events: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Dismiss open SARIF/code-scanning alerts via API",
                "Upload false-negative SARIF results to hide vulnerabilities",
                "Erase forensic evidence of compromise from the Security tab",
            ],
            lateral_movement=False,
        ),
        "read": PermissionRisk(
            permission="security-events: read",
            level="read",
            risk="MEDIUM",
            attacker_can=["Read all open security vulnerabilities — useful intelligence for further exploitation"],
        ),
    },
    "discussions": {
        "write": PermissionRisk(
            permission="discussions: write",
            level="write",
            risk="LOW",
            attacker_can=["Post to repo discussions — low direct security impact"],
        ),
    },
    "metadata": {
        "read": PermissionRisk(
            permission="metadata: read",
            level="read",
            risk="LOW",
            attacker_can=["Read repository metadata — always granted, not a risk on its own"],
        ),
    },
}


RISK_SCORE_MAP = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

# Permissions that are safe no matter what — explicit empty block or read-all
_SAFE_SENTINELS = {"read-all", "none", ""}


class PermissionParseResult:
    """Carries the parsed permissions plus how they were determined."""
    def __init__(
        self,
        permissions: dict[str, str],
        source: str,          # "explicit", "default", "write-all", "read-all", "empty-block"
        fetch_error: str = "",
    ):
        self.permissions = permissions
        self.source = source
        self.fetch_error = fetch_error

    @property
    def using_default(self) -> bool:
        return self.source == "default"

    @property
    def is_safe_explicit(self) -> bool:
        return self.source in ("read-all", "empty-block")


def score_permissions(permissions: dict[str, str]) -> tuple[int, list[PermissionRisk]]:
    """Return (risk_score 0-100, findings list)."""
    findings: list[PermissionRisk] = []
    raw_score = 0

    for perm, level in permissions.items():
        perm_key = perm.lower().replace("_", "-")
        level_key = level.lower()
        if perm_key in PERMISSION_RISK_MAP and level_key in PERMISSION_RISK_MAP[perm_key]:
            risk = PERMISSION_RISK_MAP[perm_key][level_key]
            findings.append(risk)
            raw_score += RISK_SCORE_MAP.get(risk.risk, 0)

    max_possible = len(PERMISSION_RISK_MAP) * 10
    score = min(100, int((raw_score / max(max_possible, 1)) * 100 * 2))
    return score, findings


def parse_workflow_permissions(yaml_content: str) -> PermissionParseResult:
    """
    Parse the top-level permissions block from workflow YAML.

    Handles:
      - No permissions key            -> source="default"
      - permissions: {}               -> source="empty-block" (safe, score 0)
      - permissions: read-all         -> source="read-all"   (safe, score low)
      - permissions: write-all        -> source="write-all"  (all write)
      - permissions: {key: value,...} -> source="explicit"
    """
    try:
        import yaml
        data = yaml.safe_load(yaml_content)
        if not data:
            return PermissionParseResult(default_github_token_permissions(), "default")

        if "permissions" not in data:
            return PermissionParseResult(default_github_token_permissions(), "default")

        top_level = data["permissions"]

        # Explicit string shorthand
        if isinstance(top_level, str):
            val = top_level.strip().lower()
            if val == "write-all":
                perms = {p: "write" for p in PERMISSION_RISK_MAP.keys()}
                return PermissionParseResult(perms, "write-all")
            # read-all, none, or anything else -> treat as safe
            return PermissionParseResult({}, "read-all")

        # Empty dict {} — explicit minimal grant
        if isinstance(top_level, dict) and len(top_level) == 0:
            return PermissionParseResult({}, "empty-block")

        # Normal dict of permission: level pairs
        if isinstance(top_level, dict):
            perms = {k: str(v) for k, v in top_level.items()}
            return PermissionParseResult(perms, "explicit")

        # null / unexpected value
        return PermissionParseResult(default_github_token_permissions(), "default")

    except Exception as e:
        return PermissionParseResult(
            default_github_token_permissions(), "default",
            fetch_error=f"YAML parse error: {e}"
        )


def default_github_token_permissions() -> dict[str, str]:
    """
    GitHub's legacy permissive defaults for repos that have not opted into
    restricted defaults. New orgs/repos may default to read-only — the tool
    uses these when it cannot determine the repo's default-permission setting.
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
