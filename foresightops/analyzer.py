"""
Core blast radius analyzer.
Orchestrates GitHub API calls, permission scoring, and secret exposure detection.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .github_client import GitHubClient
from .permissions import (
    PermissionRisk,
    default_github_token_permissions,
    parse_workflow_permissions,
    score_permissions,
)


@dataclass
class SecretExposure:
    name: str
    scope: str          # "repo", "org", "environment"
    environment: Optional[str] = None


@dataclass
class LateralMovementPath:
    from_permission: str
    target: str
    description: str
    risk: str


@dataclass
class Remediation:
    finding: str
    action: str
    code_example: Optional[str] = None
    priority: str = "HIGH"


@dataclass
class AnalysisResult:
    owner: str
    repo: str
    run_id: int
    run_url: str
    workflow_name: str
    triggered_by: str
    run_started_at: str
    risk_score: int
    risk_label: str
    permissions_used: dict[str, str]
    permission_findings: list[PermissionRisk]
    exposed_secrets: list[SecretExposure]
    lateral_paths: list[LateralMovementPath]
    remediations: list[Remediation]
    token_scopes: list[str]
    environments: list[str]
    using_default_permissions: bool
    has_id_token: bool
    jobs: list[dict]
    analysis_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


def _risk_label(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


class BlastRadiusAnalyzer:
    def __init__(self, token: str):
        self.client = GitHubClient(token)

    def analyze(self, owner: str, repo: str, run_id: int) -> AnalysisResult:
        # 1. Fetch run metadata
        run = self.client.get_workflow_run(owner, repo, run_id)
        jobs = self.client.get_workflow_run_jobs(owner, repo, run_id)

        workflow_id = run.get("workflow_id")
        workflow_name = run.get("name", "unknown")
        triggered_by = run.get("event", "unknown")
        run_started_at = run.get("run_started_at", run.get("created_at", ""))
        run_url = run.get("html_url", f"https://github.com/{owner}/{repo}/actions/runs/{run_id}")

        # 2. Fetch and parse the workflow YAML for explicit permissions
        workflow_path = run.get("path", "")
        ref = run.get("head_sha", "HEAD")
        using_default = True
        permissions: dict[str, str] = {}

        if workflow_path:
            yaml_content = self.client.get_workflow_yaml_content(owner, repo, workflow_path, ref)
            if yaml_content:
                permissions = parse_workflow_permissions(yaml_content)

        if not permissions:
            permissions = default_github_token_permissions()
        else:
            using_default = False

        # 3. Token scopes
        token_info = self.client.get_token_permissions()
        token_scopes = token_info.get("scopes", [])

        # 4. Score permissions
        risk_score, findings = score_permissions(permissions)

        # 5. Exposed secrets
        exposed_secrets: list[SecretExposure] = []
        repo_secrets = self.client.get_repo_secrets(owner, repo)
        for s in repo_secrets:
            exposed_secrets.append(SecretExposure(name=s["name"], scope="repo"))

        # Org secrets if applicable
        repo_info = self.client.get_repo(owner, repo)
        org = repo_info.get("organization", {}) or {}
        org_login = org.get("login") if isinstance(org, dict) else None
        if org_login:
            org_secrets = self.client.get_org_secrets(org_login)
            for s in org_secrets:
                exposed_secrets.append(SecretExposure(name=s["name"], scope="org"))

        # Environment secrets
        environments_raw = self.client.get_repo_environments(owner, repo)
        env_names = [e.get("name", "") for e in environments_raw]

        # 6. Lateral movement paths
        lateral_paths: list[LateralMovementPath] = []
        for f in findings:
            if f.lateral_movement:
                for target in f.lateral_targets:
                    lateral_paths.append(LateralMovementPath(
                        from_permission=f.permission,
                        target=target,
                        description=f.attacker_can[0] if f.attacker_can else "",
                        risk=f.risk,
                    ))

        # 7. Check OIDC / id-token
        has_id_token = "id-token" in permissions and permissions["id-token"] == "write"
        if has_id_token:
            risk_score = min(100, risk_score + 20)

        # 8. Build remediations
        remediations = _build_remediations(findings, using_default, has_id_token, exposed_secrets)

        return AnalysisResult(
            owner=owner,
            repo=repo,
            run_id=run_id,
            run_url=run_url,
            workflow_name=workflow_name,
            triggered_by=triggered_by,
            run_started_at=run_started_at,
            risk_score=risk_score,
            risk_label=_risk_label(risk_score),
            permissions_used=permissions,
            permission_findings=findings,
            exposed_secrets=exposed_secrets,
            lateral_paths=lateral_paths,
            remediations=remediations,
            token_scopes=token_scopes,
            environments=env_names,
            using_default_permissions=using_default,
            has_id_token=has_id_token,
            jobs=[{"name": j.get("name"), "status": j.get("status"), "conclusion": j.get("conclusion")} for j in jobs],
        )


def _build_remediations(
    findings: list[PermissionRisk],
    using_default: bool,
    has_id_token: bool,
    secrets: list[SecretExposure],
) -> list[Remediation]:
    items: list[Remediation] = []

    if using_default:
        items.append(Remediation(
            finding="Workflow uses GitHub's over-permissive default token permissions",
            action="Set explicit minimal permissions at the workflow level",
            code_example=(
                "permissions:\n"
                "  contents: read   # only what this job needs\n"
                "  # remove everything else"
            ),
            priority="CRITICAL",
        ))

    for f in findings:
        if f.risk in ("CRITICAL", "HIGH") and f.level == "write":
            items.append(Remediation(
                finding=f"Overly broad permission: {f.permission}",
                action=f"Restrict to read-only or remove if not needed",
                code_example=f"# Change:\n{f.permission}\n# To:\n{f.permission.replace('write', 'read')}",
                priority=f.risk,
            ))

    if has_id_token:
        items.append(Remediation(
            finding="id-token: write enables OIDC cloud credential minting",
            action="Restrict OIDC trust policy to specific branch refs and audience claims",
            code_example=(
                "# In your AWS trust policy, add conditions:\n"
                "\"StringLike\": {\n"
                "  \"token.actions.githubusercontent.com:sub\":\n"
                "  \"repo:ORG/REPO:ref:refs/heads/main\"\n"
                "}"
            ),
            priority="CRITICAL",
        ))

    if secrets:
        items.append(Remediation(
            finding=f"{len(secrets)} secret(s) in scope for this workflow run",
            action="Audit which secrets are truly needed; use environment-scoped secrets with deployment protection rules",
            code_example=(
                "environment: production   # requires manual approval\n"
                "# Secrets scoped here won't leak to untrusted PRs"
            ),
            priority="HIGH",
        ))

    # Pinning recommendation
    items.append(Remediation(
        finding="Actions may be referenced by mutable tags (e.g. @v3) rather than commit SHA",
        action="Pin all third-party actions to full commit SHAs to prevent tag-based supply chain attacks",
        code_example=(
            "# Instead of:\n"
            "uses: actions/checkout@v4\n"
            "# Use:\n"
            "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2"
        ),
        priority="HIGH",
    ))

    return items
