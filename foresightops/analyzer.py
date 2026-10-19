"""Core blast radius analyzer."""

import html as html_lib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .github_client import GitHubClient
from .permissions import (
    PermissionRisk,
    PermissionParseResult,
    default_github_token_permissions,
    parse_workflow_permissions,
    score_permissions,
)


@dataclass
class SecretExposure:
    name: str
    scope: str           # "repo", "org", "environment"
    environment: Optional[str] = None
    note: str = ""       # e.g. "API error — may be incomplete"


@dataclass
class LateralMovementPath:
    from_permission: str
    target: str
    description: str
    risk: str
    scope: str = "same-repo"   # "same-repo", "supply-chain", "cloud", "external-webhook"


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
    permission_source: str       # "explicit", "default", "write-all", "read-all", "empty-block"
    permission_findings: list[PermissionRisk]
    exposed_secrets: list[SecretExposure]
    secrets_note: str            # warning if secrets API had errors
    lateral_paths: list[LateralMovementPath]
    remediations: list[Remediation]
    token_scopes: list[str]
    environments: list[str]
    has_id_token: bool
    jobs: list[dict]
    repo_default_workflow_permissions: Optional[str] = None
    workflow_yaml_content: str = ""   # raw YAML for package-name scanning in threat intel section
    analysis_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    @property
    def using_default_permissions(self) -> bool:
        return self.permission_source == "default"

    @property
    def is_safe_explicit(self) -> bool:
        return self.permission_source in ("read-all", "empty-block")


def _risk_label(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _escape(value: str) -> str:
    """HTML-escape any user-controlled string before inserting into the report."""
    return html_lib.escape(str(value), quote=True)


class BlastRadiusAnalyzer:
    def __init__(self, token: str):
        self.client = GitHubClient(token)

    def analyze(self, owner: str, repo: str, run_id: int) -> AnalysisResult:
        # 1. Fetch run metadata
        run = self.client.get_workflow_run(owner, repo, run_id)
        jobs = self.client.get_workflow_run_jobs(owner, repo, run_id)

        workflow_name = run.get("name", "unknown")
        triggered_by = run.get("event", "unknown")
        run_started_at = run.get("run_started_at", run.get("created_at", ""))
        run_url = run.get("html_url", f"https://github.com/{owner}/{repo}/actions/runs/{run_id}")
        workflow_path = run.get("path", "")
        ref = run.get("head_sha", "HEAD")

        # 2. Check repo's default workflow permission setting
        repo_default_perm = self.client.get_repo_default_workflow_permissions(owner, repo)

        # 3. Fetch and parse workflow YAML at the exact commit SHA
        parse_result: PermissionParseResult
        yaml_fetch_error = ""

        stored_yaml = ""
        if workflow_path:
            yaml_content, yaml_fetch_error = self.client.get_workflow_yaml_content(owner, repo, workflow_path, ref)
            if yaml_content:
                stored_yaml = yaml_content
                parse_result = parse_workflow_permissions(yaml_content)
            else:
                # Could not fetch YAML — fall back to defaults but flag it clearly
                parse_result = PermissionParseResult(
                    default_github_token_permissions(), "default",
                    fetch_error=yaml_fetch_error or "Workflow YAML could not be retrieved"
                )
        else:
            parse_result = PermissionParseResult(default_github_token_permissions(), "default")

        # If repo uses restricted defaults and workflow has no block, use read-only defaults
        if parse_result.source == "default" and repo_default_perm == "read":
            parse_result = PermissionParseResult(
                {"contents": "read", "metadata": "read"},
                "default",
                fetch_error=parse_result.fetch_error,
            )

        permissions = parse_result.permissions

        # 4. Token scopes
        token_info = self.client.get_token_permissions()
        token_scopes = token_info.get("scopes", [])

        # 5. Score permissions — safe explicit blocks score zero
        if parse_result.is_safe_explicit:
            risk_score, findings = 0, []
        else:
            risk_score, findings = score_permissions(permissions)

        # 6. Secrets — repo level
        exposed_secrets: list[SecretExposure] = []
        secrets_warnings: list[str] = []

        repo_secrets, repo_err = self.client.get_repo_secrets(owner, repo)
        if repo_err:
            secrets_warnings.append(f"Repo secrets: {repo_err}")
        for s in repo_secrets:
            exposed_secrets.append(SecretExposure(name=s["name"], scope="repo"))

        # Org secrets scoped to this repo (not the whole org list)
        org_secrets, org_err = self.client.get_org_secrets_for_repo(owner, repo)
        if org_err:
            secrets_warnings.append(f"Org secrets: {org_err}")
        for s in org_secrets:
            exposed_secrets.append(SecretExposure(name=s["name"], scope="org"))

        # Environment secrets — only environments this workflow references
        environments_raw = self.client.get_repo_environments(owner, repo)
        env_names = [e.get("name", "") for e in environments_raw]

        for env_name in env_names:
            env_secrets, env_err = self.client.get_environment_secrets(owner, repo, env_name)
            if env_err:
                secrets_warnings.append(f"Environment '{env_name}' secrets: {env_err}")
            for s in env_secrets:
                exposed_secrets.append(SecretExposure(name=s["name"], scope="environment", environment=env_name))

        secrets_note = "; ".join(secrets_warnings) if secrets_warnings else ""

        # 7. Lateral movement — scoped to what GITHUB_TOKEN can actually do
        lateral_paths: list[LateralMovementPath] = []
        for f in findings:
            if f.lateral_movement:
                for target in f.lateral_targets:
                    lateral_paths.append(LateralMovementPath(
                        from_permission=f.permission,
                        target=target,
                        description=f.attacker_can[0] if f.attacker_can else "",
                        risk=f.risk,
                        scope=f.lateral_scope,
                    ))

        # 8. OIDC bonus
        has_id_token = permissions.get("id-token", "").lower() == "write"
        if has_id_token:
            risk_score = min(100, risk_score + 20)

        # 9. Remediations
        remediations = _build_remediations(
            findings, parse_result, has_id_token, exposed_secrets, yaml_fetch_error
        )

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
            permission_source=parse_result.source,
            permission_findings=findings,
            exposed_secrets=exposed_secrets,
            secrets_note=secrets_note,
            lateral_paths=lateral_paths,
            remediations=remediations,
            token_scopes=token_scopes,
            environments=env_names,
            has_id_token=has_id_token,
            repo_default_workflow_permissions=repo_default_perm,
            jobs=[{
                "name": j.get("name"),
                "status": j.get("status"),
                "conclusion": j.get("conclusion"),
            } for j in jobs],
            workflow_yaml_content=stored_yaml,
        )


def _build_remediations(
    findings: list[PermissionRisk],
    parse_result: PermissionParseResult,
    has_id_token: bool,
    secrets: list[SecretExposure],
    yaml_fetch_error: str,
) -> list[Remediation]:
    items: list[Remediation] = []

    if yaml_fetch_error:
        items.append(Remediation(
            finding=f"Workflow YAML could not be fetched: {yaml_fetch_error}",
            action="Verify the token has 'contents: read' access and the workflow path is correct. Results below assume worst-case defaults.",
            priority="HIGH",
        ))

    if parse_result.source == "default":
        items.append(Remediation(
            finding="No explicit permissions block — GitHub defaults are applied",
            action="Add a minimal permissions block at the top of the workflow file",
            code_example=(
                " # workflow.yml\n"
                "-# (no permissions block — GitHub defaults apply)\n"
                "+permissions:\n"
                "+  contents: read   # grant only what this workflow needs"
            ),
            priority="CRITICAL",
        ))
    elif parse_result.source == "write-all":
        items.append(Remediation(
            finding="permissions: write-all grants maximum write access to all scopes",
            action="Replace with an explicit minimal permissions block",
            code_example=(
                " # workflow.yml\n"
                "-permissions: write-all\n"
                "+permissions:\n"
                "+  contents: read\n"
                "+  packages: write   # only if this workflow publishes"
            ),
            priority="CRITICAL",
        ))

    for f in findings:
        if f.risk in ("CRITICAL", "HIGH") and f.level == "write":
            perm_name = f.permission.split(":")[0].strip()
            items.append(Remediation(
                finding=f"Overly broad permission: {f.permission}",
                action="Restrict to read-only or remove entirely if not needed",
                code_example=(
                    f" permissions:\n"
                    f"-  {perm_name}: write\n"
                    f"+  {perm_name}: read"
                ),
                priority=f.risk,
            ))

    if has_id_token:
        items.append(Remediation(
            finding="id-token: write allows OIDC cloud credential minting",
            action="Restrict the cloud-side IAM trust policy to specific branches and audiences",
            code_example=(
                " # AWS IAM trust policy — restrict to main branch only\n"
                '-  "token.actions.githubusercontent.com:sub": "*"\n'
                '+"token.actions.githubusercontent.com:sub":\n'
                '+  "repo:ORG/REPO:ref:refs/heads/main"'
            ),
            priority="CRITICAL",
        ))

    if secrets:
        items.append(Remediation(
            finding=f"{len(secrets)} secret(s) in scope for this workflow run",
            action="Scope sensitive secrets to named environments with deployment protection rules",
            code_example=(
                " jobs:\n"
                "   deploy:\n"
                "-    # secrets injected into every job\n"
                "+    environment: production   # approval gate required\n"
                "+    # secrets only injected after human approval"
            ),
            priority="HIGH",
        ))

    items.append(Remediation(
        finding="Third-party actions referenced by mutable version tags",
        action="Pin all actions to a full commit SHA to prevent tag-based supply chain attacks",
        code_example=(
            " steps:\n"
            "-  - uses: actions/checkout@v4\n"
            "+  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2"
        ),
        priority="HIGH",
    ))

    return items
