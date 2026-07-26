"""
Demo mode — generates a realistic synthetic analysis result for conference demos.
No real GitHub token needed.
"""

from .analyzer import AnalysisResult
from .permissions import PermissionRisk
from .analyzer import SecretExposure, LateralMovementPath, Remediation


def build_demo_result() -> AnalysisResult:
    """Returns a pre-built analysis showing a high-impact supply chain compromise scenario."""

    findings = [
        PermissionRisk(
            permission="contents: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Push malicious code to any branch",
                "Overwrite release artifacts",
                "Inject backdoors into codebase",
            ],
            lateral_movement=True,
            lateral_targets=["All branches in repo", "Release pipeline"],
            cve_relevance="pwn-request / pull_request_target misuse",
        ),
        PermissionRisk(
            permission="packages: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Publish malicious package versions to GitHub Packages",
                "Overwrite existing package versions (supply chain attack)",
                "Distribute malware to all downstream consumers",
            ],
            lateral_movement=True,
            lateral_targets=["All npm/Docker consumers of acme-corp packages"],
            cve_relevance="Supply chain compromise via package poisoning",
        ),
        PermissionRisk(
            permission="id-token: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Request OIDC JWT from GitHub identity provider",
                "Authenticate to AWS without stored credentials",
                "Access S3 buckets, ECS clusters, Lambda functions",
            ],
            lateral_movement=True,
            lateral_targets=["AWS us-east-1 production account", "GCP project: acme-prod-441"],
        ),
        PermissionRisk(
            permission="checks: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Mark security scan as passed (bypass gate)",
                "Suppress failing SAST/SCA findings",
                "Forge check results to enable PR merge",
            ],
            lateral_movement=False,
        ),
        PermissionRisk(
            permission="security-events: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Dismiss all open SARIF security alerts",
                "Hide evidence of compromise in Security tab",
            ],
            lateral_movement=False,
        ),
        PermissionRisk(
            permission="pull-requests: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Approve pull requests without human review",
                "Bypass branch protection review requirements",
            ],
            lateral_movement=False,
        ),
    ]

    lateral_paths = [
        LateralMovementPath("contents: write", "Push backdoor to main branch", "All branches in acme-corp/api-service", "CRITICAL"),
        LateralMovementPath("packages: write", "Overwrite npm package @acme/sdk v2.1.4", "All downstream consumers (~4,200 installs/week)", "CRITICAL"),
        LateralMovementPath("id-token: write", "Mint AWS credentials via OIDC", "AWS Production Account (arn:aws:iam::123456789:role/github-actions)", "CRITICAL"),
    ]

    secrets = [
        SecretExposure("AWS_ACCESS_KEY_ID", "repo"),
        SecretExposure("AWS_SECRET_ACCESS_KEY", "repo"),
        SecretExposure("NPM_PUBLISH_TOKEN", "org"),
        SecretExposure("DOCKER_HUB_TOKEN", "org"),
        SecretExposure("SLACK_WEBHOOK_URL", "repo"),
        SecretExposure("DATABASE_URL", "environment", "production"),
        SecretExposure("STRIPE_SECRET_KEY", "environment", "production"),
    ]

    remediations = [
        Remediation(
            finding="Workflow uses GitHub's over-permissive default token permissions",
            action="Set explicit minimal permissions at the workflow level",
            code_example=(
                "permissions:\n"
                "  contents: read   # was: write (default)\n"
                "  # Remove packages, id-token unless explicitly needed"
            ),
            priority="CRITICAL",
        ),
        Remediation(
            finding="id-token: write enables OIDC cloud credential minting",
            action="Restrict OIDC trust policy to specific branch refs only",
            code_example=(
                '# AWS trust policy condition:\n'
                '"StringEquals": {\n'
                '  "token.actions.githubusercontent.com:sub":\n'
                '  "repo:acme-corp/api-service:ref:refs/heads/main"\n'
                '}'
            ),
            priority="CRITICAL",
        ),
        Remediation(
            finding="packages: write exposes entire supply chain",
            action="Scope package publishing to release workflows only, triggered from protected tags",
            code_example=(
                "on:\n"
                "  push:\n"
                "    tags: ['v*']   # only on version tags\n\n"
                "permissions:\n"
                "  packages: write  # only in this narrowly scoped workflow"
            ),
            priority="CRITICAL",
        ),
        Remediation(
            finding="7 secrets in scope — including production database and payment keys",
            action="Use environment-scoped secrets with deployment protection rules requiring manual approval",
            code_example=(
                "jobs:\n"
                "  deploy:\n"
                "    environment: production   # requires human approval\n"
                "    # STRIPE_SECRET_KEY only available after approval"
            ),
            priority="HIGH",
        ),
        Remediation(
            finding="Third-party actions referenced by mutable version tags",
            action="Pin all actions to full commit SHA to prevent tag hijacking",
            code_example=(
                "# Before (vulnerable):\n"
                "uses: actions/checkout@v4\n\n"
                "# After (safe):\n"
                "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2"
            ),
            priority="HIGH",
        ),
    ]

    return AnalysisResult(
        owner="acme-corp",
        repo="api-service",
        run_id=9182736450,
        run_url="https://github.com/acme-corp/api-service/actions/runs/9182736450",
        workflow_name="Build, Test & Deploy",
        triggered_by="pull_request",
        run_started_at="2026-06-27T14:32:11Z",
        risk_score=94,
        risk_label="CRITICAL",
        permissions_used={
            "contents": "write",
            "packages": "write",
            "id-token": "write",
            "checks": "write",
            "security-events": "write",
            "pull-requests": "write",
            "issues": "write",
            "deployments": "write",
        },
        permission_findings=findings,
        exposed_secrets=secrets,
        lateral_paths=lateral_paths,
        remediations=remediations,
        token_scopes=["repo", "workflow", "write:packages"],
        environments=["staging", "production"],
        using_default_permissions=True,
        has_id_token=True,
        jobs=[
            {"name": "lint", "status": "completed", "conclusion": "success"},
            {"name": "test", "status": "completed", "conclusion": "success"},
            {"name": "build-and-push", "status": "completed", "conclusion": "success"},
            {"name": "deploy-production", "status": "completed", "conclusion": "success"},
        ],
    )
