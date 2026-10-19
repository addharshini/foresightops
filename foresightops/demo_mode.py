"""
Demo mode — synthetic scenario for conference demonstrations.
No GitHub token required.

Scenario: A release workflow with explicit dangerous permissions
(packages: write + id-token: write) that was triggered from a tag push.
This is a realistic configuration seen in many open-source and enterprise repos.
All numbers and org names are synthetic and clearly labeled.
"""

from .analyzer import AnalysisResult
from .permissions import PermissionRisk, PermissionParseResult
from .analyzer import SecretExposure, LateralMovementPath, Remediation


def build_demo_result() -> AnalysisResult:

    findings = [
        PermissionRisk(
            permission="contents: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Push malicious commits to any unprotected branch",
                "Overwrite release artifacts and tags",
                "Inject backdoors into source files",
            ],
            lateral_movement=True,
            lateral_targets=["All unprotected branches in this repo"],
            lateral_scope="same-repo",
            cve_relevance="pull_request_target misuse / pwn-request",
        ),
        PermissionRisk(
            permission="packages: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Publish malicious versions to GitHub Packages",
                "Overwrite existing package versions if immutability not enforced",
                "Distribute malware to downstream consumers (synthetic example: ~3,000 weekly downloads)",
            ],
            lateral_movement=True,
            lateral_targets=["Downstream consumers of packages published by this repo [synthetic]"],
            lateral_scope="supply-chain",
            cve_relevance="Supply chain compromise via package poisoning",
        ),
        PermissionRisk(
            permission="id-token: write",
            level="write",
            risk="CRITICAL",
            attacker_can=[
                "Request a signed OIDC JWT from GitHub's identity provider",
                "Exchange JWT for AWS temporary credentials via STS AssumeRoleWithWebIdentity",
                "Access cloud resources — scope depends on the IAM trust policy",
            ],
            lateral_movement=True,
            lateral_targets=[
                "AWS IAM roles trusting this repo [synthetic: arn:aws:iam::111122223333:role/github-actions]",
                "GCP/Azure if federated credentials are configured",
            ],
            lateral_scope="cloud",
            cve_relevance="Cloud credential theft via OIDC token abuse",
        ),
        PermissionRisk(
            permission="checks: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Create check runs with forged 'success' conclusions",
                "Suppress failing SAST/SCA scan results",
                "Enable PR merge by satisfying required status checks fraudulently",
            ],
            lateral_movement=False,
        ),
        PermissionRisk(
            permission="security-events: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Dismiss open SARIF/code-scanning alerts via API",
                "Erase forensic evidence of compromise from the Security tab",
            ],
            lateral_movement=False,
        ),
        PermissionRisk(
            permission="pull-requests: write",
            level="write",
            risk="HIGH",
            attacker_can=[
                "Approve pull requests without human review",
                "Bypass mandatory code review requirements",
            ],
            lateral_movement=False,
        ),
    ]

    lateral_paths = [
        LateralMovementPath(
            "contents: write",
            "Push malicious commit to main branch",
            "All unprotected branches in this repo [same-repo only]",
            "CRITICAL",
            "same-repo",
        ),
        LateralMovementPath(
            "packages: write",
            "Publish malicious package version to GitHub Packages",
            "Downstream consumers [synthetic: ~3,000 weekly downloads]",
            "CRITICAL",
            "supply-chain",
        ),
        LateralMovementPath(
            "id-token: write",
            "Mint AWS credentials via OIDC (no stored key needed)",
            "AWS production account [synthetic: arn:aws:iam::111122223333:role/github-actions]",
            "CRITICAL",
            "cloud",
        ),
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
            finding="contents: write, packages: write, id-token: write are all explicitly set",
            action="Scope each dangerous permission to the specific job that needs it, not the whole workflow",
            code_example=(
                "# Instead of top-level:\n"
                "# permissions:\n"
                "#   packages: write\n"
                "#   id-token: write\n\n"
                "# Scope per job:\n"
                "jobs:\n"
                "  publish:\n"
                "    permissions:\n"
                "      packages: write   # only this job\n"
                "  deploy:\n"
                "    permissions:\n"
                "      id-token: write   # only this job"
            ),
            priority="CRITICAL",
        ),
        Remediation(
            finding="id-token: write allows OIDC cloud credential minting",
            action="Restrict the AWS/GCP trust policy to specific branch refs and audiences",
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
            finding="packages: write is set — supply chain risk if run on untrusted input",
            action="Trigger package publishing only from protected tags, not from pull_request events",
            code_example=(
                "on:\n"
                "  push:\n"
                "    tags: ['v*']   # protected tags only\n\n"
                "permissions:\n"
                "  packages: write  # scoped to this release workflow only"
            ),
            priority="CRITICAL",
        ),
        Remediation(
            finding="7 secrets in scope including production database and payment keys [synthetic]",
            action="Scope sensitive secrets to named deployment environments with approval gates",
            code_example=(
                "jobs:\n"
                "  deploy:\n"
                "    environment: production   # requires manual approval\n"
                "    # STRIPE_SECRET_KEY only injected after a human approves"
            ),
            priority="HIGH",
        ),
        Remediation(
            finding="Third-party actions referenced by mutable version tags",
            action="Pin all actions to full commit SHAs",
            code_example=(
                "# Vulnerable:\n"
                "uses: actions/checkout@v4\n\n"
                "# Safe:\n"
                "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2"
            ),
            priority="HIGH",
        ),
    ]

    # Compute the real score so demo matches what the scorer produces
    from .permissions import score_permissions
    demo_permissions = {
        "contents": "write",
        "packages": "write",
        "id-token": "write",
        "checks": "write",
        "security-events": "write",
        "pull-requests": "write",
        "issues": "write",
        "deployments": "write",
    }
    base_score, _ = score_permissions(demo_permissions)
    # +20 for OIDC, capped at 100
    risk_score = min(100, base_score + 20)

    # Synthetic workflow YAML — references 6+ compromised packages/actions so the
    # Threat Intel section shows multiple CRITICAL/HIGH hits for the demo.
    synthetic_yaml = """name: Release and Publish
on:
  push:
    tags: ['v*']
  workflow_dispatch:

permissions:
  contents: write
  packages: write
  id-token: write
  checks: write
  security-events: write
  pull-requests: write
  issues: write
  deployments: write

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
      # caching layer — uses keyv and cacheable under the hood
      - run: npm install keyv cacheable flat-cache file-entry-cache
      # obfuscation tooling
      - run: npm install jscrambler
      # async event-driven tooling
      - run: npm install @asyncapi/generator @asyncapi/specs
      # mastra AI framework
      - run: npm install @mastra/core @mastra/memory
      - run: npm test

  release:
    needs: build-and-test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # semantic release via compromised action
      - uses: codfish/semantic-release-action@v3
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_PUBLISH_TOKEN }}

  publish-package:
    needs: release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_PUBLISH_TOKEN }}

  deploy-production:
    needs: publish-package
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
"""

    return AnalysisResult(
        owner="acme-corp [synthetic]",
        repo="api-service [synthetic]",
        run_id=9182736450,
        run_url="https://github.com/acme-corp/api-service/actions/runs/9182736450",
        workflow_name="Release and Publish [synthetic]",
        triggered_by="push (tag: v2.1.4) [synthetic]",
        run_started_at="2026-10-18T14:32:11Z",
        risk_score=risk_score,
        risk_label="CRITICAL",
        permissions_used=demo_permissions,
        permission_source="explicit",   # these permissions ARE explicitly set in this demo
        permission_findings=findings,
        exposed_secrets=secrets,
        secrets_note="",
        lateral_paths=lateral_paths,
        remediations=remediations,
        token_scopes=["repo", "workflow", "write:packages"],
        environments=["staging", "production"],
        has_id_token=True,
        repo_default_workflow_permissions="write",
        workflow_yaml_content=synthetic_yaml,
        jobs=[
            {"name": "build", "status": "completed", "conclusion": "success"},
            {"name": "test", "status": "completed", "conclusion": "success"},
            {"name": "publish-package", "status": "completed", "conclusion": "success"},
            {"name": "deploy-production", "status": "completed", "conclusion": "success"},
        ],
    )
