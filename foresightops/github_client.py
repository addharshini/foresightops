"""GitHub API client for ForesightOps."""

import requests
from typing import Optional


class GitHubClient:
    BASE = "https://api.github.com"

    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _get(self, path: str, **kwargs) -> dict | list:
        r = self.session.get(f"{self.BASE}{path}", **kwargs)
        r.raise_for_status()
        return r.json()

    def get_repo(self, owner: str, repo: str) -> dict:
        return self._get(f"/repos/{owner}/{repo}")

    def get_workflow_run(self, owner: str, repo: str, run_id: int) -> dict:
        return self._get(f"/repos/{owner}/{repo}/actions/runs/{run_id}")

    def get_workflow_file(self, owner: str, repo: str, workflow_id: int) -> dict:
        return self._get(f"/repos/{owner}/{repo}/actions/workflows/{workflow_id}")

    def get_workflow_run_jobs(self, owner: str, repo: str, run_id: int) -> list:
        data = self._get(f"/repos/{owner}/{repo}/actions/runs/{run_id}/jobs")
        return data.get("jobs", [])

    def get_repo_secrets(self, owner: str, repo: str) -> list:
        try:
            data = self._get(f"/repos/{owner}/{repo}/actions/secrets")
            return data.get("secrets", [])
        except requests.HTTPError:
            return []

    def get_org_secrets(self, org: str) -> list:
        try:
            data = self._get(f"/orgs/{org}/actions/secrets")
            return data.get("secrets", [])
        except requests.HTTPError:
            return []

    def get_repo_environments(self, owner: str, repo: str) -> list:
        try:
            data = self._get(f"/repos/{owner}/{repo}/environments")
            return data.get("environments", [])
        except requests.HTTPError:
            return []

    def get_repo_collaborators(self, owner: str, repo: str) -> list:
        try:
            return self._get(f"/repos/{owner}/{repo}/collaborators")
        except requests.HTTPError:
            return []

    def list_org_repos(self, org: str) -> list:
        try:
            repos = []
            page = 1
            while True:
                batch = self._get(f"/orgs/{org}/repos", params={"per_page": 100, "page": page})
                if not batch:
                    break
                repos.extend(batch)
                page += 1
                if len(batch) < 100:
                    break
            return repos
        except requests.HTTPError:
            return []

    def get_token_permissions(self) -> dict:
        """Probe what the token can actually do via the rate-limit endpoint."""
        r = self.session.get(f"{self.BASE}/rate_limit")
        scopes = r.headers.get("X-OAuth-Scopes", "")
        return {
            "raw_scopes": scopes,
            "scopes": [s.strip() for s in scopes.split(",") if s.strip()],
        }

    def get_workflow_yaml_content(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> Optional[str]:
        """Fetch the raw workflow YAML."""
        try:
            import base64
            data = self._get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref})
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode()
            return data.get("content")
        except Exception:
            return None

    def list_workflows(self, owner: str, repo: str) -> list:
        try:
            data = self._get(f"/repos/{owner}/{repo}/actions/workflows")
            return data.get("workflows", [])
        except requests.HTTPError:
            return []
