"""GitHub API client for ForesightOps."""

import requests
from typing import Optional


class APIError(Exception):
    """Wraps GitHub API errors with a human-readable message."""
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


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

    def _get_paginated(self, path: str, key: str, **kwargs) -> list:
        """Fetch all pages for a list endpoint."""
        results = []
        page = 1
        while True:
            params = dict(kwargs.pop("params", {}))
            params["per_page"] = 100
            params["page"] = page
            try:
                data = self._get(path, params=params, **kwargs)
                batch = data.get(key, []) if isinstance(data, dict) else data
                if not batch:
                    break
                results.extend(batch)
                page += 1
                if len(batch) < 100:
                    break
            except requests.HTTPError:
                break
        return results

    def get_repo(self, owner: str, repo: str) -> dict:
        return self._get(f"/repos/{owner}/{repo}")

    def get_workflow_run(self, owner: str, repo: str, run_id: int) -> dict:
        return self._get(f"/repos/{owner}/{repo}/actions/runs/{run_id}")

    def get_workflow_run_jobs(self, owner: str, repo: str, run_id: int) -> list:
        return self._get_paginated(f"/repos/{owner}/{repo}/actions/runs/{run_id}/jobs", "jobs")

    def get_repo_secrets(self, owner: str, repo: str) -> tuple[list, str]:
        """
        Returns (secrets_list, error_message).
        error_message is empty on success, or a human-readable note on failure.
        Fully paginated.
        """
        try:
            results = self._get_paginated(f"/repos/{owner}/{repo}/actions/secrets", "secrets")
            return results, ""
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 403:
                return [], "403 Forbidden — token lacks secrets:read or repo admin access"
            return [], f"HTTP {e.response.status_code if e.response else '?'}"

    def get_org_secrets_for_repo(self, owner: str, repo: str) -> tuple[list, str]:
        """
        Returns org secrets that are explicitly shared with this repo.
        Uses the repo-scoped org secrets endpoint, not the org-wide list.
        """
        try:
            results = self._get_paginated(
                f"/repos/{owner}/{repo}/actions/organization-secrets", "secrets"
            )
            return results, ""
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 403:
                return [], "403 Forbidden — token lacks org secrets access"
            return [], f"HTTP {e.response.status_code if e.response else '?'}"

    def get_environment_secrets(self, owner: str, repo: str, environment: str) -> tuple[list, str]:
        """Returns secrets for a specific environment. Paginated."""
        try:
            results = self._get_paginated(
                f"/repos/{owner}/{repo}/environments/{environment}/secrets", "secrets"
            )
            return results, ""
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 403:
                return [], "403 Forbidden"
            return [], f"HTTP {e.response.status_code if e.response else '?'}"

    def get_repo_environments(self, owner: str, repo: str) -> list:
        try:
            data = self._get(f"/repos/{owner}/{repo}/environments")
            return data.get("environments", [])
        except requests.HTTPError:
            return []

    def get_token_permissions(self) -> dict:
        """Probe the token's OAuth scopes via the rate-limit endpoint."""
        r = self.session.get(f"{self.BASE}/rate_limit")
        scopes = r.headers.get("X-OAuth-Scopes", "")
        return {
            "raw_scopes": scopes,
            "scopes": [s.strip() for s in scopes.split(",") if s.strip()],
        }

    def get_workflow_yaml_content(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> tuple[Optional[str], str]:
        """
        Returns (yaml_content, error_message).
        Fetches the file at the exact commit ref, not current HEAD.
        """
        try:
            import base64
            data = self._get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref})
            if isinstance(data, dict) and data.get("encoding") == "base64":
                content = data["content"].replace("\n", "")
                return base64.b64decode(content).decode("utf-8"), ""
            return None, "Unexpected content format from API"
        except requests.HTTPError as e:
            status = e.response.status_code if e.response else 0
            return None, f"Could not fetch workflow YAML (HTTP {status})"
        except Exception as e:
            return None, f"Error reading workflow YAML: {e}"

    def get_repo_default_workflow_permissions(self, owner: str, repo: str) -> Optional[str]:
        """
        Returns the repo's default workflow permission setting:
        'read' or 'write', or None if not accessible.
        This reflects whether the org/repo has opted into restricted defaults.
        """
        try:
            data = self._get(f"/repos/{owner}/{repo}/actions/permissions/workflow")
            return data.get("default_workflow_permissions")
        except requests.HTTPError:
            return None

    def list_workflows(self, owner: str, repo: str) -> list:
        try:
            data = self._get(f"/repos/{owner}/{repo}/actions/workflows")
            return data.get("workflows", [])
        except requests.HTTPError:
            return []
