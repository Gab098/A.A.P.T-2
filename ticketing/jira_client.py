"""
Jira client wrapper providing idempotent create/update operations for AAPT.

Environment variables (fallbacks):
- JIRA_URL
- JIRA_USER
- JIRA_TOKEN
- JIRA_PROJECT_KEY

Notes:
- Uses issue summary normalization and fingerprint-based lookup to avoid duplicates.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from jira import JIRA  # type: ignore


class JiraClient:
    def __init__(
        self,
        url: Optional[str] = None,
        user: Optional[str] = None,
        token: Optional[str] = None,
        project_key: Optional[str] = None,
    ) -> None:
        self.url = url or os.getenv("JIRA_URL", "")
        self.user = user or os.getenv("JIRA_USER", "")
        self.token = token or os.getenv("JIRA_TOKEN", "")
        self.project_key = project_key or os.getenv("JIRA_PROJECT_KEY", "")
        if not all([self.url, self.user, self.token, self.project_key]):
            raise ValueError("JiraClient requires URL, USER, TOKEN, and PROJECT_KEY")
        self.client = JIRA(self.url, basic_auth=(self.user, self.token))

    def _find_issue_by_fingerprint(self, fingerprint: str) -> Optional[str]:
        jql = f'project = "{self.project_key}" AND text ~ "{fingerprint}" ORDER BY created DESC'
        issues = self.client.search_issues(jql, maxResults=1)
        if issues:
            return issues[0].key
        return None

    def create_or_update_issue(self, fingerprint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        existing = self._find_issue_by_fingerprint(fingerprint)
        if existing:
            issue = self.client.issue(existing)
            fields = {}
            if payload.get("summary"):
                fields["summary"] = payload["summary"]
            if payload.get("description"):
                fields["description"] = payload["description"]
            if fields:
                issue.update(fields={"summary": fields.get("summary", issue.fields.summary),
                                     "description": fields.get("description", issue.fields.description)})
            return {"action": "updated", "issue_key": issue.key, "url": f"{self.url}/browse/{issue.key}"}
        # create new
        issue_dict = {
            "project": {"key": self.project_key},
            "summary": payload.get("summary", f"AAPT Finding {fingerprint[:8]}"),
            "description": payload.get("description", f"Auto-created by AAPT for {fingerprint}"),
            "issuetype": {"name": payload.get("issuetype", "Task")},
        }
        issue = self.client.create_issue(fields=issue_dict)
        return {"action": "created", "issue_key": issue.key, "url": f"{self.url}/browse/{issue.key}"}
