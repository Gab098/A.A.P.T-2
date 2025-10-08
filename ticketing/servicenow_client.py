"""
ServiceNow client wrapper for AAPT with idempotent create/update operations.

Environment variables:
- SN_URL
- SN_USER
- SN_PASSWORD (or SN_TOKEN if using token-based auth)
- SN_TABLE (default: incident)

Notes:
- Uses a fingerprint search to avoid duplicates.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import requests


class ServiceNowClient:
    def __init__(
        self,
        url: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        table: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ) -> None:
        self.url = (url or os.getenv("SN_URL", "")).rstrip("/")
        self.user = user or os.getenv("SN_USER", "")
        self.password = password or os.getenv("SN_PASSWORD", "")
        self.table = table or os.getenv("SN_TABLE", "incident")
        self.verify_ssl = bool(int(os.getenv("SN_VERIFY_SSL", "1"))) if verify_ssl is None else verify_ssl
        if not all([self.url, self.user, self.password, self.table]):
            raise ValueError("ServiceNowClient requires URL, USER, PASSWORD, and TABLE")

    def _api(self, path: str) -> str:
        return f"{self.url}/api/now/table/{path}"

    def _headers(self) -> Dict[str, str]:
        return {"Accept": "application/json", "Content-Type": "application/json"}

    def _find_by_fingerprint(self, fingerprint: str) -> Optional[str]:
        params = {"sysparm_query": f"short_descriptionLIKE{fingerprint}", "sysparm_limit": "1"}
        resp = requests.get(self._api(self.table), auth=(self.user, self.password), headers=self._headers(), params=params, verify=self.verify_ssl, timeout=60)
        resp.raise_for_status()
        js = resp.json()
        result = js.get("result", [])
        if result:
            return result[0].get("sys_id")
        return None

    def create_or_update_ticket(self, fingerprint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        existing = self._find_by_fingerprint(fingerprint)
        if existing:
            data = {k: v for k, v in payload.items() if k in {"short_description", "description", "priority"}}
            resp = requests.patch(self._api(f"{self.table}/{existing}"), auth=(self.user, self.password), headers=self._headers(), json=data, verify=self.verify_ssl, timeout=60)
            resp.raise_for_status()
            return {"action": "updated", "sys_id": existing, "url": f"{self.url}/nav_to.do?uri={self.table}.do?sys_id={existing}"}
        data = {
            "short_description": payload.get("short_description", f"AAPT Finding {fingerprint[:8]}"),
            "description": payload.get("description", f"Auto-created by AAPT for {fingerprint}"),
            "priority": payload.get("priority", "3"),
        }
        resp = requests.post(self._api(self.table), auth=(self.user, self.password), headers=self._headers(), json=data, verify=self.verify_ssl, timeout=60)
        resp.raise_for_status()
        js = resp.json()
        sys_id = js.get("result", {}).get("sys_id")
        return {"action": "created", "sys_id": sys_id, "url": f"{self.url}/nav_to.do?uri={self.table}.do?sys_id={sys_id}"}
