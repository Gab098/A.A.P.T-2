"""
Splunk connector for AAPT ingestion pipeline using Splunk REST API.

Features:
- Creates search jobs and polls results via /services/search/jobs
- Incremental ingestion using a file-based checkpoint (last processed _time)
- Environment-based configuration
- Maps events to unified Finding schema (category=siem_alert)

Environment variables (fallbacks for constructor params):
- SPLUNK_BASE_URL      (e.g., https://splunk:8089)
- SPLUNK_USERNAME
- SPLUNK_PASSWORD
- SPLUNK_VERIFY_SSL    (0/1, default: 1)
- SPLUNK_QUERY         (e.g., index=security sourcetype=... | stats ...)
- SPLUNK_EARLIEST      (optional absolute; otherwise derived from checkpoint)
- SPLUNK_LATEST        (optional absolute; defaults to now)

Notes:
- The connector uses Splunk's REST API and basic auth. Ensure the user has
  appropriate roles to run the provided query.
"""
from __future__ import annotations

import os
import time
import base64
import json
import logging
from typing import Any, Dict, Iterator, List, Optional, Tuple
from datetime import datetime, timezone

import requests
from requests.auth import HTTPBasicAuth

from .base import BaseConnector, RateLimiter, FileCheckpointBackend
from ..core.unified_schema import (
    Finding,
    Asset,
    Severity,
    FindingCategory,
)

logger = logging.getLogger(__name__)


class SplunkRestClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({"Accept": "application/json"})

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def create_search_job(self, search: str, earliest_time: Optional[str] = None, latest_time: Optional[str] = None) -> str:
        data = {"search": f"search {search}"}
        if earliest_time:
            data["earliest_time"] = earliest_time
        if latest_time:
            data["latest_time"] = latest_time
        resp = self.session.post(self._url("/services/search/jobs"), data=data, timeout=60)
        resp.raise_for_status()
        # XML by default unless output_mode=json; use service/info to set default or parse XML
        # Safer: request JSON
        # Re-issue with output_mode=json
        resp = self.session.post(self._url("/services/search/jobs?output_mode=json"), data=data, timeout=60)
        resp.raise_for_status()
        js = resp.json()
        sid = js.get("sid") or js.get("data", {}).get("sid")
        if not sid:
            raise RuntimeError(f"Failed to get SID for search job: {js}")
        return str(sid)

    def get_job_status(self, sid: str) -> Dict[str, Any]:
        resp = self.session.get(self._url(f"/services/search/jobs/{sid}?output_mode=json"), timeout=60)
        resp.raise_for_status()
        return resp.json()

    def get_job_results(self, sid: str, count: int = 0) -> List[Dict[str, Any]]:
        # count=0 -> all results
        params = {"output_mode": "json"}
        if count:
            params["count"] = str(count)
        resp = self.session.get(self._url(f"/services/search/jobs/{sid}/results"), params=params, timeout=300)
        resp.raise_for_status()
        js = resp.json()
        # Expect structure {"results": [ {field: value, ...}, ... ]}
        return js.get("results", [])


class SplunkConnector(BaseConnector):
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        query: Optional[str] = None,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        *,
        checkpoint_backend: Optional[FileCheckpointBackend] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        super().__init__(checkpoint_backend=checkpoint_backend, rate_limiter=rate_limiter, name="Splunk")
        self.base_url = (base_url or os.getenv("SPLUNK_BASE_URL", "")).rstrip("/")
        self.username = username or os.getenv("SPLUNK_USERNAME", "")
        self.password = password or os.getenv("SPLUNK_PASSWORD", "")
        self.verify_ssl = bool(int(os.getenv("SPLUNK_VERIFY_SSL", "1"))) if verify_ssl is None else verify_ssl
        self.query = query or os.getenv("SPLUNK_QUERY", "index=_internal | head 10")
        self.earliest = earliest or os.getenv("SPLUNK_EARLIEST", "")
        self.latest = latest or os.getenv("SPLUNK_LATEST", "")

        if not self.base_url:
            raise ValueError("SplunkConnector requires base_url or SPLUNK_BASE_URL env var")
        if not self.username or not self.password:
            raise ValueError("SplunkConnector requires username/password or env vars")

        if self.rate_limiter is None:
            self.rate_limiter = RateLimiter(calls_per_second=2.5)

        self.client = SplunkRestClient(self.base_url, self.username, self.password, self.verify_ssl)

    def _compute_time_bounds(self) -> Tuple[Optional[str], Optional[str]]:
        # Prefer explicit earliest/latest
        earliest = self.earliest.strip() or None
        latest = self.latest.strip() or None
        if earliest:
            return earliest, latest
        # Otherwise use checkpoint last_time (Splunk expects absolute times like 2024-07-01T12:00:00)
        last_time = self.get_checkpoint("last_time")
        if last_time:
            # Use ISO 8601 if stored
            try:
                # validate
                _ = datetime.fromisoformat(last_time.replace("Z", "+00:00"))
                earliest = last_time
            except Exception:
                pass
        # Always set latest to now if not provided
        if not latest:
            latest = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return earliest, latest

    def fetch(self) -> Iterator[Dict[str, Any]]:
        last_time_str: Optional[str] = self.get_checkpoint("last_time")
        earliest, latest = self._compute_time_bounds()

        sid = self.client.create_search_job(self.query, earliest_time=earliest, latest_time=latest)

        # Poll until done
        while True:
            status = self.client.get_job_status(sid)
            entry = None
            if isinstance(status, dict):
                # Splunk returns {"entry": [{"content": {"isDone": true, ...}}]}
                entries = status.get("entry", [])
                if entries:
                    entry = entries[0].get("content", {})
            is_done = bool(entry.get("isDone", False)) if entry else True
            if is_done:
                break
            time.sleep(1.0)

        results = self.client.get_job_results(sid, count=0)

        max_time_seen: Optional[datetime] = None
        for item in results:
            # Some fields use "_time" (string), "host", "sourcetype", "source", raw payload often in "_raw"
            ts = item.get("_time")
            dt = None
            if ts:
                try:
                    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                except Exception:
                    dt = None
            if dt and (max_time_seen is None or dt > max_time_seen):
                max_time_seen = dt
            yield item

        # Update checkpoint to last _time processed
        if max_time_seen:
            self.set_checkpoint("last_time", max_time_seen.isoformat().replace("+00:00", "Z"))
            self.flush_checkpoint()

    def transform(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        host = str(raw.get("host") or raw.get("dest") or raw.get("src") or "unknown-host")
        sourcetype = str(raw.get("sourcetype") or raw.get("source") or "splunk_event")
        title = str(raw.get("rule") or raw.get("signature") or sourcetype)
        description = str(raw.get("_raw") or raw.get("message") or title)

        # Severity heuristics
        sev_field = str(raw.get("severity") or raw.get("risk_level") or "info").lower()
        sev_map = {
            "0": "info",
            "1": "low",
            "2": "medium",
            "3": "high",
            "4": "critical",
            "informational": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }
        sev_name = sev_map.get(sev_field, "info")

        # occurred_at
        occurred_at = None
        ts = raw.get("_time")
        if ts:
            try:
                occurred_at = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except Exception:
                occurred_at = None

        # Identity/fingerprint: prefer fields like rule/signature + host + sourcetype
        asset = Asset(asset_id=host, hostname=host)
        fingerprint = Finding.compute_fingerprint(
            source="splunk",
            source_id=str(raw.get("rule_id") or raw.get("signature_id") or ""),
            asset=asset,
            title=title,
            key_fields={"sourcetype": sourcetype},
        )

        finding_id = f"splunk:{host}:{raw.get('rule_id') or raw.get('signature_id') or sourcetype}"

        finding = Finding(
            finding_id=finding_id,
            source="splunk",
            source_id=str(raw.get("rule_id") or raw.get("signature_id") or None),
            category=FindingCategory.siem_alert,
            title=title,
            description=description,
            severity=Severity(sev_name),
            asset=asset,
            occurred_at=occurred_at,
            fingerprint=fingerprint,
            raw=raw,
        )
        return finding.dict()
