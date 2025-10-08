"""
Nessus connector for AAPT ingestion pipeline.

This connector fetches scans and vulnerabilities from a Nessus-compatible API
(Tenable.io/Tenable.sc) and maps them to the unified Finding schema.

Notes:
- This is a pragmatic implementation using the REST endpoints /scans and /scans/{id}.
  For production-grade export of findings, consider the bulk export APIs.
- Uses a file-based checkpoint for incremental retrieval.
- Requires the `requests` library.

Environment variables (fallbacks for constructor params):
- NESSUS_API_URL (e.g., https://cloud.tenable.com)
- NESSUS_API_KEY (e.g., "accessKey=...;secretKey=...")
- NESSUS_VERIFY_SSL (default: true)
"""
from __future__ import annotations

import os
import logging
from typing import Any, Dict, Iterator, List, Optional
from datetime import datetime, timezone

import requests

from .base import BaseConnector, RateLimiter, FileCheckpointBackend
from ..core.unified_schema import (
    Finding,
    Asset,
    Severity,
    FindingCategory,
)

logger = logging.getLogger(__name__)


class NessusConnector(BaseConnector):
    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        *,
        checkpoint_backend: Optional[FileCheckpointBackend] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        super().__init__(checkpoint_backend=checkpoint_backend, rate_limiter=rate_limiter, name="Nessus")
        self.api_url = (api_url or os.getenv("NESSUS_API_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("NESSUS_API_KEY", "")
        self.verify_ssl = (
            bool(int(os.getenv("NESSUS_VERIFY_SSL", "1"))) if verify_ssl is None else verify_ssl
        )

        if not self.api_url:
            raise ValueError("NessusConnector requires api_url or NESSUS_API_URL env var")
        if not self.api_key:
            raise ValueError("NessusConnector requires api_key or NESSUS_API_KEY env var")

        # Default modest rate limit to be gentle with API
        if self.rate_limiter is None:
            self.rate_limiter = RateLimiter(calls_per_second=3.0)

    # -------------
    # HTTP helpers
    # -------------
    def _headers(self) -> Dict[str, str]:
        # Tenable.io uses X-ApiKeys: accessKey=...; secretKey=...
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": self.api_key,
        }

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.api_url}{path}"
        resp = requests.get(url, headers=self._headers(), params=params, verify=self.verify_ssl, timeout=60)
        resp.raise_for_status()
        return resp.json()  # type: ignore[return-value]

    # -------------
    # Fetch logic
    # -------------
    def fetch(self) -> Iterator[Dict[str, Any]]:
        """Iterate raw vulnerability items incrementally based on checkpoint.

        The checkpoint key `last_seen` stores the last timestamp processed (epoch seconds).
        """
        last_seen: int = int(self.get_checkpoint("last_seen", 0) or 0)

        scans = self._list_scans()
        max_seen = last_seen

        for scan in scans:
            scan_id = scan.get("id")
            if scan_id is None:
                continue
            try:
                for vul in self._iter_scan_vulnerabilities(scan_id):
                    # Filter incrementally if possible
                    ts = int(vul.get("last_found") or vul.get("last_seen") or 0)
                    if last_seen and ts and ts <= last_seen:
                        continue
                    if ts and ts > max_seen:
                        max_seen = ts
                    yield {
                        "scan": scan,
                        "vulnerability": vul,
                    }
            except Exception as e:
                logger.exception("Failed to iterate vulnerabilities for scan %s: %s", scan_id, e)

        if max_seen > last_seen:
            self.set_checkpoint("last_seen", max_seen)
            self.flush_checkpoint()

    def _list_scans(self) -> List[Dict[str, Any]]:
        try:
            data = self._get("/scans")
            # Tenable.io returns {"scans": [...]} structure
            scans = data.get("scans", [])
            return scans
        except Exception as e:
            logger.exception("Failed to list scans: %s", e)
            return []

    def _iter_scan_vulnerabilities(self, scan_id: int) -> Iterator[Dict[str, Any]]:
        """Yield vulnerability entries from a scan.

        Note: For production use, prefer export APIs to retrieve full findings
        with evidence. This method provides a quick incremental approach when
        vulnerability summaries are sufficient.
        """
        try:
            data = self._get(f"/scans/{scan_id}")
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                yield item
        except Exception as e:
            logger.exception("Failed to fetch scan %s details: %s", scan_id, e)
            return

    # ---------------
    # Transformation
    # ---------------
    def transform(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        scan = raw.get("scan", {})
        vul = raw.get("vulnerability", {})

        # Build asset
        host = scan.get("name") or scan.get("uuid") or "unknown-host"
        asset = Asset(asset_id=str(host), hostname=str(host))

        # Extract fields
        plugin_id = str(vul.get("plugin_id") or vul.get("pluginID") or "")
        plugin_name = vul.get("plugin_name") or vul.get("pluginName") or "Nessus Finding"
        severity_num = int(vul.get("severity") or 0)

        # Map severity number to enum names if necessary
        sev_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        severity_name = sev_map.get(severity_num, "low")

        # Timestamps
        last_found = vul.get("last_found") or vul.get("lastSeen")
        occurred_at = None
        if last_found:
            try:
                occurred_at = datetime.fromtimestamp(int(last_found), tz=timezone.utc)
            except Exception:
                occurred_at = None

        # Fingerprint stable across re-ingestion
        fingerprint = Finding.compute_fingerprint(
            source="nessus", source_id=plugin_id, asset=asset, title=str(plugin_name)
        )

        finding_id = f"nessus:{scan.get('id')}:{plugin_id}" if plugin_id else f"nessus:{scan.get('id')}:plugin"

        finding = Finding(
            finding_id=finding_id,
            source="nessus",
            source_id=plugin_id or None,
            category=FindingCategory.vulnerability,
            title=str(plugin_name),
            description=vul.get("description"),
            severity=Severity(severity_name),
            cvss=(float(vul.get("cvss3_base_score")) if vul.get("cvss3_base_score") else None),
            asset=asset,
            occurred_at=occurred_at,
            fingerprint=fingerprint,
            raw={"scan": scan, "vulnerability": vul},
        )

        return finding.dict()  # Return as dict for downstream serialization
