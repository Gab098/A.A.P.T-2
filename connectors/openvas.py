"""
OpenVAS (Greenbone) connector for AAPT ingestion pipeline.

This connector is designed to integrate with Greenbone/OpenVAS to ingest
vulnerability results and normalize them to the unified Finding schema.

Key features:
- File checkpoint for incremental processing
- Environment-based configuration
- Optional python-gvm integration (if installed)
- Dummy mode for local testing without external systems

Environment variables:
- OPENVAS_BASE_URL           (optional; for REST-like deployments)
- OPENVAS_USERNAME           (username for GMP/Greenbone)
- OPENVAS_PASSWORD           (password for GMP/Greenbone)
- OPENVAS_VERIFY_SSL         (0/1, default: 1)
- OPENVAS_DUMMY              (0/1, default: 0) -> yields mock findings for testing

Notes:
- Production-grade integration commonly uses python-gvm to speak GMP.
- If python-gvm is unavailable and OPENVAS_DUMMY!=1, fetch() will no-op but
  the module still loads safely.
"""
from __future__ import annotations

import os
import logging
from typing import Any, Dict, Iterator, Optional
from datetime import datetime, timezone

from .base import BaseConnector, RateLimiter, FileCheckpointBackend
from ..core.unified_schema import Finding, Asset, Severity, FindingCategory

logger = logging.getLogger(__name__)

# Optional dependency: python-gvm
try:  # pragma: no cover
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    GVM_AVAILABLE = True
except Exception:  # pragma: no cover
    TLSConnection = Gmp = None  # type: ignore
    GVM_AVAILABLE = False


class OpenVASConnector(BaseConnector):
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        *,
        checkpoint_backend: Optional[FileCheckpointBackend] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        super().__init__(checkpoint_backend=checkpoint_backend, rate_limiter=rate_limiter, name="OpenVAS")
        # Configuration via env vars
        self.base_url = (base_url or os.getenv("OPENVAS_BASE_URL", "")).rstrip("/")
        self.username = username or os.getenv("OPENVAS_USERNAME", "")
        self.password = password or os.getenv("OPENVAS_PASSWORD", "")
        self.verify_ssl = bool(int(os.getenv("OPENVAS_VERIFY_SSL", "1"))) if verify_ssl is None else verify_ssl
        self.dummy = bool(int(os.getenv("OPENVAS_DUMMY", "0")))

        if self.rate_limiter is None:
            self.rate_limiter = RateLimiter(calls_per_second=2.0)

        if not self.dummy and not GVM_AVAILABLE:
            logger.warning(
                "python-gvm not available. OpenVASConnector will run in no-op mode unless OPENVAS_DUMMY=1"
            )

    # -----------------
    # Fetch (incremental)
    # -----------------
    def fetch(self) -> Iterator[Dict[str, Any]]:
        """Yield raw OpenVAS result items.

        If OPENVAS_DUMMY=1 -> produce a small set of mock findings.
        Otherwise, attempts a minimal GMP session if python-gvm is available;
        currently implemented as a placeholder to be expanded.
        """
        last_seen: int = int(self.get_checkpoint("last_seen", 0) or 0)
        max_seen: int = last_seen

        if self.dummy:
            # Produce 2 mock vulnerabilities with incremental timestamps
            import time
            now = int(time.time())
            samples = [
                {
                    "result": {
                        "name": "OpenVAS Test Vulnerability A",
                        "host": "10.0.0.5",
                        "threat": "High",
                        "nvt": {
                            "oid": "1.3.6.1.4.1.25623.1.0.103674",
                            "cvss_base": "7.5",
                            "cve": "CVE-2021-1234",
                        },
                        "creation_time": now - 60,
                        "description": "Test issue A from dummy mode",
                    }
                },
                {
                    "result": {
                        "name": "OpenVAS Test Vulnerability B",
                        "host": "10.0.0.6",
                        "threat": "Medium",
                        "nvt": {
                            "oid": "1.3.6.1.4.1.25623.1.0.105678",
                            "cvss_base": "5.0",
                            "cve": "CVE-2022-5678",
                        },
                        "creation_time": now,
                        "description": "Test issue B from dummy mode",
                    }
                },
            ]
            for item in samples:
                ts = int(item["result"].get("creation_time", now))
                if last_seen and ts <= last_seen:
                    continue
                if ts > max_seen:
                    max_seen = ts
                yield item
        else:
            if not GVM_AVAILABLE:
                logger.info("OpenVASConnector in no-op mode (no python-gvm and dummy disabled)")
                return
            # Placeholder for GMP calls (list results since last_seen). To be expanded.
            # Example outline:
            # conn = TLSConnection(hostname="openvas-host", port=9390)
            # with Gmp(conn) as gmp:
            #     gmp.authenticate(self.username, self.password)
            #     # Query results filtered by time
            #     # Iterate and yield raw dicts
            logger.info("OpenVASConnector GMP integration not implemented yet; yielding no items")

        if max_seen > last_seen:
            self.set_checkpoint("last_seen", max_seen)
            self.flush_checkpoint()

    # -----------------
    # Transform
    # -----------------
    def transform(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        result = raw.get("result", {})
        name = result.get("name", "OpenVAS Finding")
        threat = str(result.get("threat", "Low")).lower()
        host = str(result.get("host") or result.get("ip") or "unknown")
        nvt = result.get("nvt", {})
        oid = str(nvt.get("oid") or "")
        cvss = None
        try:
            cvss = float(nvt.get("cvss_base")) if nvt.get("cvss_base") else None
        except Exception:
            cvss = None

        severity_map = {
            "log": "info",
            "debug": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }
        sev_name = severity_map.get(threat, "low")

        # occurred_at
        occurred_at = None
        ts = result.get("creation_time")
        if ts:
            try:
                occurred_at = datetime.fromtimestamp(int(ts), tz=timezone.utc)
            except Exception:
                occurred_at = None

        asset = Asset(asset_id=host, ip=host if host.count(".") == 3 else None)
        fingerprint = Finding.compute_fingerprint(
            source="openvas", source_id=oid or None, asset=asset, title=name
        )

        finding_id = f"openvas:{host}:{oid or 'nvt'}"

        finding = Finding(
            finding_id=finding_id,
            source="openvas",
            source_id=oid or None,
            category=FindingCategory.vulnerability,
            title=name,
            description=result.get("description"),
            severity=Severity(sev_name),
            cvss=cvss,
            asset=asset,
            occurred_at=occurred_at,
            fingerprint=fingerprint,
            raw=raw,
        )
        return finding.dict()
