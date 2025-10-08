"""
Elasticsearch (ELK) connector for AAPT ingestion pipeline.

Features:
- Incremental ingestion using search_after on a time+_id sort
- Environment-based configuration
- Maps events to unified Finding schema (category=siem_alert)

Environment variables:
- ELASTICSEARCH_HOSTS   (comma-separated, e.g., https://es:9200)
- ELASTICSEARCH_USERNAME
- ELASTICSEARCH_PASSWORD
- ELASTICSEARCH_VERIFY_SSL (0/1, default: 1)
- ELASTICSEARCH_INDEX   (e.g., security-*)
- ELASTICSEARCH_QUERY   (Lucene/DSL subset as JSON string or empty for match_all)
"""
from __future__ import annotations

import os
import json
import logging
from typing import Any, Dict, Iterator, List, Optional, Tuple
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

from .base import BaseConnector, RateLimiter, FileCheckpointBackend
from ..core.unified_schema import (
    Finding,
    Asset,
    Severity,
    FindingCategory,
)

logger = logging.getLogger(__name__)


class ELKConnector(BaseConnector):
    def __init__(
        self,
        hosts: Optional[List[str]] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        index: Optional[str] = None,
        query: Optional[Dict[str, Any]] = None,
        *,
        checkpoint_backend: Optional[FileCheckpointBackend] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        super().__init__(checkpoint_backend=checkpoint_backend, rate_limiter=rate_limiter, name="ELK")
        hosts_env = os.getenv("ELASTICSEARCH_HOSTS", "")
        self.hosts = hosts or ([h.strip() for h in hosts_env.split(",") if h.strip()] or ["http://localhost:9200"])
        self.username = username or os.getenv("ELASTICSEARCH_USERNAME", "")
        self.password = password or os.getenv("ELASTICSEARCH_PASSWORD", "")
        self.verify_ssl = bool(int(os.getenv("ELASTICSEARCH_VERIFY_SSL", "1"))) if verify_ssl is None else verify_ssl
        self.index = index or os.getenv("ELASTICSEARCH_INDEX", "*")
        self.query = query or self._parse_query(os.getenv("ELASTICSEARCH_QUERY", ""))

        if self.rate_limiter is None:
            self.rate_limiter = RateLimiter(calls_per_second=5.0)

        self.client = Elasticsearch(
            self.hosts,
            basic_auth=(self.username, self.password) if self.username and self.password else None,
            verify_certs=self.verify_ssl,
        )

    def _parse_query(self, q: str) -> Dict[str, Any]:
        if not q:
            return {"match_all": {}}
        try:
            return json.loads(q)
        except Exception:
            # fallback minimal match query on a string
            return {"query_string": {"query": q}}

    def fetch(self) -> Iterator[Dict[str, Any]]:
        # Use checkpoint: last_sort (list) for search_after; or last_time
        last_sort = self.get_checkpoint("last_sort")
        body = {
            "size": 500,
            "sort": [
                {"@timestamp": "asc"},
                {"_id": "asc"},
            ],
            "query": self.query or {"match_all": {}},
        }
        if last_sort:
            body["search_after"] = last_sort

        while True:
            res = self.client.search(index=self.index, body=body)
            hits = res.get("hits", {}).get("hits", [])
            if not hits:
                break
            for h in hits:
                yield h
            last = hits[-1]
            last_sort = last.get("sort")
            body["search_after"] = last_sort
            self.set_checkpoint("last_sort", last_sort)

        self.flush_checkpoint()

    def transform(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        src = raw.get("_source", {})
        host = str(src.get("host", {}).get("name") or src.get("host") or src.get("destination") or "unknown-host")
        title = str(src.get("event", {}).get("module") or src.get("rule", {}).get("name") or src.get("log", {}).get("logger") or "ELK Event")
        description = str(src.get("message") or json.dumps(src)[:1024])

        sev = str(src.get("event", {}).get("severity") or src.get("log", {}).get("level") or "info").lower()
        sev_map = {
            "emergency": "critical", "alert": "critical", "critical": "critical",
            "error": "high", "err": "high",
            "warning": "medium", "warn": "medium",
            "notice": "low",
            "info": "info", "informational": "info",
            "debug": "info",
        }
        sev_name = sev_map.get(sev, "info")

        occurred_at = None
        ts = src.get("@timestamp") or src.get("event", {}).get("created")
        if ts:
            try:
                occurred_at = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except Exception:
                occurred_at = None

        asset = Asset(asset_id=host, hostname=host)
        fingerprint = Finding.compute_fingerprint(
            source="elk",
            source_id=str(raw.get("_id") or ""),
            asset=asset,
            title=title,
            key_fields={"index": raw.get("_index")},
        )

        finding_id = f"elk:{raw.get('_index')}:{raw.get('_id')}"

        finding = Finding(
            finding_id=finding_id,
            source="elk",
            source_id=str(raw.get("_id") or None),
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
