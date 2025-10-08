"""
Unified schema models for AAPT findings, assets, correlations, and ticket references.
These models provide a single source of truth to normalize data coming from
Nessus/OpenVAS, SIEM (Splunk/ELK), and other sources. They are also used by
ML services, orchestrator, and the dashboard backend for validation and IO.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import hashlib
import json

from pydantic import BaseModel, Field, validator


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingCategory(str, Enum):
    vulnerability = "vulnerability"
    siem_alert = "siem_alert"
    anomaly = "anomaly"
    misconfiguration = "misconfiguration"
    intel = "intel"
    other = "other"


class TicketSystem(str, Enum):
    jira = "jira"
    servicenow = "servicenow"
    other = "other"


class Asset(BaseModel):
    asset_id: str = Field(..., description="Canonical asset identifier in AAPT")
    hostname: Optional[str] = Field(None, description="Hostname of the asset")
    ip: Optional[str] = Field(None, description="Primary IP of the asset")
    fqdn: Optional[str] = Field(None, description="FQDN of the asset")
    tags: List[str] = Field(default_factory=list, description="Tags associated to the asset")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional asset metadata")


class TicketRef(BaseModel):
    system: TicketSystem
    ticket_id: str
    url: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Finding(BaseModel):
    """Unified Finding model used across the platform.

    Notes:
    - fingerprint should be stable across re-ingestion for idempotency.
    - correlations can store ML grouping ids, scores, and references.
    - raw should contain the original source payload (redacted as needed).
    """

    finding_id: str = Field(..., description="Internal unique ID for the finding (AAPT-generated)")
    source: str = Field(..., description="Source system (e.g., nessus, openvas, splunk, elk)")
    source_id: Optional[str] = Field(None, description="Native ID from the source, if available")

    category: FindingCategory = FindingCategory.other
    title: str
    description: Optional[str] = None

    severity: Severity = Severity.info
    cvss: Optional[float] = None
    cwe: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)

    asset: Optional[Asset] = None

    occurred_at: Optional[datetime] = Field(
        default=None, description="When the finding occurred (event time). If None, set to collected_at"
    )
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the finding was collected/ingested",
    )

    fingerprint: str = Field(..., description="Stable idempotency key for deduplication")
    status: str = Field(
        default="new",
        description="Lifecycle status: new | triaged | ticketed | resolved | closed",
    )

    correlations: Dict[str, Any] = Field(default_factory=dict, description="ML/heuristics correlation metadata")
    raw: Dict[str, Any] = Field(default_factory=dict, description="Raw source payload for traceability")

    tickets: List[TicketRef] = Field(default_factory=list, description="Associated tickets in external systems")

    @validator("occurred_at", pre=True, always=True)
    def _default_occurred_at(cls, v, values):
        # If not provided, default to collected_at
        if v is None:
            collected = values.get("collected_at")
            if isinstance(collected, datetime):
                return collected
            return datetime.now(timezone.utc)
        return v

    @staticmethod
    def compute_fingerprint(
        *,
        source: str,
        source_id: Optional[str] = None,
        asset: Optional[Asset] = None,
        title: Optional[str] = None,
        key_fields: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Compute a stable fingerprint using meaningful fields.

        The function prefers source_id if available; otherwise hashes a tuple
        of fields that define the identity of the finding (source, asset, title, etc.).
        """
        base: Dict[str, Any] = {
            "source": source,
            "source_id": source_id or "",
            "asset_id": getattr(asset, "asset_id", None),
            "hostname": getattr(asset, "hostname", None),
            "ip": getattr(asset, "ip", None),
            "title": title or "",
        }
        if key_fields:
            base.update(key_fields)
        # Sort keys to ensure stable hashing
        payload = json.dumps(base, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = [
    "Severity",
    "FindingCategory",
    "TicketSystem",
    "Asset",
    "TicketRef",
    "Finding",
]
