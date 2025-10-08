"""
Base connector interfaces and utilities for AAPT ingestion pipeline.

This module defines:
- BaseConnector: Abstract interface for all connectors (Nessus, OpenVAS, Splunk, ELK, ...)
- CheckpointBackend + FileCheckpointBackend: Persisted state for idempotent incremental fetch
- RateLimiter: Simple client-side rate limiter to avoid overloading external APIs

Connectors should:
1) Implement fetch() to retrieve raw events/documents (using checkpoint state)
2) Implement transform() to map raw payloads to unified_schema.Finding dicts
3) Use checkpoint backend to persist progress (e.g., last timestamp/cursor)
"""
from __future__ import annotations

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, Optional

from datetime import datetime, timezone

# Unified schema utilities can be used by concrete connectors
try:
    from ..core.unified_schema import Finding, Asset, Severity, FindingCategory
except Exception:  # pragma: no cover - allow import even if not installed yet
    Finding = Asset = Severity = FindingCategory = object  # type: ignore

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple token-bucket-like limiter based on sleep between calls."""

    def __init__(self, calls_per_second: float = 5.0):
        self.interval = 1.0 / max(0.001, calls_per_second)
        self._last = 0.0

    def wait(self) -> None:
        now = time.time()
        delta = now - self._last
        if delta < self.interval:
            time.sleep(self.interval - delta)
        self._last = time.time()


class CheckpointBackend(ABC):
    @abstractmethod
    def load_state(self) -> Dict[str, Any]:
        ...

    @abstractmethod
    def save_state(self, state: Dict[str, Any]) -> None:
        ...

    def get(self, key: str, default: Any = None) -> Any:
        state = self.load_state()
        return state.get(key, default)

    def set(self, key: str, value: Any) -> None:
        state = self.load_state()
        state[key] = value
        self.save_state(state)


class FileCheckpointBackend(CheckpointBackend):
    """Persist checkpoint state in a local JSON file.

    Not suitable for distributed scaling by itself; for multi-instance
    deployments, replace with a shared store (DB/Redis/Blob).
    """

    def __init__(self, path: str, autosave_every: int = 50):
        self.path = path
        self.autosave_every = max(1, autosave_every)
        self._state_cache: Dict[str, Any] = {}
        self._counter = 0
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._state_cache = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load checkpoint file %s: %s", self.path, e)
                self._state_cache = {}
        else:
            self._state_cache = {}

    def load_state(self) -> Dict[str, Any]:
        return dict(self._state_cache)

    def save_state(self, state: Dict[str, Any]) -> None:
        self._state_cache = dict(state)
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._state_cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("Failed to save checkpoint to %s: %s", self.path, e)

    def set(self, key: str, value: Any) -> None:
        self._state_cache[key] = value
        self._counter += 1
        if self._counter % self.autosave_every == 0:
            self.save_state(self._state_cache)


class BaseConnector(ABC):
    """Abstract base class for ingestion connectors.

    Implementations must override fetch() and transform(). The run() helper
    yields transformed documents and applies optional rate limiting.
    """

    def __init__(
        self,
        *,
        checkpoint_backend: Optional[CheckpointBackend] = None,
        rate_limiter: Optional[RateLimiter] = None,
        name: Optional[str] = None,
    ) -> None:
        self.name = name or self.__class__.__name__
        # Default checkpoint file placed in cwd; override in production
        default_path = f".aapt_{self.name.lower()}_checkpoint.json"
        self.checkpoint = checkpoint_backend or FileCheckpointBackend(default_path)
        self.rate_limiter = rate_limiter

    @abstractmethod
    def fetch(self) -> Iterator[Dict[str, Any]]:
        """Yield raw documents from the source system.

        Implement incremental retrieval using self.checkpoint to store
        cursors (e.g., last timestamp, last id).
        """
        ...

    @abstractmethod
    def transform(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Map raw document into unified Finding dict.

        Should validate minimally and ensure presence of key fields such as
        finding_id, source, severity, title, fingerprint.
        """
        ...

    def run(self) -> Iterator[Dict[str, Any]]:
        """High-level generator that applies rate limiting and error handling."""
        for raw in self.fetch():
            if self.rate_limiter is not None:
                self.rate_limiter.wait()
            try:
                doc = self.transform(raw)
                yield doc
            except Exception as e:
                logger.exception("%s transform failed: %s", self.name, e)

    # Convenience helpers for timestamp handling
    @staticmethod
    def now_utc() -> datetime:
        return datetime.now(timezone.utc)

    def get_checkpoint(self, key: str, default: Any = None) -> Any:
        return self.checkpoint.get(key, default)

    def set_checkpoint(self, key: str, value: Any) -> None:
        self.checkpoint.set(key, value)

    def flush_checkpoint(self) -> None:
        state = self.checkpoint.load_state()
        self.checkpoint.save_state(state)
