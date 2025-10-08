"""
AAPT Core Clients

Wrapper HTTP per servizi esterni: Prioritizer, LLM Router e altri.
"""
from __future__ import annotations

import os
import json
from typing import Dict, Any, List
import requests

from .contracts import ScoredTarget


class PrioritizerClient:
    def __init__(self, base_url: str | None = None, timeout: float = 5.0):
        self.base_url = base_url or os.getenv("PRIORITIZER_URL", "http://prioritizer:8080")
        self.timeout = timeout

    def score_targets(self, targets: List[Dict[str, Any]]) -> List[ScoredTarget]:
        url = f"{self.base_url}/score_targets"
        resp = requests.post(url, json=targets, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        result: List[ScoredTarget] = []
        for item in data:
            result.append(
                ScoredTarget(
                    host=item.get("host"),
                    score=float(item.get("score", 0.0)),
                    label=item.get("label", "low"),
                    reasons=item.get("reasons", []),
                    metadata=item.get("metadata", {}),
                )
            )
        return result


class LLMRouterClient:
    def __init__(self, base_url: str | None = None, timeout: float = 10.0):
        self.base_url = base_url or os.getenv("LLM_ROUTER_URL", "http://llm-router:8082")
        self.timeout = timeout

    def plan_next_action(self, system_state: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/plan_next_action"
        resp = requests.post(url, json={"payload": system_state}, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def deep_reason(self, system_state: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/deep_reason"
        resp = requests.post(url, json={"payload": system_state}, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()
