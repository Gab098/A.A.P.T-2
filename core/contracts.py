"""
AAPT Core Contracts

Scopo:
- Definire contratti (interfacce) comuni per servizi e adapter dell'ecosistema AAPT.
- Abilitare modularità per Prioritizer, LLM Router, Net-Gateway e Policy.

Compatibilità: Python 3.10+
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable, Dict, Any, List, Optional, TypedDict, Literal
from dataclasses import dataclass


# ==========================
#  Messaggi e Tipi Comuni
# ==========================

SchemaStatus = Literal["success", "failure", "partial"]
Priority = Literal["high", "medium", "low"]


class TaskMessage(TypedDict, total=False):
    task_id: str
    correlation_id: str
    target: str
    timestamp: str
    attempt: int
    # payload generico per task specifici
    payload: Dict[str, Any]


class ResultMessage(TypedDict, total=False):
    schema_version: str
    producer_version: str
    task_id: str
    correlation_id: str
    attempt: int
    worker_type: str
    target: str
    status: SchemaStatus
    timestamp: str
    summary: str
    data: Dict[str, Any]
    raw_output_path: Optional[str]
    # Estensioni opzionali (v1.2+)
    message_type: Optional[str]
    media: Optional[Dict[str, Any]]
    reason_codes: Optional[List[str]]


@dataclass
class ScoredTarget:
    host: str
    score: float  # 0..1
    label: Priority
    reasons: List[str]
    metadata: Dict[str, Any]


# ==========================
#  Interfacce (Protocol)
# ==========================

@runtime_checkable
class Prioritizer(Protocol):
    """Servizio di scoring target ibrido (neurale + regole)."""

    def score_targets(self, targets: List[Dict[str, Any]]) -> List[ScoredTarget]:
        """
        Restituisce una lista di ScoredTarget ordinabili per score.
        targets: lista di dict con features (tech, ports, cve, banner, signals, ecc.).
        """
        ...


@runtime_checkable
class LLMRouter(Protocol):
    """Router LLM: smista tra Planner (veloce) e Thinker (profondo)."""

    def plan_next_action(self, system_state: Dict[str, Any]) -> Dict[str, Any]:
        """Pianificazione rapida: output JSON con action, target, priority, confidence, route."""
        ...

    def deep_reason(self, system_state: Dict[str, Any]) -> Dict[str, Any]:
        """Ragionamento profondo: usato se confidenza bassa o contesto complesso."""
        ...


@runtime_checkable
class NetClient(Protocol):
    """Client astratto per invio richieste HTTP(S) tramite Net-Gateway."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[bytes | str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Esegue una richiesta via Net-Gateway e restituisce un dict contenente:
        {
          "status_code": int,
          "headers": Dict[str, str],
          "body": str | bytes | None,
          "error": Optional[str]
        }
        """
        ...


@runtime_checkable
class Policy(Protocol):
    """Policy engine generico (evaluation di contesto/policy)."""

    def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Restituisce decisioni/flags in base al contesto (es. VM_MODE, allowlists)."""
        ...


# ==========================
#  Costanti comuni
# ==========================

SCHEMA_VERSION_CURRENT = "1.2"
PRODUCER_VERSION_DEFAULT = "0.3.0"
