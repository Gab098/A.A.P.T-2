import logging
import json
import os
import sys
from typing import Dict, Any, Optional

# Abilita import dei moduli core (clients) dalla cartella superiore
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from core.clients import LLMRouterClient  # type: ignore


class LLMPlanner:
    """
    LLM Planner rifattorizzato per utilizzare il servizio LLM Router
    invece del caricamento del modello locale. Il Router seleziona tra
    Planner (piccolo, rapido) e Thinker (più grande, profondo).
    """

    def __init__(
        self,
        router_url: Optional[str] = None,
        confidence_threshold: float = 0.6,
        history_file: str = "llm_history.json",
    ):
        self.logger = logging.getLogger(__name__)
        self.router_url = router_url or os.getenv("LLM_ROUTER_URL", "http://llm-router:8082")
        self.router = LLMRouterClient(base_url=self.router_url)
        self.confidence_threshold = confidence_threshold
        self.history_file = history_file
        self.history = self._load_history()

    # ==========================
    #  History utils ( opzionali )
    # ==========================
    def _load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Errore nel caricamento della cronologia LLM: {e}")
        return []

    def _save_history(self):
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.logger.error(f"Errore nel salvataggio della cronologia LLM: {e}")

    # ==========================
    #  Pianificazione
    # ==========================
    def plan_next_action(self, system_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Richiede al LLM Router la prossima azione. Se la confidenza è bassa,
        esegue un deep_reason per maggiore accuratezza.
        """
        try:
            # Manteniamo una history minimale per audit (non necessaria al router)
            self.history.append({"role": "user", "content": {"type": "system_state", "data": system_state}})

            resp = self.router.plan_next_action(system_state)
            self.logger.info(f"Router plan_next_action -> {resp}")

            confidence = float(resp.get("confidence", 1.0))
            if confidence < self.confidence_threshold:
                self.logger.info(f"Confidenza bassa ({confidence}), eseguo deep_reason")
                # Arricchisco lo stato con un hint di routing
                deep_payload = {
                    "mode": "plan",
                    "system_state": system_state,
                    "prev": resp,
                }
                resp = self.router.deep_reason(deep_payload)
                self.logger.info(f"Router deep_reason(plan) -> {resp}")

            # Normalizza il piano in un dict previsto dall'orchestrator
            plan = {
                "action": resp.get("action", "wait"),
                "target": resp.get("target"),
                "reasoning": resp.get("reasoning", "LLM Router decision"),
                "priority": resp.get("priority", "low"),
                "parameters": resp.get("parameters", {}),
                "confidence": float(resp.get("confidence", 1.0)),
                "route": resp.get("route", "planner"),
                # Nuovi campi per exploit chain
                "exploit_module": resp.get("exploit_module"),
                "payload": resp.get("payload"),
                "lhost": resp.get("lhost"),
                "lport": resp.get("lport"),
                "vulnerability_details": resp.get("vulnerability_details"), # Details of the vulnerability to exploit
                "target_details": resp.get("target_details") # Full target context for exploit
            }

            self.history.append({"role": "assistant", "content": {"type": "plan", "data": plan}})
            self._save_history()
            return plan

        except Exception as e:
            self.logger.error(f"Errore nella pianificazione tramite LLM Router: {e}")
            self._save_history()
            return {"action": "wait", "reasoning": f"Errore router: {e}", "priority": "low"}

    # ==========================
    #  Analisi risultati
    # ==========================
    def analyze_results(self, target_details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Richiede un'analisi dei risultati al LLM Router (modalità deep_reason).
        """
        try:
            payload = {
                "mode": "analyze",
                "target_details": target_details,
            }
            resp = self.router.deep_reason(payload)
            self.logger.info(f"Router deep_reason(analyze) -> {resp}")

            # Normalizzazione output analisi
            analysis = {
                "recommendations": resp.get("recommendations", []),
                "summary": resp.get("summary", resp.get("reasoning", "Analisi LLM Router")),
                "confidence": resp.get("confidence", 0.7),
            }
            return analysis
        except Exception as e:
            self.logger.error(f"Errore nell'analisi tramite LLM Router: {e}")
            return {"recommendations": [], "summary": f"Errore: {str(e)}"}

    def close(self):
        # Nessuna risorsa da rilasciare: client HTTP stateless
        return
