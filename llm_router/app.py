from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any

# Placeholder: in futuro caricare modelli via llama_cpp.Llama
# e aggiungere routing planner/thinker

app = FastAPI(title="AAPT LLM Router", version="0.1.0")

class SystemState(BaseModel):
    payload: Dict[str, Any]

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/plan_next_action")
def plan_next_action(state: SystemState):
    # Stub: ritorno wait con confidenza alta, da sostituire con modello planner
    return {"action": "wait", "priority": "low", "confidence": 0.9, "route": "planner"}

@app.post("/deep_reason")
def deep_reason(state: SystemState):
    # Stub: ritorno nuclei_scan con confidenza media, da sostituire con modello thinker
    return {"action": "nuclei_scan", "target": "http://example.com", "priority": "high", "confidence": 0.7, "route": "thinker"}
