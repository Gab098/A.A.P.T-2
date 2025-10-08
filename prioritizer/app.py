from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any

app = FastAPI(title="AAPT Prioritizer", version="0.1.0")

class Target(BaseModel):
    host: str
    tech: List[str] = []
    ports: List[int] = []
    cve: List[str] = []
    banner: str | None = None
    metadata: Dict[str, Any] = {}

class Scored(BaseModel):
    host: str
    score: float
    label: str
    reasons: List[str]
    metadata: Dict[str, Any] = {}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/score_targets", response_model=List[Scored])
def score_targets(targets: List[Target]):
    results = []
    for t in targets:
        score = 0.0
        reasons = []
        if any("jenkins" in x.lower() for x in t.tech):
            score += 0.3
            reasons.append("tech:jenkins")
        if t.cve:
            score += 0.4
            reasons.append("cve_present")
        if any(p in [8080, 8443, 5601, 9000] for p in t.ports):
            score += 0.1
            reasons.append("interesting_port")
        if "takeover" in (t.metadata.get("signals", [])):
            score = 1.0
            reasons.append("takeover_signal")
        label = "high" if score >= 0.7 else ("medium" if score >= 0.4 else "low")
        results.append(Scored(host=t.host, score=min(score, 1.0), label=label, reasons=reasons, metadata=t.metadata))
    return results
