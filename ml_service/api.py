"""
AAPT ML Service - FastAPI

Endpoints:
- GET  /health            -> health check
- POST /infer/group       -> finding grouping via clustering/heuristics
- POST /infer/anomaly     -> simple anomaly scoring over metrics windows

Design:
- Tries to use sentence-transformers for text embeddings; otherwise falls back to
  TF-IDF (scikit-learn). If both unavailable, uses a simple hashing embedder.
- Clustering default: DBSCAN (cosine distance) if scikit-learn available; otherwise
  degrades to a deterministic grouping based on normalized title.

This module is self-contained and safe to run even without heavy ML dependencies.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from dataclasses import dataclass
import hashlib
import math

from fastapi import FastAPI
from pydantic import BaseModel, Field

# Optional heavy deps
try:  # pragma: no cover
    import numpy as np
except Exception:  # pragma: no cover
    np = None  # type: ignore

try:  # pragma: no cover
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover
    SentenceTransformer = None  # type: ignore

try:  # pragma: no cover
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
except Exception:  # pragma: no cover
    TfidfVectorizer = DBSCAN = None  # type: ignore


app = FastAPI(title="AAPT ML Service", version="0.1.0")

# -----------------
# Data models
# -----------------
class FindingIn(BaseModel):
    finding_id: str
    title: str
    description: Optional[str] = None
    severity: Optional[str] = "info"
    source: Optional[str] = None
    asset_id: Optional[str] = None

class GroupOut(BaseModel):
    group_id: str
    score: float = Field(ge=0.0, le=1.0)

class AnomalyIn(BaseModel):
    metrics_window: Dict[str, Any]

class AnomalyOut(BaseModel):
    anomaly_score: float = Field(ge=0.0, le=1.0)


# -----------------
# Embedding utilities
# -----------------
@dataclass
class Embedder:
    st_model: Any = None
    tfidf: Any = None

    def __post_init__(self):
        if SentenceTransformer is not None:
            try:
                self.st_model = SentenceTransformer("all-MiniLM-L6-v2")
            except Exception:
                self.st_model = None
        # TF-IDF will be created on demand

    def encode(self, texts: List[str]):
        # Prefer sentence-transformers
        if self.st_model is not None:
            try:
                return self.st_model.encode(texts, convert_to_numpy=True)
            except Exception:
                pass
        # Fall back to TF-IDF
        if TfidfVectorizer is not None and np is not None:
            try:
                self.tfidf = self.tfidf or TfidfVectorizer(max_features=2048)
                mat = self.tfidf.fit_transform(texts)
                return mat.toarray()  # dense
            except Exception:
                pass
        # Last resort: simple hashing based embedding
        return [self._hash_embed(t) for t in texts]

    @staticmethod
    def _hash_embed(text: str, dims: int = 64):
        # Deterministic 64-d vector based on multiple hashes
        vec = [0.0] * dims
        tokens = (text or "").lower().split()
        for tok in tokens:
            h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
            idx = h % dims
            vec[idx] += 1.0
        # L2 normalize
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


EMBEDDER = Embedder()


# -----------------
# Health
# -----------------
@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


# -----------------
# Group inference
# -----------------
@app.post("/infer/group", response_model=List[GroupOut])
async def infer_group(findings: List[FindingIn]) -> List[GroupOut]:
    if not findings:
        return []

    texts = [f"{f.title} \n {f.description or ''}" for f in findings]
    X = EMBEDDER.encode(texts)

    groups: List[GroupOut] = []

    if DBSCAN is not None and np is not None:
        # DBSCAN with cosine similarity via metric='cosine'
        try:
            clustering = DBSCAN(eps=0.3, min_samples=2, metric="cosine").fit(np.asarray(X))
            labels = clustering.labels_.tolist()
            # Map labels to deterministic group ids; noise (-1) becomes unique ids
            for i, lbl in enumerate(labels):
                if lbl >= 0:
                    gid = f"G-{lbl}"
                    score = 0.8  # heuristic default for clustered points
                else:
                    # singleton/noise -> hash-based id
                    base = f"{findings[i].title}|{findings[i].asset_id or ''}"
                    gid = f"G-{hashlib.sha1(base.encode('utf-8')).hexdigest()[:10]}"
                    score = 0.5
                groups.append(GroupOut(group_id=gid, score=score))
            return groups
        except Exception:
            # fall through to heuristic grouping
            pass

    # Heuristic deterministic grouping: normalize titles
    for f in findings:
        base = f"{(f.title or '').strip().lower()}|{f.asset_id or ''}"
        gid = f"G-{hashlib.sha1(base.encode('utf-8')).hexdigest()[:10]}"
        groups.append(GroupOut(group_id=gid, score=0.6))

    return groups


# -----------------
# Anomaly scoring
# -----------------
@app.post("/infer/anomaly", response_model=AnomalyOut)
async def infer_anomaly(payload: AnomalyIn) -> AnomalyOut:
    # Simple heuristic anomaly score: based on count and diversity if present
    mw = payload.metrics_window or {}
    count = float(mw.get("count", 0))
    unique_assets = float(mw.get("unique_assets", 1) or 1)
    # Scale score into [0,1]
    score = 1.0 - (1.0 / (1.0 + count / max(1.0, unique_assets)))
    score = max(0.0, min(1.0, score))
    return AnomalyOut(anomaly_score=score)


# -----------------
# Dev entrypoint
# -----------------
if __name__ == "__main__":  # pragma: no cover
    try:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8088)
    except Exception:
        print("Install uvicorn to run the service: pip install uvicorn[standard]")
