from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
import requests
import os

app = FastAPI(title="AAPT Net-Gateway", version="0.1.0")

INTERNET_ACCESS = os.getenv("INTERNET_ACCESS", "disabled").lower()
VM_MODE = os.getenv("VM_MODE", "false").lower() == "true"

# Whitelist domini/hosts (semplice, in futuro da ConfigMap)
ALLOWED_HOSTS = set((os.getenv("ALLOWED_HOSTS", "").split(",") if os.getenv("ALLOWED_HOSTS") else []))

class HttpRequest(BaseModel):
    method: str
    url: str
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    json: Optional[Any] = None
    data: Optional[str] = None

@app.get("/health")
def health():
    return {"status": "ok", "internet_access": INTERNET_ACCESS, "vm_mode": VM_MODE}

@app.post("/http")
def http_proxy(req: HttpRequest):
    if INTERNET_ACCESS not in ("enabled", "gateway"):
        raise HTTPException(status_code=403, detail="Internet access disabled")
    # check whitelist
    from urllib.parse import urlparse
    host = urlparse(req.url).hostname or ""
    if ALLOWED_HOSTS and host not in ALLOWED_HOSTS:
        raise HTTPException(status_code=403, detail=f"Host not allowed: {host}")
    try:
        r = requests.request(
            req.method.upper(), req.url,
            headers=req.headers, params=req.params,
            json=req.json, data=req.data, timeout=10
        )
        return {
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body": r.text[:1024*1024],  # limit 1MB
            "error": None
        }
    except Exception as e:
        return {"status_code": 0, "headers": {}, "body": None, "error": str(e)}
