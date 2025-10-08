"""
AAPT Core Net Adapter

Tutte le richieste HTTP/HTTPS escono tramite Net-Gateway (Step 6), con fallback opzionale disabilitato.
"""
from __future__ import annotations

import os
from typing import Dict, Any, Optional
import requests


class NetGatewayClient:
    def __init__(self, base_url: Optional[str] = None, timeout: float = 10.0):
        self.base_url = base_url or os.getenv("NET_GATEWAY_URL", "http://net-gateway:8081")
        self.timeout = timeout
        self.internet_access = os.getenv("INTERNET_ACCESS", "disabled").lower()

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
        if self.internet_access not in ("enabled", "gateway"):
            # Enforce passa sempre dal gateway
            pass
        gw_url = f"{self.base_url}/http"
        payload = {
            "method": method.upper(),
            "url": url,
            "headers": headers or {},
            "params": params or {},
            "json": json,
            "data": data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data,
        }
        try:
            r = requests.post(gw_url, json=payload, timeout=timeout or self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"status_code": 0, "headers": {}, "body": None, "error": str(e)}
