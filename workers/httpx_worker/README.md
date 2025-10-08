# HTTPx Worker

Worker per il probing HTTP/HTTPS e fingerprinting tecnologico usando HTTPx.

## Funzionalità
- Ascolta su coda `httpx_tasks`
- Esegue `httpx` su una lista di targets
- Rileva tecnologie, titoli, server headers, CNAME
- Identifica potenziali subdomain takeover
- Salva in Neo4j (nodi HttpProbe, Tech, relazioni)
- Pubblica risultati su `results_queue`

## Throttling Parameters
- `AAPT_HTTPX_THREADS`: numero di thread (default: 50)
- `AAPT_HTTPX_RATE_LIMIT`: rate limit req/sec (default: 150)
- `AAPT_HTTPX_TIMEOUT`: timeout per richiesta (default: 10s)
- `AAPT_HTTPX_RETRIES`: numero di retry (default: 2)

## Task Input
```json
{
  "task_id": "uuid",
  "targets": ["example.com", "sub.example.com", "192.168.1.1"]
}
```

## Risultato Output
```json
{
  "task_id": "uuid",
  "worker_type": "httpx_worker",
  "target": "example.com, sub.example.com, ...",
  "status": "success",
  "timestamp": "2024-...",
  "summary": "HTTPx completato: X risposte HTTP da Y targets.",
  "data": {
    "http_responses": [
      {
        "host": "example.com",
        "ip": "1.2.3.4",
        "port": 80,
        "status_code": 200,
        "title": "Example Site",
        "tech": ["nginx", "php"],
        "server": "nginx/1.18.0",
        "cname": "",
        "content_length": 1234
      }
    ]
  }
}
```