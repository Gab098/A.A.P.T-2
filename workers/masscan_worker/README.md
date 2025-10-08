# Masscan Worker

Worker per la scansione rapida di porte usando Masscan.

## Funzionalità
- Ascolta su coda `masscan_tasks`
- Esegue `masscan` su un target
- Parsa i risultati JSON
- Salva in Neo4j (nodi Host e Service)
- Pubblica risultati su `results_queue`

## Task Input
```json
{
  "task_id": "uuid",
  "target": "192.168.1.1"
}
```

## Risultato Output
```json
{
  "task_id": "uuid",
  "worker_type": "masscan_worker",
  "target": "192.168.1.1",
  "status": "success",
  "timestamp": "2024-...",
  "summary": "Trovate X porte aperte.",
  "data": {
    "open_ports": [{"port": 80, "protocol": "tcp", "status": "open"}, ...]
  }
}
```