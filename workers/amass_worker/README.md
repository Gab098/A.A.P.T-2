# Amass Worker

Worker per l'enumerazione di sottodomini usando Amass.

## Funzionalità
- Ascolta su coda `amass_tasks`
- Esegue `amass enum` su un dominio
- Parsa i risultati JSON
- Salva in Neo4j (nodi Domain e Subdomain)
- Pubblica risultati su `results_queue`

## Task Input
```json
{
  "task_id": "uuid",
  "domain": "example.com"
}
```

## Risultato Output
```json
{
  "task_id": "uuid",
  "worker_type": "amass_worker",
  "target": "example.com",
  "status": "success",
  "timestamp": "2024-...",
  "summary": "Trovati X sottodomini.",
  "data": {
    "subdomains": ["sub1.example.com", ...]
  }
}
```