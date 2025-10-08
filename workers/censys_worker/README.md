# Censys Worker

Worker per l'integrazione con Censys API.

## Funzionalità
- Ascolta su coda `censys_tasks`
- Query Censys per info su host
- Salva in Neo4j (aggiorna Host e Services)
- Pubblica risultati su `results_queue`

## Requisiti
- Imposta CENSYS_API_ID e CENSYS_API_SECRET in environment

## Task Input
```json
{
  "task_id": "uuid",
  "target": "8.8.8.8"
}
```

## Risultato Output
Strutturato come da schema, con "data" contenente il risultato Censys completo.
