# Shodan Worker

Worker per l'integrazione con Shodan API.

## Funzionalità
- Ascolta su coda `shodan_tasks`
- Query Shodan per info su host
- Salva in Neo4j (aggiorna Host e Services)
- Pubblica risultati su `results_queue`

## Requisiti
- Imposta SHODAN_API_KEY in environment

## Task Input
```json
{
  "task_id": "uuid",
  "target": "8.8.8.8"
}
```

## Risultato Output
Strutturato come da schema, con "data" contenente il risultato Shodan completo.
