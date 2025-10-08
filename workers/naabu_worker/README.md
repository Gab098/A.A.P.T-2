# Naabu Worker (A.A.P.T.)

## Panoramica
Worker per port scanning leggero e veloce (naabu, Go). Scrive risultati su RabbitMQ e su SQLite (`recon.db`).

## Pipeline
- Port scan su asset attivi (dopo probe httpx).
- Output: porte aperte pubblicate su results_queue e salvate in SQLite.
- Asset attivi/interessanti importati in Neo4j solo se confermati.

## Sicurezza e Hardening
- Container non root
- Input target validato
- Aggiorna regolarmente naabu
- Limita rate di scan su target

## Esportazione
- Asset prioritari esportabili dalla dashboard in CSV/JSON per Burp/altro. 