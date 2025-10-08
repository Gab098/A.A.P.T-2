# Subfinder Worker (A.A.P.T.)

## Panoramica
Worker per la ricognizione passiva: enumera sottodomini tramite subfinder (Go, velocissimo), salva risultati sia su RabbitMQ che su SQLite (`recon.db`).

## Pipeline
- Ricognizione continua: subfinder lanciato su domini configurati.
- Output: sottodomini pubblicati su results_queue e salvati in SQLite.
- Asset attivi/interessanti importati in Neo4j solo se confermati da probe.

## Sicurezza e Hardening
- Container non root
- Input domain validato
- Aggiorna regolarmente subfinder
- Limita rate di richieste su domini di terzi

## Esportazione
- Asset prioritari esportabili dalla dashboard in CSV/JSON per Burp/altro. 