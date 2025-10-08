# Privesc Worker (A.A.P.T.)

## Panoramica
Worker per privilege escalation (linpeas, winPEAS). Lanciato solo su shell ottenute.

## Pipeline
- Privesc viene lanciato solo su shell confermate.
- Output: risultati pubblicati su results_queue, importati in Neo4j.

## Sicurezza e Hardening
- Container non root
- Input shell_id/script validato
- Aggiorna regolarmente linpeas/winPEAS
- Limita esecuzioni massicce

## Esportazione
- Asset prioritari esportabili dalla dashboard in CSV/JSON per Burp/altro. 