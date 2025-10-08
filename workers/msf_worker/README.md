# MSF Worker (A.A.P.T.)

## Panoramica
Worker per exploit automatici tramite Metasploit. Lanciato solo su asset con vulnerabilità confermata.

## Pipeline
- MSF viene lanciato solo su trigger manuale o alta confidenza.
- Output: risultati pubblicati su results_queue, importati in Neo4j.

## Sicurezza e Hardening
- Container non root
- Input exploit/payload validato
- Aggiorna regolarmente Metasploit
- Limita exploit massivi

## Esportazione
- Asset prioritari esportabili dalla dashboard in CSV/JSON per Burp/altro. 