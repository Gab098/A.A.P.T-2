# Nmap Worker (A.A.P.T.)

## Panoramica
Worker per port/service scan approfondito (nmap). Lanciato solo su asset confermati/interessanti dalla pipeline passiva.

## Pipeline
- Nmap viene lanciato solo su asset selezionati (dopo naabu/httpx).
- Output: risultati pubblicati su results_queue, importati in Neo4j.

## Sicurezza e Hardening
- Container non root
- Input target/porte validato
- Aggiorna regolarmente nmap
- Limita scan massivi

## Esportazione
- Asset prioritari esportabili dalla dashboard in CSV/JSON per Burp/altro. 