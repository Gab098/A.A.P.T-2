# Nuclei Worker (A.A.P.T.)

## Panoramica
Worker per vulnerability scanning mirato (nuclei). Lanciato solo su asset con tech/banner/CVE ad alto impatto.

## Pipeline
- Nuclei viene lanciato solo su asset suggeriti da httpx/naabu/LLM.
- Output: risultati pubblicati su results_queue, importati in Neo4j.

## Sicurezza e Hardening
- Container non root
- Input target/template validato
- Aggiorna regolarmente nuclei/templates
- Limita scan massivi

## Esportazione
- Asset prioritari esportabili dalla dashboard in CSV/JSON per Burp/altro. 