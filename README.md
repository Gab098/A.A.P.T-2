# A.A.P.T. - Advanced Agent Penetration Testing

> **Sviluppatore principale:** smokey (like nagata)

## Panoramica
A.A.P.T. è una piattaforma di ricognizione passiva e pentesting intelligente, progettata per bug bounty, red team e automazione avanzata. Utilizza una pipeline asincrona, knowledge base ibrida e orchestrazione LLM-driven per massimizzare la scoperta di asset e vulnerabilità ad alto impatto, minimizzando il carico sul sistema.

## Architettura
- **Pipeline passiva/asincrona**: subfinder → httpx → naabu → nuclei mirato/manuale → nmap/msf solo su trigger.
- **Knowledge base ibrida**: SQLite (`recon.db`) per ricognizione massiva, Neo4j solo per asset attivi/interessanti.
- **Notifiche real-time**: dashboard (toast), Slack integration via webhook.
- **Esportazione**: asset prioritari esportabili in CSV (Burp) e JSON.
- **Azioni manuali avanzate**: lancia nuclei, nmap, msf exploit con parametri custom dalla dashboard.

## Componenti
- [orchestrator/](./orchestrator/): orchestrazione pipeline, dispatch asincrono, gestione obiettivi interessanti, LLM planner, state manager.
- [workers/subfinder_worker/](./workers/subfinder_worker/): ricognizione passiva (subfinder, output su SQLite e RabbitMQ).
- [workers/httpx_worker/](./workers/httpx_worker/): probe HTTP/tech/banner (output su SQLite e RabbitMQ).
- [workers/naabu_worker/](./workers/naabu_worker/): port scan leggero (output su SQLite e RabbitMQ).
- [workers/nmap_worker/](./workers/nmap_worker/): scan approfondito (solo su asset selezionati).
- [workers/nuclei_worker/](./workers/nuclei_worker/): vulnerability scan mirato.
- [workers/msf_worker/](./workers/msf_worker/): exploit automatici (solo su trigger manuale/alta confidenza).
- [workers/privesc_worker/](./workers/privesc_worker/): privilege escalation su shell ottenute.
- [ui/](./ui/): dashboard web, notifiche real-time, esportazione, azioni manuali avanzate.

## Sicurezza e Hardening
- Container non root, isolamento per worker
- RabbitMQ/Neo4j accessibili solo dalla rete interna, credenziali forti
- Input validato, rate limiting orchestrator
- Logging strutturato, audit trail
- Aggiornamento regolare di tool e dipendenze
- Policy di retention e script di pulizia Neo4j
- Nessun dato sensibile nei webhook/notifiche

## Esportazione e Integrazione
- **CSV per Burp**: dashboard → “Esporta per Burp”
- **JSON**: dashboard → “Esporta JSON”
- **Slack**: imposta `AAPT_SLACK_WEBHOOK` per notifiche automatiche
- **Azioni manuali avanzate**: dashboard → menu Azioni su ogni asset

## Notifiche Real-Time
- Toast/alert automatici per ogni nuovo obiettivo ad alta priorità
- Slack integration per obiettivi high
- Polling dashboard ogni 10 secondi

## Pipeline Passiva/Asincrona
1. subfinder → 2. httpx → 3. naabu → 4. nuclei mirato/manuale → 5. nmap/msf solo su trigger
- Ricognizione continua, probe e scan leggeri, nuclei solo su asset ad alto impatto
- Dashboard e notifiche ti guidano solo su ciò che conta davvero

## Avvio rapido
1. Clona il repo, configura domini in `AAPT_DOMAINS`.
2. Scarica i modelli LLM (vedi README_AUTONOMOUS.md).
3. `docker-compose --profile autonomous up -d`
4. Dashboard: [http://localhost:5000](http://localhost:5000)

## Licenza
Open source. Vedi LICENSE. 