# Orchestrator (A.A.P.T.)

## Panoramica
Questa cartella contiene la logica di orchestrazione autonoma e passiva di A.A.P.T. (Advanced Agent Penetration Testing).

## Architettura
- **Pipeline passiva/asincrona**: orchestrator gestisce subfinder → httpx → naabu → nuclei mirato/manuale → nmap/msf solo su trigger.
- **Knowledge base ibrida**: SQLite per ricognizione massiva, Neo4j solo per asset attivi/interessanti.
- **Notifiche real-time**: toast in dashboard, Slack integration via webhook.
- **Esportazione**: asset prioritari esportabili in CSV (Burp) e JSON.
- **Azioni manuali avanzate**: lancia nuclei, nmap, msf exploit con parametri custom dalla dashboard.

## Componenti Principali
- **orchestrator_v2.py**: orchestrazione pipeline, dispatch asincrono, gestione obiettivi interessanti.
- **llm_planner.py**: prompt ottimizzato per ricognizione passiva, nuclei mirato, scoring priorità.
- **state_manager.py**: fornisce stato ricco (new_subdomains, active_targets, interesting_assets, anomalous_assets).
- **test_autonomous_system.py**: test automatici pipeline.

## Sicurezza e Hardening
- **Isolamento container**: ogni worker gira in container separato, user non root.
- **RabbitMQ con credenziali forti**: usa variabili d’ambiente sicure, limita accesso di rete.
- **Neo4j accessibile solo dalla rete interna**.
- **Sanitizzazione input**: tutti i parametri passati ai worker sono validati.
- **Rate limiting**: limita task pesanti (nmap, nuclei massivo) via orchestrator.
- **Logging e audit**: log strutturati, audit trail per ogni azione.
- **Webhook/Slack**: non inviare mai dati sensibili nei messaggi.
- **Aggiorna regolarmente i tool**: subfinder, httpx, nuclei, naabu, msf, ecc.

## Estensioni future
- Integrazione con SIEM/SOAR
- Notifiche email/Discord
- Esportazione asset per altri strumenti
- Policy di retention dati 