# A.A.P.T. - Schema Completo del Progetto e Documentazione Tecnica

## 📁 Struttura Completa del Progetto

```
AAPT/
├── AAPT/
│   ├── aapt_framework/                    # Framework principale
│   │   ├── common/                        # Componenti condivisi
│   │   │   ├── result_schema.py          # Schema JSON standardizzato per tutti i worker
│   │   │   ├── secrets.py                # Gestione sicura credenziali e configurazione
│   │   │   └── error_handler.py          # Sistema centralizzato gestione errori
│   │   ├── core/                          # Core del framework
│   │   │   ├── clients.py                # Client per servizi esterni
│   │   │   ├── contracts.py              # Contratti e interfacce
│   │   │   └── net.py                    # Gateway di rete
│   │   ├── k8s/                          # Configurazioni Kubernetes
│   │   │   ├── keda-autoscaling.yaml     # Auto-scaling con KEDA
│   │   │   ├── llm_router.yaml          # Router LLM
│   │   │   ├── namespace.yaml           # Namespace Kubernetes
│   │   │   ├── neo4j.yaml               # Database Neo4j
│   │   │   ├── net_gateway_egress.yaml  # Gateway di rete egress
│   │   │   ├── net_gateway.yaml         # Gateway di rete principale
│   │   │   ├── networkpolicy-egress.yaml # Policy di rete egress
│   │   │   ├── opsec-profiles.yaml      # Profili di sicurezza operativa
│   │   │   ├── orchestrator.yaml        # Orchestratore principale
│   │   │   ├── prioritizer.yaml         # Sistema di priorità
│   │   │   ├── rabbitmq-definitions.yaml # Definizioni RabbitMQ
│   │   │   ├── rabbitmq.yaml            # Message broker RabbitMQ
│   │   │   ├── secrets.yaml             # Secret Kubernetes
│   │   │   ├── ui.yaml                  # Interfaccia utente
│   │   │   ├── vision_worker.yaml       # Worker per analisi visiva
│   │   │   └── workers.yaml             # Configurazione worker
│   │   ├── llm_router/                   # Router per modelli LLM
│   │   │   └── app.py                   # Applicazione router LLM
│   │   ├── net_gateway/                  # Gateway di rete
│   │   │   └── app.py                   # Applicazione gateway
│   │   ├── orchestrator/                 # Sistema di orchestrazione
│   │   │   ├── Dockerfile               # Container orchestratore
│   │   │   ├── llm_planner.py           # Pianificatore basato su LLM
│   │   │   ├── main.py                  # Orchestratore base (v1)
│   │   │   ├── orchestrator_v2.py       # Orchestratore autonomo (v2)
│   │   │   ├── orchestrator_v3.py       # Orchestratore avanzato (v3)
│   │   │   ├── README.md                # Documentazione orchestratore
│   │   │   ├── requirements.txt         # Dipendenze Python
│   │   │   ├── state_manager.py         # Gestore stato sistema
│   │   │   └── test_autonomous_system.py # Test sistema autonomo
│   │   ├── prioritizer/                  # Sistema di priorità
│   │   │   └── app.py                   # Applicazione prioritizer
│   │   ├── ui/                          # Interfaccia utente web
│   │   │   ├── app.py                   # Applicazione Flask
│   │   │   ├── Dockerfile               # Container UI
│   │   │   ├── README.md                # Documentazione UI
│   │   │   ├── requirements.txt         # Dipendenze UI
│   │   │   ├── static/                  # File statici
│   │   │   │   ├── css/
│   │   │   │   │   └── style.css        # Stili CSS
│   │   │   │   └── js/
│   │   │   │       └── app.js           # JavaScript frontend
│   │   │   └── templates/
│   │   │       └── index.html           # Template HTML
│   │   ├── vision_worker/               # Worker per analisi visiva
│   │   │   └── consumer.py              # Consumer per task visivi
│   │   ├── workers/                     # Worker specializzati
│   │   │   ├── amass_worker/            # Worker per enumerazione subdomain
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── censys_worker/           # Worker per ricerca Censys
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── cve_enrichment_worker/   # Worker per arricchimento CVE
│   │   │   │   ├── main.py
│   │   │   │   └── requirements.txt
│   │   │   ├── dnsx_worker/             # Worker per risoluzione DNS
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   └── requirements.txt
│   │   │   ├── httpx_worker/            # Worker per probe HTTP
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── masscan_worker/          # Worker per port scan veloce
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── msf_worker/              # Worker per exploit Metasploit
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── naabu_worker/            # Worker per port scan
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── nmap_worker/             # Worker per scan approfondito
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── nuclei_worker/           # Worker per vulnerability scan
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── privesc_worker/          # Worker per privilege escalation
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── shodan_worker/           # Worker per ricerca Shodan
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── subfinder_worker/        # Worker per enumerazione subdomain
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── threat_intel_worker/     # Worker per threat intelligence
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── exploit_adaptation_worker/ # Worker per adattamento exploit
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   ├── cloud_recon_worker/      # Worker per ricognizione cloud
│   │   │   │   ├── Dockerfile
│   │   │   │   ├── main.py
│   │   │   │   ├── README.md
│   │   │   │   └── requirements.txt
│   │   │   └── reporting_worker/        # Worker per generazione report
│   │   │       ├── Dockerfile
│   │   │       ├── main.py
│   │   │       ├── README.md
│   │   │       ├── requirements.txt
│   │   │       └── templates/
│   │   │           └── report_template.md
│   │   ├── scripts/                     # Script di utilità
│   │   │   ├── backup.py                # Script di backup
│   │   │   ├── neo4j_bootstrap.cql      # Bootstrap database Neo4j
│   │   │   ├── neo4j_cleanup.py         # Pulizia database Neo4j
│   │   │   └── setup_secure.py          # Setup sicuro con credenziali generate
│   │   ├── docker-compose.yml           # Configurazione Docker Compose
│   │   ├── env.example                  # Template configurazione sicura
│   │   ├── recon_db.py                  # Database SQLite per ricognizione
│   │   ├── result_schema.md             # Documentazione schema risultati
│   │   ├── README.md                    # Documentazione principale
│   │   ├── README_AUTONOMOUS.md         # Documentazione sistema autonomo
│   │   ├── README_UNIFIED.md            # Guida completa unificata
│   │   ├── start_autonomous.bat         # Script avvio Windows
│   │   └── start_autonomous.sh          # Script avvio Linux/Mac
│   ├── Framework A.A.P.T. Avanzato_ Architettura Multi-Agente e Flussi Operativi.pdf
│   ├── HIP_HOP_MASHUP_LYRICS.md         # Lyrics complete del mashup hip-hop (file random)
│   └── models/                          # Modelli LLM
│       └── phi-3-mini-4K-instruct-q4
|           └── phi-3-mini-4K-instruct-q4.gguf
```

---

## 🏗️ Architettura del Sistema A.A.P.T.

### Panoramica Generale
**A.A.P.T. (Advanced Agent Penetration Testing)** è una piattaforma di ricognizione passiva e pentesting intelligente progettata per bug bounty, red team e automazione avanzata. Utilizza una pipeline asincrona, knowledge base ibrida e orchestrazione LLM-driven per massimizzare la scoperta di asset e vulnerabilità ad alto impatto.

### Componenti Principali

#### 1. **Sistema di Orchestrazione** (`orchestrator/`)
- **`main.py`**: Orchestratore base (v1) - gestione task semplici
- **`orchestrator_v2.py`**: Sistema autonomo con LLM - ciclo OSSERVA-PENSA-AGISCI
- **`orchestrator_v3.py`**: Versione avanzata con pipeline passiva/asincrona
- **`llm_planner.py`**: Pianificatore basato su Phi-3 per decisioni autonome
- **`state_manager.py`**: Gestore stato sistema, interfaccia con Neo4j

#### 2. **Worker Specializzati** (`workers/`)
Pipeline di ricognizione e attacco:
- **`subfinder_worker`**: Enumerazione subdomain passiva
- **`amass_worker`**: Enumerazione subdomain avanzata
- **`httpx_worker`**: Probe HTTP, tech detection, banner grabbing
- **`naabu_worker`**: Port scan leggero e veloce
- **`nmap_worker`**: Scan approfondito porte e servizi
- **`nuclei_worker`**: Vulnerability scanning mirato
- **`msf_worker`**: Exploit automatici con Metasploit
- **`privesc_worker`**: Privilege escalation su shell ottenute
- **`masscan_worker`**: Port scan ad alta velocità
- **`dnsx_worker`**: Risoluzione DNS e record lookup
- **`shodan_worker`**: Ricerca asset tramite Shodan API
- **`censys_worker`**: Ricerca asset tramite Censys API
- **`cve_enrichment_worker`**: Arricchimento informazioni CVE
- **`threat_intel_worker`**: Worker per threat intelligence
- **`exploit_adaptation_worker`**: Worker per adattamento exploit
- **`cloud_recon_worker`**: Worker per ricognizione cloud
- **`reporting_worker`**: Worker per generazione report

#### 3. **Interfaccia Utente** (`ui/`)
- **Dashboard web** con notifiche real-time
- **Esportazione** asset in CSV (Burp) e JSON
- **Azioni manuali** avanzate (nuclei, nmap, msf exploit)
- **Integrazione Slack** per notifiche automatiche
- **Visualizzazione grafo** Neo4j

#### 4. **Infrastruttura** (`k8s/`, `docker-compose.yml`)
- **Containerizzazione** completa con Docker
- **Orchestrazione** con Kubernetes
- **Auto-scaling** con KEDA
- **Message broker** RabbitMQ
- **Database** Neo4j per knowledge graph
- **SQLite** per ricognizione massiva

---

## 🔄 Flusso Operativo del Sistema

### Pipeline Passiva/Asincrona
```
1. subfinder → 2. httpx → 3. naabu → 4. nuclei mirato → 5. nmap/msf (solo su trigger)
```

### Ciclo OSSERVA-PENSA-AGISCI (Sistema Autonomo)
1. **OSSERVA**: StateManager interroga Neo4j per stato sistema
2. **PENSA**: LLMPlanner analizza e decide prossime azioni
3. **AGISCI**: Orchestrator esegue task tramite RabbitMQ

### Schema JSON Standardizzato (v1.2)
Tutti i worker pubblicano risultati su `results_queue` seguendo schema unificato con validazione e versioning:
```json
{
  "schema_version": "1.2",
  "producer_version": "0.3.0",
  "task_id": "uuid",
  "correlation_id": "uuid",
  "attempt": 1,
  "worker_type": "nmap_worker|nuclei_worker|msf_worker|privesc_worker",
  "target": "192.168.1.10",
  "status": "success|failure|partial",
  "timestamp": "2024-10-27T10:00:00Z",
  "summary": "Breve riassunto leggibile",
  "data": { /* dati specifici worker */ },
  "raw_output_path": "/path/to/log.txt", // opzionale
  "message_type": null,
  "media": null,
  "reason_codes": null
}
```

---

## 🛠️ Tecnologie e Stack

### Backend
- **Python 3.8+** - Linguaggio principale
- **Flask** - Framework web per UI
- **RabbitMQ** - Message broker asincrono
- **Neo4j** - Database grafo per knowledge base
- **SQLite** - Database per ricognizione massiva
- **Docker** - Containerizzazione
- **Kubernetes** - Orchestrazione container

### AI/ML
- **Phi-3 Mini** - Modello LLM per pianificazione autonoma
- **Llama 3 8B** - Modello LLM alternativo
- **llama-cpp-python** - Binding Python per modelli GGUF

### Security Tools
- **Nmap** - Network scanning
- **Nuclei** - Vulnerability scanning
- **Metasploit** - Exploitation framework
- **Subfinder** - Subdomain enumeration
- **Amass** - Subdomain enumeration avanzata
- **Httpx** - HTTP probing
- **Naabu** - Port scanning
- **Masscan** - High-speed port scanning

### Monitoring e Observability
- **Prometheus** - Metriche e monitoring
- **Healthcheck endpoints** - Status servizi
- **Structured logging** - Logging avanzato
- **Slack integration** - Notifiche real-time

---

## 🚀 Modalità di Avvio

### Modalità Base
```bash
docker-compose up -d
```
Avvia servizi base senza autonomia.

### Modalità Autonoma
```bash
docker-compose --profile autonomous up -d
```
Avvia sistema completo con pianificazione autonoma LLM.

### Prerequisiti
1. **Modelli LLM** in `./models/`:
   - `./models/Microsoft/phi-3-mini-4k-instruct-q4/Phi-3-mini-4k-instruct-q4.gguf`
   - `./models/Meta/meta-llama-3-8b-instruct.Q4_K_M/meta-llama-3-8b-instruct.Q4_K_M.gguf`

### Setup Sicuro Automatico
```bash
# Setup automatico con credenziali sicure generate
python scripts/setup_secure.py

# Setup con secrets Kubernetes
python scripts/setup_secure.py --k8s
```

---

## 📊 Endpoint e API

### UI Dashboard
- **`http://localhost:5000`** - Dashboard principale
- **`/api/scan`** - Avvia scansione
- **`/api/results`** - Ottieni risultati
- **`/api/interesting_targets`** - Asset prioritari
- **`/api/export_burp`** - Esporta CSV per Burp
- **`/api/export_json`** - Esporta JSON
- **`/api/manual_action`** - Azioni manuali

### Orchestrator
- **`http://localhost:8080/health`** - Orchestrator v1
- **`http://localhost:5151/health`** - Orchestrator v2 (autonomo)
- **`http://localhost:5152/health`** - Orchestrator v3 (avanzato)

### Worker Healthcheck
- **`http://localhost:8080`** - nmap_worker (`/health`, `/errors`)
- **`http://localhost:8082`** - nuclei_worker (`/health`, `/errors`)
- **`http://localhost:8083`** - subfinder_worker (`/health`, `/errors`)
- **`http://localhost:8084`** - amass_worker (`/health`, `/errors`)
- **`http://localhost:8085`** - masscan_worker (`/health`, `/errors`)
- **`http://localhost:8086`** - shodan_worker (`/health`, `/errors`)
- **`http://localhost:8087`** - censys_worker (`/health`, `/errors`)
- **`http://localhost:8088`** - msf_worker (`/health`, `/errors`)
- **`http://localhost:8090`** - httpx_worker (`/health`, `/errors`)
- **`http://localhost:8091`** - dnsx_worker (`/health`, `/errors`)
- **`http://localhost:8092`** - cve_enrichment_worker (`/health`, `/errors`)

---

## 🔧 Configurazione e Personalizzazione

### Variabili d'Ambiente Principali
```bash
# Secrets Management
AAPT_ENCRYPTION_KEY=your_encryption_key_here

# RabbitMQ
RABBITMQ_HOST=rabbitmq
RABBITMQ_USER=aapt_user
RABBITMQ_PASS=your_secure_rabbitmq_password_here

# Neo4j
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASS=your_secure_neo4j_password_here

# LLM Models
MODEL_PATH=./models/Microsoft/phi-3-mini-4k-instruct-q4/
LLM_CONFIDENCE_THRESHOLD=0.6

# Slack Integration
AAPT_SLACK_WEBHOOK=https://hooks.slack.com/services/...

# API Keys (Optional)
SHODAN_API_KEY=your_shodan_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
NVD_API_KEY=your_nvd_key

# OPSEC Profiles
AAPT_NMAP_TIMING=T3
AAPT_HTTPX_RATE_LIMIT=150
AAPT_PASSIVE_INTERVAL=300
```

### Personalizzazione Worker
Ogni worker può essere configurato tramite variabili d'ambiente:
- **NMAP_PORTS**: Porte da scansionare
- **NUCLEI_SEVERITY**: Livelli severità nuclei
- **HTTPX_THREADS**: Thread per probe HTTP
- **DNSX_RATE_LIMIT**: Rate limit DNS

---

## 🔒 Sicurezza e Hardening

### Container Security
- **Container non root** - Esecuzione con privilegi limitati
- **Isolamento per worker** - Ogni worker in container separato
- **Network policies** - Comunicazione limitata tra servizi

### Database Security
- **Credenziali forti** - Password complesse per Neo4j/RabbitMQ
- **Accesso limitato** - Solo rete interna
- **Backup regolari** - Script di backup automatici

### Operational Security
- **Input validation** - Validazione input utente con `common/secrets.py`
- **Rate limiting** - Limitazione richieste configurabile
- **Audit trail** - Logging strutturato con error handling centralizzato
- **Retention policies** - Pulizia dati automatica
- **Secrets encryption** - Crittografia end-to-end per credenziali
- **Error handling** - Sistema centralizzato con categorizzazione errori

---

## 📈 Monitoring e Metriche

### Prometheus Metrics
- **`aapt_results_total`** - Numero totale risultati
- **`aapt_interesting_targets_total`** - Asset promossi
- **`aapt_errors_total`** - Errori sistema

### Healthcheck
Tutti i servizi espongono endpoint `/health` per monitoring e `/errors` per error tracking.

### Logging
- **Structured logging** con timestamp
- **Log levels** configurabili
- **Error tracking** centralizzato

---

## 🔄 Estensioni e Sviluppo

### Aggiungere Nuovo Worker
1. Creare directory in `workers/`
2. Implementare `main.py` con schema standardizzato e error handling
3. Aggiungere validazione input con `common/secrets.py`
4. Integrare sistema error handling con `common/error_handler.py`
5. Aggiungere `Dockerfile` e `requirements.txt`
6. Configurare in `docker-compose.yml`
7. Aggiungere healthcheck endpoint (`/health`, `/errors`)

### Integrazione Tool Esterni
Il sistema supporta integrazione con:
- **Burp Suite** (esportazione CSV)
- **Slack** (notifiche)
- **Prometheus** (metriche)
- **Grafana** (dashboard)

### API Estensioni
- **REST API** per controllo remoto
- **Webhook** per integrazioni
- **GraphQL** per query complesse Neo4j

---

## 🎯 Casi d'Uso Principali

### Bug Bounty
- **Ricognizione automatica** di asset target
- **Prioritizzazione** asset interessanti
- **Esportazione** per Burp Suite
- **Notifiche real-time** su Slack

### Red Team
- **Pipeline completa** da ricognizione a post-exploitation
- **Automazione** exploit con Metasploit
- **Privilege escalation** automatica
- **Persistence** e lateral movement

### Security Assessment
- **Scanning continuo** asset aziendali
- **Vulnerability management** automatizzato
- **Compliance** e reporting
- **Risk assessment** basato su AI

---

## 🚨 Troubleshooting

### Problemi Comuni
1. **Modello LLM non trovato** - Verificare path in `./models/`
2. **Connessione Neo4j fallita** - Controllare credenziali e porta
3. **Errore RabbitMQ** - Verificare servizio e credenziali
4. **Worker non risponde** - Controllare healthcheck endpoint

### Debug
```bash
# Logs dettagliati
export LOG_LEVEL=DEBUG
docker-compose up -d

# Test componenti
python test_autonomous_system.py

# Status servizi
curl http://localhost:5000/api/status
```

---

## 📚 Documentazione Aggiuntiva

- **`README_UNIFIED.md`** - Guida completa unificata (500+ righe)
- **`README.md`** - Guida principale
- **`README_AUTONOMOUS.md`** - Sistema autonomo
- **`result_schema.md`** - Schema risultati
- **`DEPLOYMENT.md`** - Guida deployment
- **`env.example`** - Template configurazione sicura
- **`Framework A.A.P.T. Avanzato.pdf`** - Documentazione architetturale

---

## 🤝 Contributi e Supporto

### Sviluppatore Principale
**smokey (like nagata)**

### Licenza
Open source - Vedi LICENSE

### Supporto
Per problemi o domande:
1. Controllare logs: `docker logs <service_name>`
2. Eseguire test: `python test_autonomous_system.py`
3. Verificare configurazione in `docker-compose.yml`
4. Consultare documentazione componenti

---

**Nota**: Questo sistema rappresenta un avanzamento significativo nell'automazione del pentesting. Utilizzalo responsabilmente e sempre in ambienti autorizzati.

---

## 🔄 Changelog v0.3.1 - Enhanced Security & Error Handling

### ✅ **Bug Fixes**
- **StateManager Bug**: Risolto bug critico variabile `result` non definita
- **Nmap Worker**: Completata implementazione `run_nmap_task` mancante
- **Setup Script**: Corretto path relativi per funzionamento cross-platform

### 🔒 **Security Enhancements**
- **Secrets Management**: Sistema crittografia end-to-end per credenziali
- **Input Validation**: Validazione robusta input per prevenire injection attacks
- **Secure Setup**: Script automatico generazione password sicure
- **Kubernetes Secrets**: Supporto secrets sicuri per deployment K8s

### 🛡️ **Error Handling**
- **Centralized System**: Sistema unificato gestione errori con categorizzazione
- **Error Tracking**: Endpoint `/errors` per monitoring errori real-time
- **Retry Logic**: Meccanismo retry automatico per operazioni critiche
- **Audit Trail**: Logging strutturato per debugging e compliance

### 📊 **Schema Improvements**
- **Version 1.2**: Schema JSON aggiornato con versioning e metadata
- **Validation**: Validazione automatica messaggi con schema
- **Correlation ID**: Tracciabilità completa task end-to-end
- **Raw Output**: Supporto file di log dettagliati per forensics

### 🚀 **Production Readiness**
- **Health Checks**: Endpoint `/health` e `/errors` per tutti i servizi
- **Monitoring**: Metriche Prometheus per observability
- **Documentation**: README unificato 500+ righe con esempi pratici
- **Setup Automation**: Script setup automatico con configurazione sicura

### 🎯 **Developer Experience**
- **Common Modules**: Librerie condivise per validazione e error handling
- **Template System**: Template configurazione per setup rapido
- **Cross-Platform**: Supporto Windows/Linux/macOS
- **Debug Tools**: Endpoint debugging per troubleshooting

---

*A.A.P.T. Framework v0.3.1* - *Enhanced Security & Error Handling*
