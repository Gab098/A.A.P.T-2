# Reporting Worker

## Panoramica

Il `reporting_worker` è un componente specializzato del framework A.A.P.T. responsabile della generazione automatica di report di penetration testing. Aggrega i dati raccolti durante una campagna di sicurezza da vari worker e li formatta in documenti leggibili e professionali.

## Funzionalità Principali

- **Generazione Automatica**: Genera report in modo automatico al termine di una campagna o su richiesta.
- **Formati Multipli**: Supporta l'output in diversi formati, come Markdown, PDF e HTML (con estensioni future).
- **Aggregazione Dati**: Raccoglie e consolida i risultati da tutti i worker interrogando il database Neo4j.
- **Templating**: Utilizza il motore di templating Jinja2 per creare report personalizzabili e standardizzati.

## Flusso Operativo

1.  **Attivazione**: Il worker viene attivato da un messaggio sulla coda `reporting_queue` di RabbitMQ. Il messaggio contiene il `task_id` o `campaign_id` della campagna da reportizzare.
2.  **Estrazione Dati**: Si connette a Neo4j per estrarre tutti i dati associati alla campagna, inclusi asset, vulnerabilità, porte aperte, ecc.
3.  **Generazione Report**: I dati estratti vengono utilizzati per popolare un template di report predefinito.
4.  **Output**: Il report finale viene salvato in un volume condiviso o inviato tramite canali di notifica.

## Configurazione

Il `reporting_worker` viene configurato tramite le seguenti variabili d'ambiente:

- `RABBITMQ_HOST`: L'hostname del server RabbitMQ.
- `NEO4J_URI`: L'URI per la connessione al database Neo4j.
- `NEO4J_USER`: L'utente per l'autenticazione a Neo4j.
- `NEO4J_PASS`: La password per l'autenticazione a Neo4j.

## Come Eseguirlo

Il worker è progettato per essere eseguito come un container Docker e orchestrato tramite `docker-compose` o Kubernetes.

```bash
# Esempio di avvio con Docker
docker run -d --name reporting_worker \
  -e RABBITMQ_HOST=rabbitmq \
  -e NEO4J_URI=bolt://neo4j:7687 \
  -e NEO4J_USER=neo4j \
  -e NEO4J_PASS=your_password \
  aapt/reporting_worker
```

## Sviluppo

Per estendere il worker, è possibile:

- Aggiungere nuovi template di report nella directory `templates/`.
- Modificare le query Cypher in `main.py` per estrarre dati aggiuntivi.
- Aggiungere il supporto per nuovi formati di output (es. PDF, HTML).
