# UI (A.A.P.T.)

## Panoramica
Questa cartella contiene la dashboard web di A.A.P.T., progettata per monitorare lo stato del sistema, visualizzare i task, i risultati delle scansioni e lo stato dei worker. L'interfaccia adotta uno stile cyberpunk e punta a fornire feedback in tempo reale.

## Componenti
- **app.py**: Applicazione Flask che espone le API e serve la dashboard.
- **Dockerfile**: Ambiente Python per la UI.
- **requirements.txt**: Dipendenze Python (Flask, pika, ecc).
- **static/**: File statici (CSS, JS, immagini, cyberpunk theme).
- **templates/**: Template HTML Jinja2 per la dashboard e le pagine di stato.

## Endpoints Principali
- `/` : Dashboard principale (stato sistema, task, risultati)
- `/health` : Healthcheck della UI
- (Futuro) `/ws` : WebSocket per aggiornamenti in tempo reale

## Avvio e Test

### Avvio standalone
```bash
docker-compose up -d ui
```

### Avvio in modalità autonoma (tutto il sistema)
```bash
docker-compose --profile autonomous up -d
```

La dashboard sarà disponibile su: [http://localhost:5000](http://localhost:5000)

## Estensioni Future
- Aggiornamenti in tempo reale via WebSocket
- Visualizzazione avanzata dei risultati di privesc/exploit
- Filtri e ricerca avanzata
- Grafici e timeline degli attacchi
- Notifiche e alert 

## Visualizzazione Risultati Standard

La UI può leggere i risultati pubblicati su orchestrator_results (o results_queue) e visualizzarli in modo strutturato e uniforme.

### Esempio di Risultato JSON
```json
{
  "task_id": "uuid",
  "worker_type": "nmap_worker",
  "target": "192.168.1.10",
  "status": "success",
  "timestamp": "2024-10-27T10:00:00Z",
  "summary": "Trovate 2 porte aperte su 192.168.1.10.",
  "data": {
    "open_ports": [
      {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.29"},
      {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2p1"}
    ]
  },
  "raw_output_path": "/app/logs/nmap_taskid.txt"
}
```

### Come visualizzare nella dashboard
- **Tabella risultati**: mostra `target`, `worker_type`, `status`, `summary`, `timestamp`.
- **Dettaglio**: espandi la riga per vedere il contenuto di `data` (es: lista porte, vulnerabilità, shell, findings).
- **Link log grezzo**: se presente, mostra un link per scaricare o visualizzare il file `raw_output_path`.
- **Filtri**: permetti di filtrare per worker_type, status, target, data/time.

### Estensioni future
- Visualizzazione avanzata findings privesc e shell ottenute
- Grafici e timeline degli eventi
- Alert automatici su risultati critici
- Download diretto dei log raw 