# Formato Standard dei Messaggi di Risultato (results_queue)

Tutti i worker A.A.P.T. devono pubblicare i risultati su `results_queue` seguendo questo schema JSON unificato.

## Schema JSON
```json
{
  "task_id": "uuid-del-task-originale",
  "worker_type": "nmap_worker" | "nuclei_worker" | "msf_worker" | "privesc_worker",
  "target": "192.168.1.10",
  "status": "success" | "failure",
  "timestamp": "2024-10-27T10:00:00Z",
  "summary": "Breve riassunto leggibile.",
  "data": {
    // Sezione specifica del worker
  },
  "raw_output_path": "/path/to/full/log.txt" // Opzionale
}
```

## Descrizione dei Campi
- **task_id**: UUID del task originale ricevuto dal worker.
- **worker_type**: Identificatore del tipo di worker che ha prodotto il risultato.
- **target**: Target del task (IP, dominio, ecc.).
- **status**: Stato finale del task (`success` o `failure`).
- **timestamp**: Data e ora di completamento del task (ISO 8601).
- **summary**: Breve descrizione leggibile del risultato.
- **data**: Oggetto con i dati specifici del worker (vedi esempi sotto).
- **raw_output_path**: (Opzionale) Percorso al file di log/output completo.

## Esempi di Campo `data` per Worker

### nmap_worker
```json
"data": {
  "open_ports": [
    {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.29"},
    {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2p1"}
  ]
}
```

### nuclei_worker
```json
"data": {
  "vulnerabilities_found": [
    {"name": "Apache Path Traversal CVE-2021-41773", "severity": "high", "cve": "CVE-2021-41773"}
  ]
}
```

### msf_worker
```json
"data": {
  "exploit_used": "exploit/windows/smb/ms17_010_eternalblue",
  "exploit_successful": true,
  "shell_obtained": {
    "shell_id": "meterpreter-session-1",
    "access_level": "SYSTEM",
    "os": "Windows Server 2016"
  }
}
```

### privesc_worker
```json
"data": {
  "script_used": "linpeas.sh",
  "findings": [
    {"type": "suid_binary", "description": "/usr/bin/find", "exploit_suggestion": "GTFOBins"},
    {"type": "writable_file", "description": "/etc/passwd"}
  ]
}
```

## Best Practice
- **Valida sempre** lo schema prima di pubblicare il messaggio.
- **Includi sempre** `task_id`, `worker_type`, `target`, `status`, `timestamp`, `summary`, `data`.
- **raw_output_path** è opzionale ma consigliato per debug/forensics.
- Mantieni la sezione `data` il più possibile strutturata e coerente tra worker.

## Estensioni Future
- Versionamento dello schema (`schema_version`)
- Supporto per allegati (es. file di output compressi)
- Integrazione con sistemi di alerting 