import pika
import os
import json
import subprocess
from neo4j import GraphDatabase
import time
import logging
from flask import Flask, jsonify
import threading
from datetime import datetime
import uuid
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from recon_db import insert_nuclei_vulnerability

# --- CONFIGURAZIONE E CONNESSIONI ---
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
NUCLEI_TIMEOUT = int(os.getenv('NUCLEI_TIMEOUT', '300'))
NUCLEI_SEVERITY = os.getenv('NUCLEI_SEVERITY', 'low,medium,high,critical')

# Logging avanzato
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("nuclei_worker")

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
try:
    db_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
except Exception as e:
    logger.error(f"Errore connessione Neo4j: {e}")
    db_driver = None

# --- HEALTHCHECK HTTP ---
app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

def start_healthcheck_server():
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

# --- FUNZIONI DI BASE ---
def write_vulnerabilities_to_db(target, vulnerabilities):
    if not db_driver:
        logger.error("Driver Neo4j non disponibile!")
        return
    with db_driver.session() as session:
        for vuln in vulnerabilities:
            session.run("""
                MERGE (v:Vulnerability {
                    name: $name,
                    severity: $severity,
                    cve: $cve,
                    description: $description
                })
                """,
                name=vuln.get('info', {}).get('name', 'unknown'),
                severity=vuln.get('info', {}).get('severity', 'unknown'),
                cve=vuln.get('info', {}).get('cve', []),
                description=vuln.get('info', {}).get('description', '')
            )
            if target.startswith('http'):
                session.run("""
                    MATCH (s:Service {name: 'http'})
                    MATCH (v:Vulnerability {name: $vuln_name})
                    MERGE (s)-[:IS_VULNERABLE_TO]->(v)
                    """,
                    vuln_name=vuln.get('info', {}).get('name', 'unknown')
                )
            else:
                session.run("""
                    MATCH (h:Host {ip: $ip})
                    MATCH (v:Vulnerability {name: $vuln_name})
                    MERGE (h)-[:IS_VULNERABLE_TO]->(v)
                    """,
                    ip=target,
                    vuln_name=vuln.get('info', {}).get('name', 'unknown')
                )
            logger.info(f"Vulnerabilità trovata: {vuln.get('info', {}).get('name', 'N/A')} ({vuln.get('info', {}).get('severity', 'N/A')})")

def run_nuclei_task(task):
    target = task.get('target')
    templates = task.get('templates', 'cves,defaults')
    severity = task.get('severity', 'medium,high,critical')
    cmd = f"nuclei -u {target} -t {templates} -severity {severity} -json"
    logging.info(f"Eseguo comando: {cmd}")
    result = subprocess.getoutput(cmd)
    vulnerabilities = []
    for line in result.splitlines():
        try:
            data = json.loads(line)
            vuln_info = data.get('info', {})
            vuln = {
                'name': vuln_info.get('name', 'unknown'),
                'severity': vuln_info.get('severity', 'unknown'),
                'cve': vuln_info.get('cve', ''),
                'description': vuln_info.get('description', ''),
                'port': data.get('port', 80),
                'takeover': int(data.get('takeover', False))
            }
            vulnerabilities.append(vuln)
            insert_nuclei_vulnerability(
                target,
                vuln['name'],
                vuln['severity'],
                vuln['cve'],
                vuln['description'],
                vuln['port'],
                vuln['takeover']
            )
        except Exception:
            continue
    return vulnerabilities

def process_nuclei_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        target = task.get('target')
        task_id = task.get('task_id') or str(uuid.uuid4())
        logger.info(f"[+] Ricevuto task Nuclei: Scansione vulnerabilità di '{target}' (task_id={task_id})")
        vulnerabilities = run_nuclei_task(task)
        status = "success" if vulnerabilities else "failure"
        summary = (
            f"Trovate {len(vulnerabilities)} vulnerabilità su {target}."
            if vulnerabilities else
            f"Nessuna vulnerabilità trovata su {target}."
        )
        raw_output_path = None
        # Salva log grezzo opzionale
        raw_log_path = f"/app/logs/nuclei_{task_id}.txt"
        try:
            with open(raw_log_path, "w") as f:
                f.write(json.dumps(vulnerabilities, indent=2))
            raw_output_path = raw_log_path
        except Exception as e:
            logger.warning(f"Impossibile salvare il log grezzo: {e}")
        result_message = {
            "task_id": task_id,
            "worker_type": "nuclei_worker",
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": {
                "vulnerabilities_found": vulnerabilities or []
            },
        }
        if raw_output_path:
            result_message["raw_output_path"] = raw_output_path
        try:
            channel.queue_declare(queue='results_queue', durable=True)
            channel.basic_publish(
                exchange='',
                routing_key='results_queue',
                body=json.dumps(result_message),
                properties=pika.BasicProperties(delivery_mode=2)
            )
            logger.info(f"[>>>] Risultato standard pubblicato su results_queue per {target} (task_id={task_id})")
        except Exception as e:
            logger.error(f"Errore pubblicando su results_queue: {e}")
    except Exception as e:
        logger.error(f"Errore critico durante l'esecuzione del task: {e}")
    finally:
        channel.basic_ack(delivery_tag=method.delivery_tag)
        logger.info("[*] Task nuclei completato. In attesa del prossimo...")

def main():
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    global health_status
    health_status["status"] = "starting"
    connection = None
    while True:
        try:
            logger.info("[*] Worker Nuclei avviato. Provo a connettermi a RabbitMQ...")
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='nuclei_tasks', durable=True)
            logger.info("[*] Connessione a RabbitMQ riuscita. Coda 'nuclei_tasks' pronta.")
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='nuclei_tasks', on_message_callback=process_nuclei_task)
            health_status["status"] = "ok"
            logger.info("[*] Inizio ad ascoltare la coda nuclei_tasks per i task...")
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError as e:
            health_status["status"] = "rabbitmq_error"
            logger.warning(f"[!] Errore di connessione a RabbitMQ: {e}. Riprovo tra 5 secondi...")
            time.sleep(5)
        except Exception as e:
            health_status["status"] = "error"
            logger.error(f"[E] Errore non gestito: {e}")
            if connection and connection.is_open:
                connection.close()
            time.sleep(10)

if __name__ == '__main__':
    main() 