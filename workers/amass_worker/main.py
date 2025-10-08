import pika
import os
import json
from neo4j import GraphDatabase
import logging
from flask import Flask, jsonify
import threading
import subprocess
from datetime import datetime
import uuid

# --- CONFIGURAZIONE E CONNESSIONI ---
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')

# Logging avanzato
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("amass_worker")

# Prepara le credenziali per RabbitMQ
credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
# Prepara il driver per Neo4j
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
    app.run(host='0.0.0.0', port=8084, debug=False, use_reloader=False)

# --- FUNZIONI DI BASE ---
def write_to_db(domain, subdomains):
    if not db_driver:
        logger.error("Driver Neo4j non disponibile!")
        return
    now = datetime.utcnow().isoformat()
    with db_driver.session() as session:
        session.run("MERGE (d:Domain {name: $name}) SET d.last_seen = $now", name=domain, now=now)
        for sub in subdomains:
            session.run("""
                MATCH (d:Domain {name: $domain})
                MERGE (s:Subdomain {name: $sub})
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                SET s.last_seen = $now
            """, domain=domain, sub=sub, now=now)
        logger.info(f"Aggiunti {len(subdomains)} sottodomini per {domain} in Neo4j.")

def run_amass_task(domain, task_id):
    output_file = f"/tmp/amass_{task_id}.json"
    # Throttling / evasion
    timeout = os.getenv('AAPT_AMASS_TIMEOUT')  # e.g., '10m'
    max_dns_queries = os.getenv('AAPT_AMASS_MAX_DNS', '')
    cmd = ["amass", "enum", "-d", domain, "-json", output_file]
    if timeout:
        cmd += ["-timeout", timeout]
    if max_dns_queries:
        cmd += ["-max-dns-queries", max_dns_queries]
    logger.info(f"Eseguo comando: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        logger.error(f"Errore esecuzione Amass: {proc.stderr}")
        return []
    subdomains = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if 'name' in data:
                        subdomains.append(data['name'])
                except json.JSONDecodeError:
                    continue
        os.remove(output_file)
    except Exception as e:
        logger.error(f"Errore parsing output Amass: {e}")
    return subdomains

def process_amass_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        domain = task.get('domain')
        task_id = task.get('task_id') or str(uuid.uuid4())
        logger.info(f"[+] Ricevuto task Amass: Enumerazione per '{domain}' (task_id={task_id})")
        subdomains = run_amass_task(domain, task_id)
        write_to_db(domain, subdomains)
        status = "success" if subdomains else "failure"
        summary = f"Trovati {len(subdomains)} sottodomini per {domain}."
        result_message = {
            "task_id": task_id,
            "worker_type": "amass_worker",
            "target": domain,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": {
                "subdomains": subdomains
            }
        }
        channel.queue_declare(queue='results_queue', durable=True)
        channel.basic_publish(
            exchange='',
            routing_key='results_queue',
            body=json.dumps(result_message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        logger.info(f"[>>>] Risultato pubblicato su results_queue per {domain} (task_id={task_id})")
    except Exception as e:
        logger.error(f"Errore critico durante l'esecuzione del task: {e}")
    finally:
        channel.basic_ack(delivery_tag=method.delivery_tag)
        logger.info("[*] Task completato. In attesa del prossimo...")

def main():
    # Avvia healthcheck HTTP in thread separato
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    global health_status
    health_status["status"] = "starting"
    connection = None
    while True:
        try:
            logger.info("[*] Worker Amass avviato. Provo a connettermi a RabbitMQ...")
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='amass_tasks', durable=True)
            logger.info("[*] Connessione a RabbitMQ riuscita. Coda 'amass_tasks' pronta.")
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='amass_tasks', on_message_callback=process_amass_task)
            health_status["status"] = "ok"
            logger.info("[*] Inizio ad ascoltare la coda per i task...")
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