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
logger = logging.getLogger("masscan_worker")

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
    app.run(host='0.0.0.0', port=8085, debug=False, use_reloader=False)

# --- FUNZIONI DI BASE ---
def write_to_db(target, open_ports):
    if not db_driver:
        logger.error("Driver Neo4j non disponibile!")
        return
    now = datetime.utcnow().isoformat()
    with db_driver.session() as session:
        session.run("MERGE (h:Host {ip: $ip}) SET h.last_seen = $now", ip=target, now=now)
        for p in open_ports:
            session.run("""
                MATCH (h:Host {ip: $ip})
                MERGE (s:Service {port: $port, protocol: $protocol})
                MERGE (h)-[:RUNS_SERVICE]->(s)
                SET s.state = $status, s.last_seen = $now
            """, ip=target, port=p['port'], protocol=p['protocol'], status=p['status'], now=now)
        logger.info(f"Aggiunte {len(open_ports)} porte aperte per {target} in Neo4j.")

def run_masscan_task(target, task_id):
    output_file = f"/tmp/masscan_{task_id}.json"
    rate = os.getenv('AAPT_MASSCAN_RATE', '1000')
    excludes = os.getenv('AAPT_MASSCAN_EXCLUDES')  # e.g., '127.0.0.1/8,10.0.0.0/8'
    src_port = os.getenv('AAPT_MASSCAN_SRC_PORT')
    cmd = ["masscan", target, f"--rate={rate}", "-p1-65535", "-oJ", output_file]
    if excludes:
        cmd += ["--exclude", excludes]
    if src_port:
        cmd += ["--source-port", src_port]
    logger.info(f"Eseguo comando: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        logger.error(f"Errore esecuzione Masscan: {proc.stderr}")
        return []
    open_ports = []
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
            for entry in data:
                if 'ports' in entry:
                    for port in entry['ports']:
                        open_ports.append({
                            'port': port['port'],
                            'protocol': port.get('proto', 'tcp'),
                            'status': port.get('status', 'open')
                        })
        os.remove(output_file)
    except Exception as e:
        logger.error(f"Errore parsing output Masscan: {e}")
    return open_ports

def process_masscan_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        target = task.get('target')
        task_id = task.get('task_id') or str(uuid.uuid4())
        logger.info(f"[+] Ricevuto task Masscan: Scansione per '{target}' (task_id={task_id})")
        open_ports = run_masscan_task(target, task_id)
        write_to_db(target, open_ports)
        status = "success" if open_ports else "failure"
        summary = f"Trovate {len(open_ports)} porte aperte per {target}."
        result_message = {
            "task_id": task_id,
            "worker_type": "masscan_worker",
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": {
                "open_ports": open_ports
            }
        }
        channel.queue_declare(queue='results_queue', durable=True)
        channel.basic_publish(
            exchange='',
            routing_key='results_queue',
            body=json.dumps(result_message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        logger.info(f"[>>>] Risultato pubblicato su results_queue per {target} (task_id={task_id})")
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
            logger.info("[*] Worker Masscan avviato. Provo a connettermi a RabbitMQ...")
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='masscan_tasks', durable=True)
            logger.info("[*] Connessione a RabbitMQ riuscita. Coda 'masscan_tasks' pronta.")
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='masscan_tasks', on_message_callback=process_masscan_task)
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