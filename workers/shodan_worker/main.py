import pika
import os
import json
from neo4j import GraphDatabase
import logging
from flask import Flask, jsonify
import threading
from datetime import datetime
import uuid

# --- CONFIGURAZIONE E CONNESSIONI ---
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

# Logging avanzato
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("shodan_worker")

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
    app.run(host='0.0.0.0', port=8086, debug=False, use_reloader=False)

# --- FUNZIONI DI BASE ---
def write_to_db(target, result):
    if not db_driver:
        logger.error("Driver Neo4j non disponibile!")
        return
    now = datetime.utcnow().isoformat()
    with db_driver.session() as session:
        session.run("""
            MERGE (h:Host {ip: $ip})
            SET h.hostname = $hostname, h.os = $os, h.last_seen = $now
        """, ip=target, hostname=result.get('hostnames', []), os=result.get('os', None), now=now)
        for banner in result.get('data', []):
            port = banner['port']
            protocol = banner.get('transport', 'tcp')
            service = banner.get('service', 'unknown')
            product = banner.get('product', '')
            version = banner.get('version', '')
            session.run("""
                MATCH (h:Host {ip: $ip})
                MERGE (s:Service {port: $port, protocol: $protocol})
                MERGE (h)-[:RUNS_SERVICE]->(s)
                SET s.service = $service, s.product = $product, s.version = $version, s.last_seen = $now
            """, ip=target, port=port, protocol=protocol, service=service, product=product, version=version, now=now)
        logger.info(f"Aggiunti dati Shodan per {target} in Neo4j.")

def run_shodan_task(target, task_id):
    if not SHODAN_API_KEY:
        logger.error("SHODAN_API_KEY non impostata!")
        return {}
    try:
        import shodan
        client = shodan.Shodan(SHODAN_API_KEY)
        result = client.host(target)
        return result
    except Exception as e:
        logger.error(f"Errore query Shodan: {e}")
        return {}

def process_shodan_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        target = task.get('target')
        task_id = task.get('task_id') or str(uuid.uuid4())
        logger.info(f"[+] Ricevuto task Shodan: Query per '{target}' (task_id={task_id})")
        result = run_shodan_task(target, task_id)
        if result:
            write_to_db(target, result)
        status = "success" if result else "failure"
        summary = f"Dati Shodan recuperati per {target}." if result else f"Nessun dato trovato o errore per {target}."
        result_message = {
            "task_id": task_id,
            "worker_type": "shodan_worker",
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": result
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
            logger.info("[*] Worker Shodan avviato. Provo a connettermi a RabbitMQ...")
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='shodan_tasks', durable=True)
            logger.info("[*] Connessione a RabbitMQ riuscita. Coda 'shodan_tasks' pronta.")
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='shodan_tasks', on_message_callback=process_shodan_task)
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