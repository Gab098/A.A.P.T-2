import os
import json
import pika
import subprocess
from datetime import datetime
from flask import Flask, jsonify
import threading
import uuid
from neo4j import GraphDatabase
import logging

RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
QUEUE = 'subfinder_tasks'
RESULTS_QUEUE = 'results_queue'

# Logging avanzato
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("subfinder_worker")

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)

try:
    db_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
except Exception as e:
    logger.error(f"Errore connessione Neo4j: {e}")
    db_driver = None

app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

def start_healthcheck_server():
    app.run(host='0.0.0.0', port=8083, debug=False, use_reloader=False)

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

def run_subfinder(domain, task_id):
    output_file = f"/tmp/subfinder_{task_id}.json"
    rate_limit = os.getenv('AAPT_SUBFINDER_RATE')  # e.g., '100'
    resolvers = os.getenv('AAPT_SUBFINDER_RESOLVERS')  # path to resolvers.txt
    provider_cfg = os.getenv('AAPT_SUBFINDER_PROVIDER')  # path to provider config
    cmd = ["subfinder", "-d", domain, "-oJ", "-o", output_file, "-silent"]
    if rate_limit:
        cmd += ["-rl", rate_limit]
    if resolvers and os.path.exists(resolvers):
        cmd += ["-r", resolvers]
    if provider_cfg and os.path.exists(provider_cfg):
        cmd += ["-pc", provider_cfg]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        logger.error(f"Errore esecuzione Subfinder: {proc.stderr}")
        return []
    subdomains = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if 'host' in data:
                        subdomains.append(data['host'])
                except json.JSONDecodeError:
                    continue
        os.remove(output_file)
    except Exception as e:
        logger.error(f"Errore parsing output Subfinder: {e}")
    return subdomains

def publish_result(channel, domain, subdomains, task_id):
    result = {
        "task_id": task_id,
        "worker_type": "subfinder_worker",
        "target": domain,
        "status": "success" if subdomains else "failure",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": f"Trovati {len(subdomains)} sottodomini per {domain}.",
        "data": {
            "subdomains": subdomains
        }
    }
    channel.queue_declare(queue=RESULTS_QUEUE, durable=True)
    channel.basic_publish(
        exchange='',
        routing_key=RESULTS_QUEUE,
        body=json.dumps(result),
        properties=pika.BasicProperties(delivery_mode=2)
    )

def process_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        domain = task.get('domain')
        task_id = task.get('task_id') or str(uuid.uuid4())
        if not domain:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return
        subdomains = run_subfinder(domain, task_id)
        write_to_db(domain, subdomains)
        publish_result(channel, domain, subdomains, task_id)
    except Exception as e:
        logger.error(f"Errore nel process_task: {e}")
    finally:
        channel.basic_ack(delivery_tag=method.delivery_tag)

def main():
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    global health_status
    health_status["status"] = "starting"
    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue=QUEUE, on_message_callback=process_task)
            health_status["status"] = "ok"
            logger.info("[*] subfinder_worker in ascolto su coda subfinder_tasks...")
            channel.start_consuming()
        except Exception as e:
            health_status["status"] = "error"
            logger.error(f"[!] Errore: {e}")
            import time
            time.sleep(5)

if __name__ == '__main__':
    main()