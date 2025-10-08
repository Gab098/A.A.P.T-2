import pika
import json
import uuid
import threading
import time
import os
import logging
from flask import Flask, jsonify

# --- CONFIGURAZIONE ---
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
ORCH_HEALTH_PORT = int(os.getenv('ORCH_HEALTH_PORT', '8080'))
credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)

# Logging avanzato
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("orchestrator")

# Healthcheck HTTP
app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

def start_healthcheck_server():
    app.run(host='0.0.0.0', port=ORCH_HEALTH_PORT, debug=False, use_reloader=False)

# Funzione per inviare un task nmap
def send_nmap_task(target_host):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
    channel = connection.channel()
    channel.queue_declare(queue='nmap_tasks', durable=True)
    task_message = {
        'task_id': str(uuid.uuid4()),
        'target': target_host
    }
    channel.basic_publish(
        exchange='',
        routing_key='nmap_tasks',
        body=json.dumps(task_message),
        properties=pika.BasicProperties(
            delivery_mode=2,
        )
    )
    logger.info(f"[>>>] Task inviato con successo per il target: {target_host}")
    connection.close()

# Funzione per inviare un task nuclei
def send_nuclei_task(target_url):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
    channel = connection.channel()
    channel.queue_declare(queue='nuclei_tasks', durable=True)
    task_message = {
        'task_id': str(uuid.uuid4()),
        'target': target_url
    }
    channel.basic_publish(
        exchange='',
        routing_key='nuclei_tasks',
        body=json.dumps(task_message),
        properties=pika.BasicProperties(
            delivery_mode=2,
        )
    )
    logger.info(f"[>>>] Task nuclei inviato per il target: {target_url}")
    connection.close()

# Funzione che ascolta la coda results_queue
def listen_results_queue():
    def callback(ch, method, properties, body):
        try:
            result = json.loads(body)
            logger.info(f"[***] Risultato ricevuto su results_queue: {json.dumps(result, indent=2)}")
            # --- LOGICA REATTIVA: se nmap trova porte web, lancia nuclei ---
            if 'open_ports' in result:  # Risultato da nmap_worker
                target = result.get('target', '')
                open_ports = result.get('open_ports', [])
                web_ports = [port for port in open_ports if str(port.get('port')) in ['80', '443']]
                if web_ports:
                    logger.info(f"[***] Trovate porte web aperte su {target}. Avvio scansione nuclei...")
                    if target.startswith('http'):
                        nuclei_target = target
                    else:
                        nuclei_target = f"http://{target}"
                    send_nuclei_task(nuclei_target)
                else:
                    logger.info(f"[***] Nessuna porta web trovata su {target}. Nessuna azione nuclei.")
            elif 'vulnerabilities_found' in result:  # Risultato da nuclei_worker
                logger.info(f"[***] Scansione nuclei completata. Trovate {result.get('vulnerabilities_found', 0)} vulnerabilità.")
        except Exception as e:
            logger.error(f"[E] Errore parsing risultato: {e}")
        finally:
            ch.basic_ack(delivery_tag=method.delivery_tag)
            logger.info("[***] In attesa di altri risultati...")
    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='results_queue', durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='results_queue', on_message_callback=callback)
            health_status["status"] = "ok"
            logger.info("[***] In ascolto su results_queue...")
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError as e:
            health_status["status"] = "rabbitmq_error"
            logger.warning(f"[!] Errore di connessione a RabbitMQ: {e}. Riprovo tra 5 secondi...")
            time.sleep(5)
        except Exception as e:
            health_status["status"] = "error"
            logger.error(f"[E] Errore non gestito: {e}")
            time.sleep(10)

if __name__ == '__main__':
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    health_status["status"] = "starting"
    t = threading.Thread(target=listen_results_queue, daemon=True)
    t.start()
    logger.info("[***] Orchestratore reattivo avviato. Puoi inviare nuovi task nmap.")
    while True:
        target = input("Inserisci un target da scansionare (o premi invio per uscire): ").strip()
        if not target:
            logger.info("Uscita.")
            break
        send_nmap_task(target)
    logger.info("[***] Orchestratore terminato.") 