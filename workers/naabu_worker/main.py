import os
import json
import pika
import asyncio
import aiofiles
import subprocess
import uuid
from datetime import datetime
from flask import Flask, jsonify
import threading
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from recon_db import insert_naabu_result

RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
QUEUE = 'naabu_tasks'
RESULTS_QUEUE = 'results_queue'

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
parameters = pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials, heartbeat=600)

app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

def start_healthcheck_server():
    app.run(host='0.0.0.0', port=8085, debug=False, use_reloader=False)

async def run_naabu(target, task_id):
    output_file = f"naabu_{task_id}.txt"
    cmd = [
        "naabu", "-host", target, "-o", output_file, "-silent"
    ]
    proc = await asyncio.create_subprocess_exec(*cmd)
    await proc.communicate()
    # Leggi risultati
    open_ports = []
    try:
        async with aiofiles.open(output_file, 'r') as f:
            async for line in f:
                line = line.strip()
                if line:
                    try:
                        port = int(line.split("/")[0]) if "/" in line else int(line)
                        # Placeholder: servizio non disponibile direttamente da naabu, si può integrare con nmap o banner grabbing
                        service = None
                        open_ports.append({"port": port, "service": service})
                        insert_naabu_result(target, port, service)
                    except Exception:
                        continue
    except Exception:
        pass
    # Cleanup
    try:
        os.remove(output_file)
    except Exception:
        pass
    return open_ports

def publish_result(channel, target, open_ports, task_id):
    result = {
        "task_id": task_id,
        "worker_type": "naabu_worker",
        "target": target,
        "status": "success" if open_ports else "failure",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": f"Trovate {len(open_ports)} porte aperte su {target}.",
        "data": {
            "open_ports": open_ports
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
        target = task.get('target')
        task_id = task.get('task_id') or str(uuid.uuid4())
        if not target:
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        open_ports = loop.run_until_complete(run_naabu(target, task_id))
        publish_result(channel, target, open_ports, task_id)
    except Exception as e:
        print(f"Errore nel process_task: {e}")
    finally:
        channel.basic_ack(delivery_tag=method.delivery_tag)

def main():
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    global health_status
    health_status["status"] = "starting"
    while True:
        try:
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue=QUEUE, on_message_callback=lambda ch, m, p, b: process_task(ch, m, p, b))
            health_status["status"] = "ok"
            print("[*] naabu_worker in ascolto su coda naabu_tasks...")
            channel.start_consuming()
        except Exception as e:
            health_status["status"] = "error"
            print(f"[!] Errore: {e}")
            import time
            time.sleep(5)

if __name__ == '__main__':
    main() 