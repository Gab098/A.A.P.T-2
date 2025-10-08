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
import sys
import re

# Add common module to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from common.result_schema import create_result_message, extract_task_info

# Configuration
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
QUEUE = 'httpx_tasks'
RESULTS_QUEUE = 'results_queue'

# Throttling parameters
HTTPX_THREADS = os.getenv('AAPT_HTTPX_THREADS', '50')
HTTPX_RATE_LIMIT = os.getenv('AAPT_HTTPX_RATE_LIMIT', '150')
HTTPX_TIMEOUT = os.getenv('AAPT_HTTPX_TIMEOUT', '10')
HTTPX_RETRIES = os.getenv('AAPT_HTTPX_RETRIES', '2')

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("httpx_worker")

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)

try:
    db_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
except Exception as e:
    logger.error(f"Errore connessione Neo4j: {e}")
    db_driver = None

# Health check
app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

def start_healthcheck_server():
    app.run(host='0.0.0.0', port=8090, debug=False, use_reloader=False)

def write_to_db(results):
    """Write HTTPx results to Neo4j graph"""
    if not db_driver:
        logger.error("Driver Neo4j non disponibile!")
        return
    
    now = datetime.utcnow().isoformat()
    
    with db_driver.session() as session:
        for result in results:
            host = result.get('host', '')
            ip = result.get('ip', '')
            port = result.get('port', 80)
            status_code = result.get('status_code', 0)
            title = result.get('title', '')
            tech = result.get('tech', [])
            server = result.get('server', '')
            cname = result.get('cname', '')
            
            # Create/update host or subdomain
            if ip and ip != host:
                # It's a subdomain with resolved IP
                session.run("""
                    MERGE (s:Subdomain {name: $host})
                    MERGE (h:Host {ip: $ip})
                    MERGE (s)-[:RESOLVES_TO]->(h)
                    SET s.last_seen = $now, h.last_seen = $now
                """, host=host, ip=ip, now=now)
                target_match = "(s:Subdomain {name: $host})"
            else:
                # Direct IP or host
                session.run("""
                    MERGE (h:Host {ip: $host})
                    SET h.last_seen = $now
                """, host=host, now=now)
                target_match = "(h:Host {ip: $host})"
            
            # Create HTTP probe record
            session.run(f"""
                MATCH {target_match}
                MERGE (p:HttpProbe {{host: $host, port: $port}})
                SET p.status_code = $status_code, p.title = $title, 
                    p.server = $server, p.cname = $cname, p.last_seen = $now
                MERGE ({"s" if "Subdomain" in target_match else "h"})-[:PROBED_BY]->(p)
            """, host=host, port=port, status_code=status_code, 
                title=title, server=server, cname=cname, now=now)
            
            # Create tech nodes and relationships
            for technology in tech:
                tech_name = technology if isinstance(technology, str) else technology.get('name', '')
                if tech_name:
                    session.run(f"""
                        MATCH {target_match}
                        MERGE (t:Tech {{name: $tech_name, host: $host, port: $port}})
                        SET t.last_seen = $now
                        MERGE ({"s" if "Subdomain" in target_match else "h"})-[:HAS_TECH]->(t)
                    """, host=host, port=port, tech_name=tech_name, now=now)
            
            # Check for potential subdomain takeover
            if cname and any(provider in cname.lower() for provider in 
                           ['github.io', 'herokuapp.com', 'amazonaws.com', 'azurewebsites.net']):
                if status_code in [404, 403]:
                    session.run(f"""
                        MATCH {target_match}
                        MERGE (t:Tech {{name: 'subdomain_takeover_candidate', host: $host, port: $port}})
                        SET t.cname = $cname, t.cname_takeover = true, t.last_seen = $now
                        MERGE ({"s" if "Subdomain" in target_match else "h"})-[:HAS_TECH]->(t)
                    """, host=host, port=port, cname=cname, now=now)

def run_httpx_task(targets, task_id):
    """Execute httpx scan on targets"""
    if isinstance(targets, str):
        targets = [targets]
    
    # Create input file
    input_file = f"/tmp/httpx_input_{task_id}.txt"
    output_file = f"/tmp/httpx_output_{task_id}.json"
    
    try:
        with open(input_file, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
        
        # Build httpx command
        cmd = [
            "httpx",
            "-l", input_file,
            "-json",
            "-o", output_file,
            "-silent",
            "-threads", HTTPX_THREADS,
            "-rate-limit", HTTPX_RATE_LIMIT,
            "-timeout", HTTPX_TIMEOUT,
            "-retries", HTTPX_RETRIES,
            "-title",
            "-tech-detect",
            "-server",
            "-cname",
            "-ip",
            "-status-code"
        ]
        
        logger.info(f"Eseguo comando: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        if proc.returncode != 0:
            logger.error(f"Errore esecuzione HTTPx: {proc.stderr}")
            return []
        
        # Parse results
        results = []
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        if data:
                            results.append(data)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            logger.warning(f"File output non trovato: {output_file}")
        
        # Cleanup
        for file_path in [input_file, output_file]:
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass
        
        return results
        
    except Exception as e:
        logger.error(f"Errore durante esecuzione HTTPx: {e}")
        return []

def process_httpx_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        task_id, correlation_id, attempt = extract_task_info(task)
        
        targets = task.get('targets', [])
        if isinstance(targets, str):
            targets = [targets]
        
        target_str = ', '.join(targets[:3]) + ('...' if len(targets) > 3 else '')
        logger.info(f"[+] Ricevuto task HTTPx: {len(targets)} targets ({target_str}) (task_id={task_id})")
        
        results = run_httpx_task(targets, task_id)
        
        if results:
            write_to_db(results)
            status = "success"
            summary = f"HTTPx completato: {len(results)} risposte HTTP da {len(targets)} targets."
        else:
            status = "failure"
            summary = f"HTTPx fallito o nessuna risposta da {len(targets)} targets."
        
        # Prepare result data
        http_responses = []
        for result in results:
            http_responses.append({
                "host": result.get('host', ''),
                "ip": result.get('ip', ''),
                "port": result.get('port', 80),
                "status_code": result.get('status_code', 0),
                "title": result.get('title', ''),
                "tech": result.get('tech', []),
                "server": result.get('server', ''),
                "cname": result.get('cname', ''),
                "content_length": result.get('content_length', 0)
            })
        
        result_message = create_result_message(
            task_id=task_id,
            worker_type="httpx_worker",
            target=target_str,
            status=status,
            summary=summary,
            data={"http_responses": http_responses},
            correlation_id=correlation_id,
            attempt=attempt
        )
        
        channel.queue_declare(queue=RESULTS_QUEUE, durable=True)
        channel.basic_publish(
            exchange='',
            routing_key=RESULTS_QUEUE,
            body=json.dumps(result_message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        
        logger.info(f"[>>>] Risultato pubblicato su results_queue per {target_str} (task_id={task_id})")
        
    except Exception as e:
        logger.error(f"Errore critico durante l'esecuzione del task: {e}")
    finally:
        channel.basic_ack(delivery_tag=method.delivery_tag)
        logger.info("[*] Task completato. In attesa del prossimo...")

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
            channel.basic_consume(queue=QUEUE, on_message_callback=process_httpx_task)
            health_status["status"] = "ok"
            logger.info("[*] HTTPx worker in ascolto su coda httpx_tasks...")
            channel.start_consuming()
        except Exception as e:
            health_status["status"] = "error"
            logger.error(f"[!] Errore: {e}")
            import time
            time.sleep(5)

if __name__ == '__main__':
    main()