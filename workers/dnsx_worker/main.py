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
QUEUE = 'dnsx_tasks'
RESULTS_QUEUE = 'results_queue'

# Throttling parameters
DNSX_THREADS = os.getenv('AAPT_DNSX_THREADS', '100')
DNSX_RATE_LIMIT = os.getenv('AAPT_DNSX_RATE_LIMIT', '1000')
DNSX_RESOLVERS = os.getenv('AAPT_DNSX_RESOLVERS')  # path to resolvers file
DNSX_TIMEOUT = os.getenv('AAPT_DNSX_TIMEOUT', '5')

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("dnsx_worker")

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
    app.run(host='0.0.0.0', port=8091, debug=False, use_reloader=False)

def write_to_db(results):
    """Write DNSx results to Neo4j graph"""
    if not db_driver:
        logger.error("Driver Neo4j non disponibile!")
        return
    
    now = datetime.utcnow().isoformat()
    
    with db_driver.session() as session:
        for result in results:
            host = result.get('host', '')
            a_records = result.get('a', [])
            cname_records = result.get('cname', [])
            
            if not host:
                continue
            
            # Create/update subdomain
            session.run("""
                MERGE (s:Subdomain {name: $host})
                SET s.last_seen = $now, s.resolved = $resolved
            """, host=host, now=now, resolved=bool(a_records or cname_records))
            
            # Create A record relationships
            for ip in a_records:
                session.run("""
                    MATCH (s:Subdomain {name: $host})
                    MERGE (h:Host {ip: $ip})
                    MERGE (s)-[:RESOLVES_TO]->(h)
                    SET h.last_seen = $now
                """, host=host, ip=ip, now=now)
            
            # Create CNAME relationships
            for cname in cname_records:
                session.run("""
                    MATCH (s:Subdomain {name: $host})
                    MERGE (c:Subdomain {name: $cname})
                    MERGE (s)-[:ALIAS_OF]->(c)
                    SET c.last_seen = $now
                """, host=host, cname=cname, now=now)

def run_dnsx_task(domains, task_id):
    """Execute dnsx resolution on domains"""
    if isinstance(domains, str):
        domains = [domains]
    
    # Create input file
    input_file = f"/tmp/dnsx_input_{task_id}.txt"
    output_file = f"/tmp/dnsx_output_{task_id}.json"
    
    try:
        with open(input_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        # Build dnsx command
        cmd = [
            "dnsx",
            "-l", input_file,
            "-json",
            "-o", output_file,
            "-silent",
            "-t", DNSX_THREADS,
            "-rl", DNSX_RATE_LIMIT,
            "-timeout", DNSX_TIMEOUT,
            "-a",  # A records
            "-cname",  # CNAME records
            "-resp"  # Include response
        ]
        
        # Add custom resolvers if specified
        if DNSX_RESOLVERS and os.path.exists(DNSX_RESOLVERS):
            cmd.extend(["-r", DNSX_RESOLVERS])
        
        logger.info(f"Eseguo comando: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        if proc.returncode != 0:
            logger.error(f"Errore esecuzione DNSx: {proc.stderr}")
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
        logger.error(f"Errore durante esecuzione DNSx: {e}")
        return []

def process_dnsx_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        task_id, correlation_id, attempt = extract_task_info(task)
        
        domains = task.get('domains', [])
        if isinstance(domains, str):
            domains = [domains]
        
        domain_str = ', '.join(domains[:3]) + ('...' if len(domains) > 3 else '')
        logger.info(f"[+] Ricevuto task DNSx: {len(domains)} domini ({domain_str}) (task_id={task_id})")
        
        results = run_dnsx_task(domains, task_id)
        
        if results:
            write_to_db(results)
            resolved_count = len([r for r in results if r.get('a') or r.get('cname')])
            status = "success"
            summary = f"DNSx completato: {resolved_count}/{len(results)} domini risolti."
        else:
            status = "failure"
            summary = f"DNSx fallito o nessuna risoluzione per {len(domains)} domini."
        
        # Prepare result data
        dns_results = []
        for result in results:
            dns_results.append({
                "host": result.get('host', ''),
                "a_records": result.get('a', []),
                "cname_records": result.get('cname', []),
                "status": result.get('status', ''),
                "resolver": result.get('resolver', '')
            })
        
        result_message = create_result_message(
            task_id=task_id,
            worker_type="dnsx_worker",
            target=domain_str,
            status=status,
            summary=summary,
            data={"dns_results": dns_results},
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
        
        logger.info(f"[>>>] Risultato pubblicato su results_queue per {domain_str} (task_id={task_id})")
        
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
            channel.basic_consume(queue=QUEUE, on_message_callback=process_dnsx_task)
            health_status["status"] = "ok"
            logger.info("[*] DNSx worker in ascolto su coda dnsx_tasks...")
            channel.start_consuming()
        except Exception as e:
            health_status["status"] = "error"
            logger.error(f"[!] Errore: {e}")
            import time
            time.sleep(5)

if __name__ == '__main__':
    main()