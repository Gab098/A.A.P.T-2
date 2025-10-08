import pika
import json
import uuid
import threading
import time
import os
import logging
from flask import Flask, jsonify, request
from datetime import datetime, timedelta
import sys

# Add common module to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
from common.result_schema import create_result_message

# Configuration
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
ORCH_HEALTH_PORT = int(os.getenv('ORCH_HEALTH_PORT', '5152'))

# Passive scheduling intervals
PASSIVE_SCHEDULE_INTERVAL = int(os.getenv('AAPT_PASSIVE_INTERVAL', '300'))  # 5 minutes
SUBDOMAIN_REFRESH_HOURS = int(os.getenv('AAPT_SUBDOMAIN_REFRESH_HOURS', '24'))
HTTP_PROBE_REFRESH_HOURS = int(os.getenv('AAPT_HTTP_PROBE_REFRESH_HOURS', '12'))

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("orchestrator_v3")

# Initialize Prioritizer client (optional)
try:
    from core.clients import PrioritizerClient
    PRIORITIZER_URL = os.getenv('PRIORITIZER_URL', 'http://prioritizer:8080')
    prioritizer_client = PrioritizerClient(base_url=PRIORITIZER_URL)
    logger.info(f"Prioritizer client initialized: {PRIORITIZER_URL}")
except Exception as e:
    prioritizer_client = None
    logger.warning(f"Prioritizer client not available: {e}")

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)

# Import state manager
try:
    from state_manager import StateManager
    state_manager = StateManager(NEO4J_URI, NEO4J_USER, NEO4J_PASS)
except ImportError as e:
    logger.error(f"Cannot import StateManager: {e}")
    state_manager = None

# Flask app for API and health
app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

@app.route('/status', methods=['GET'])
def status():
    """Get system status and statistics"""
    if not state_manager:
        return jsonify({"error": "StateManager not available"}), 500
    
    try:
        system_state = state_manager.get_system_state()
        return jsonify({
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "system_state": system_state,
            "passive_scheduling": {
                "enabled": True,
                "interval_seconds": PASSIVE_SCHEDULE_INTERVAL,
                "subdomain_refresh_hours": SUBDOMAIN_REFRESH_HOURS,
                "http_probe_refresh_hours": HTTP_PROBE_REFRESH_HOURS
            }
        })
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/manual_action', methods=['POST'])
def manual_action():
    """Manual task submission endpoint"""
    try:
        data = request.get_json()
        action = data.get('action')
        target = data.get('target')
        parameters = data.get('parameters', {})
        
        if not action or not target:
            return jsonify({'error': 'action and target required'}), 400
        
        # Create task
        task = {
            'task_id': str(uuid.uuid4()),
            'correlation_id': str(uuid.uuid4()),
            'target': target,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        task.update(parameters)
        
        # Route to appropriate queue
        queue_map = {
            'nmap_scan': 'nmap_tasks',
            'subfinder': 'subfinder_tasks',
            'amass': 'amass_tasks',
            'httpx_probe': 'httpx_tasks',
            'dnsx_resolve': 'dnsx_tasks',
            'masscan': 'masscan_tasks',
            'nuclei_scan': 'nuclei_tasks',
            'msf_exploit': 'msf_tasks',
            'privesc': 'privesc_tasks',
            'cve_enrich': 'cve_enrichment_tasks'
        }
        
        queue = queue_map.get(action)
        if not queue:
            return jsonify({'error': f'Unknown action: {action}'}), 400
        
        # Publish task
        success = publish_task(queue, task)
        
        if success:
            return jsonify({
                'status': f'Task {action} submitted for {target}',
                'task_id': task['task_id']
            }), 200
        else:
            return jsonify({'error': 'Failed to publish task'}), 500
            
    except Exception as e:
        logger.error(f"Error in manual_action: {e}")
        return jsonify({'error': str(e)}), 500

def start_api_server():
    app.run(host='0.0.0.0', port=ORCH_HEALTH_PORT, debug=False, use_reloader=False)

def publish_task(queue, task):
    """Publish a task to specified queue"""
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
        channel = connection.channel()
        channel.queue_declare(queue=queue, durable=True)
        
        channel.basic_publish(
            exchange='aapt.tasks',
            routing_key=queue,
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        
        connection.close()
        logger.info(f"Published task to {queue}: {task.get('task_id')}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to publish task to {queue}: {e}")
        return False

def schedule_passive_recon():
    """Schedule passive reconnaissance tasks based on graph state"""
    if not state_manager:
        logger.warning("StateManager not available for passive scheduling")
        return
    
    try:
        logger.info("Running passive reconnaissance scheduling...")
        
        # Get stale subdomains that need DNS resolution
        cutoff_time = datetime.utcnow() - timedelta(hours=SUBDOMAIN_REFRESH_HOURS)
        
        with state_manager.driver.session() as session:
            # Find unresolved or stale subdomains
            result = session.run("""
                MATCH (s:Subdomain)
                WHERE NOT (s)-[:RESOLVES_TO]->(:Host) 
                   OR s.last_seen < $cutoff
                RETURN s.name as subdomain
                LIMIT 100
            """, cutoff=cutoff_time.isoformat())
            
            stale_subdomains = [record['subdomain'] for record in result]
            
            if stale_subdomains:
                logger.info(f"Scheduling DNS resolution for {len(stale_subdomains)} subdomains")
                
                # Batch subdomains for DNSx
                batch_size = 50
                for i in range(0, len(stale_subdomains), batch_size):
                    batch = stale_subdomains[i:i+batch_size]
                    
                    task = {
                        'task_id': str(uuid.uuid4()),
                        'correlation_id': f"passive_dns_{int(time.time())}",
                        'domains': batch,
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'source': 'passive_scheduler'
                    }
                    
                    publish_task('dnsx_tasks', task)
            
            # Find resolved subdomains that need HTTP probing
            http_cutoff = datetime.utcnow() - timedelta(hours=HTTP_PROBE_REFRESH_HOURS)
            
            result = session.run("""
                MATCH (s:Subdomain)-[:RESOLVES_TO]->(h:Host)
                WHERE NOT (s)-[:PROBED_BY]->(:HttpProbe)
                   OR EXISTS {
                       MATCH (s)-[:PROBED_BY]->(p:HttpProbe)
                       WHERE p.last_seen < $cutoff
                   }
                RETURN s.name as subdomain
                LIMIT 200
            """, cutoff=http_cutoff.isoformat())
            
            stale_http_targets = [record['subdomain'] for record in result]
            
            if stale_http_targets:
                logger.info(f"Scheduling HTTP probing for {len(stale_http_targets)} targets")
                
                # Batch targets for HTTPx
                batch_size = 100
                for i in range(0, len(stale_http_targets), batch_size):
                    batch = stale_http_targets[i:i+batch_size]
                    
                    task = {
                        'task_id': str(uuid.uuid4()),
                        'correlation_id': f"passive_http_{int(time.time())}",
                        'targets': batch,
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'source': 'passive_scheduler'
                    }
                    
                    publish_task('httpx_tasks', task)
            
            # Find interesting assets that need CVE enrichment
            result = session.run("""
                MATCH (t:Tech)
                WHERE t.cve IS NOT NULL 
                  AND NOT EXISTS {
                      MATCH (c:CVE {id: t.cve})
                      WHERE c.last_enriched > $cutoff
                  }
                RETURN DISTINCT t.cve as cve_id, t.name as product
                LIMIT 50
            """, cutoff=(datetime.utcnow() - timedelta(days=7)).isoformat())
            
            cves_to_enrich = [(record['cve_id'], record['product']) for record in result]
            
            if cves_to_enrich:
                logger.info(f"Scheduling CVE enrichment for {len(cves_to_enrich)} CVEs")
                
                for cve_id, product in cves_to_enrich:
                    task = {
                        'task_id': str(uuid.uuid4()),
                        'correlation_id': f"passive_cve_{int(time.time())}",
                        'cve_id': cve_id,
                        'product': product,
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'source': 'passive_scheduler'
                    }
                    
                    publish_task('cve_enrichment_tasks', task)
        
        logger.info("Passive reconnaissance scheduling completed")
        
    except Exception as e:
        logger.error(f"Error in passive scheduling: {e}")

def passive_scheduler_loop():
    """Main loop for passive scheduling"""
    logger.info(f"Starting passive scheduler with {PASSIVE_SCHEDULE_INTERVAL}s interval")
    
    while True:
        try:
            schedule_passive_recon()
            time.sleep(PASSIVE_SCHEDULE_INTERVAL)
        except Exception as e:
            logger.error(f"Error in passive scheduler loop: {e}")
            time.sleep(60)  # Wait 1 minute on error

def listen_results_queue():
    """Listen to results queue and process results"""
    def callback(ch, method, properties, body):
        try:
            result = json.loads(body)
            logger.info(f"[***] Result received: {result.get('worker_type')} - {result.get('status')} - {result.get('summary')}")
            
            # Process result with state manager
            if state_manager:
                state_manager.process_result_message(result)
            
            # Reactive logic based on results
            worker_type = result.get('worker_type')
            status = result.get('status')
            data = result.get('data', {})
            
            if worker_type == 'subfinder_worker' and status == 'success':
                # New subdomains found, schedule DNS resolution
                subdomains = data.get('subdomains', [])
                if subdomains:
                    logger.info(f"Scheduling DNS resolution for {len(subdomains)} new subdomains")
                    
                    task = {
                        'task_id': str(uuid.uuid4()),
                        'correlation_id': result.get('correlation_id'),
                        'domains': subdomains,
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'source': 'reactive_scheduler'
                    }
                    
                    publish_task('dnsx_tasks', task)
            
            elif worker_type == 'dnsx_worker' and status == 'success':
                # DNS resolved, schedule HTTP probing
                dns_results = data.get('dns_results', [])
                resolved_hosts = [r['host'] for r in dns_results if r.get('a_records')]
                
                if resolved_hosts:
                    logger.info(f"Scheduling HTTP probing for {len(resolved_hosts)} resolved hosts")
                    
                    task = {
                        'task_id': str(uuid.uuid4()),
                        'correlation_id': result.get('correlation_id'),
                        'targets': resolved_hosts,
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'source': 'reactive_scheduler'
                    }
                    
                    publish_task('httpx_tasks', task)
            
            elif worker_type == 'httpx_worker' and status == 'success':
                # HTTP probed: use Prioritizer if available to select nuclei targets
                http_responses = data.get('http_responses', [])
                
                try:
                    candidates = []
                    for response in http_responses:
                        host = response.get('host') or response.get('url') or response.get('domain')
                        if not host:
                            continue
                        tech_list = response.get('tech', []) or []
                        ports = []
                        if 'port' in response and isinstance(response.get('port'), int):
                            ports = [response.get('port')]
                        cve = response.get('cve', []) or []
                        banner = response.get('title') or response.get('banner')
                        candidates.append({
                            'host': host,
                            'tech': tech_list,
                            'ports': ports,
                            'cve': cve,
                            'banner': banner,
                            'metadata': {}
                        })
                    selected_hosts = set()
                    if prioritizer_client and candidates:
                        scored = prioritizer_client.score_targets(candidates)
                        # Select high label or score threshold
                        for s in scored:
                            if getattr(s, 'label', 'low') == 'high' or float(getattr(s, 'score', 0.0)) >= 0.7:
                                selected_hosts.add(getattr(s, 'host', None))
                    # Fallback to heuristic if no selection or client unavailable
                    if not selected_hosts:
                        for response in http_responses:
                            tech_list = response.get('tech', [])
                            interesting_tech = ['jenkins', 'apache', 'nginx', 'tomcat', 'wordpress']
                            if any(tech.lower() in ' '.join(tech_list).lower() for tech in interesting_tech):
                                if response.get('host'):
                                    selected_hosts.add(response.get('host'))
                    # Schedule nuclei scans for selected hosts
                    for host in selected_hosts:
                        logger.info(f"Scheduling nuclei scan (prioritized) on {host}")
                        task = {
                            'task_id': str(uuid.uuid4()),
                            'correlation_id': result.get('correlation_id'),
                            'target': f"http://{host}",
                            'timestamp': datetime.utcnow().isoformat() + 'Z',
                            'source': 'reactive_scheduler'
                        }
                        publish_task('nuclei_tasks', task)
                except Exception as e:
                    logger.error(f"Error during prioritization scheduling: {e}")
            
        except Exception as e:
            logger.error(f"Error processing result: {e}")
        finally:
            ch.basic_ack(delivery_tag=method.delivery_tag)
    
    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='results_queue', durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='results_queue', on_message_callback=callback)
            
            logger.info("[***] Listening on results_queue...")
            channel.start_consuming()
            
        except pika.exceptions.AMQPConnectionError as e:
            logger.warning(f"RabbitMQ connection error: {e}. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            time.sleep(10)

def main():
    # Start API server
    threading.Thread(target=start_api_server, daemon=True).start()
    
    # Start results listener
    threading.Thread(target=listen_results_queue, daemon=True).start()
    
    # Start passive scheduler
    threading.Thread(target=passive_scheduler_loop, daemon=True).start()
    
    health_status["status"] = "ok"
    logger.info("[***] Orchestrator V3 started with passive scheduling")
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
            logger.debug("Orchestrator V3 heartbeat")
    except KeyboardInterrupt:
        logger.info("Orchestrator V3 shutting down...")
        if state_manager:
            state_manager.close()

if __name__ == '__main__':
    main()