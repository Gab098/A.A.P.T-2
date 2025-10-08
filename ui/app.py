import os
from flask import Flask, render_template, request, jsonify, Response, send_file
import pika
import json
import uuid
import threading
import time
from datetime import datetime
import logging
from neo4j import GraphDatabase
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
from core.net import NetGatewayClient
net_client = NetGatewayClient()
import csv
from io import StringIO
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# Logging avanzato
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("aapt_ui")

# Configurazione RabbitMQ
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)

# Store per i risultati in tempo reale
results_store = []
max_results = 50  # Limite risultati da mostrare
scan_status = {}  # Stato scansioni per target

# Prometheus metrics
results_metric = Counter('aapt_results_total', 'Numero totale risultati ricevuti')
interesting_metric = Counter('aapt_interesting_targets_total', 'Numero asset promossi')
error_metric = Counter('aapt_errors_total', 'Numero errori UI')

def notify_slack(msg):
    webhook_url = os.getenv('AAPT_SLACK_WEBHOOK')
    if webhook_url:
        payload = {'text': msg}
        try:
            resp = net_client.request('POST', webhook_url, json=payload, timeout=5)
            if int(resp.get('status_code', 0)) != 200:
                logger.warning(f"Slack notify non-200: {resp.get('status_code')} err={resp.get('error')}")
        except Exception as e:
            print(f"Slack notify error: {e}")

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

def send_nmap_task(target_host):
    """Invia un task nmap su RabbitMQ"""
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
        channel = connection.channel()
        channel.queue_declare(queue='nmap_tasks', durable=True)
        task_id = str(uuid.uuid4())
        task_message = {
            'task_id': task_id,
            'target': target_host,
            'timestamp': datetime.now().isoformat()
        }
        channel.basic_publish(
            exchange='',
            routing_key='nmap_tasks',
            body=json.dumps(task_message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        connection.close()
        scan_status[target_host] = {'status': 'in_progress', 'task_id': task_id, 'start_time': datetime.now().isoformat()}
        logger.info(f"[UI] Task inviato per {target_host}")
        return True
    except Exception as e:
        logger.error(f"Errore invio task: {e}")
        scan_status[target_host] = {'status': 'error', 'error': str(e), 'start_time': datetime.now().isoformat()}
        return False

def listen_results_queue():
    """Ascolta la coda results_queue e aggiorna lo store"""
    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='results_queue', durable=True)
            channel.basic_qos(prefetch_count=1)
            def callback(ch, method, properties, body):
                try:
                    result = json.loads(body)
                    result['timestamp'] = datetime.now().isoformat()
                    result['id'] = str(uuid.uuid4())
                    # Stato scansione
                    target = result.get('target', 'unknown')
                    if 'error' in result:
                        scan_status[target] = {'status': 'error', 'error': result['error'], 'end_time': datetime.now().isoformat()}
                        error_metric.inc()
                    else:
                        scan_status[target] = {'status': 'completed', 'end_time': datetime.now().isoformat()}
                    # Aggiungi al store
                    results_store.append(result)
                    results_metric.inc()
                    # Mantieni solo gli ultimi max_results
                    if len(results_store) > max_results:
                        results_store.pop(0)
                    logger.info(f"Risultato ricevuto: {result}")
                except Exception as e:
                    logger.error(f"Errore parsing risultato: {e}")
                    error_metric.inc()
                finally:
                    ch.basic_ack(delivery_tag=method.delivery_tag)
            channel.basic_consume(queue='results_queue', on_message_callback=callback)
            logger.info("UI: In ascolto su results_queue...")
            channel.start_consuming()
        except Exception as e:
            logger.error(f"Errore connessione RabbitMQ: {e}")
            error_metric.inc()
            time.sleep(5)

@app.route('/')
def index():
    """Pagina principale"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """API per avviare una scansione"""
    data = request.get_json()
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'success': False, 'error': 'Target non specificato'})
    success = send_nmap_task(target)
    if success:
        return jsonify({
            'success': True, 
            'message': f'Scansione avviata per {target}',
            'target': target
        })
    else:
        return jsonify({'success': False, 'error': 'Errore nell\'invio del task'})

@app.route('/api/results')
def get_results():
    """API per ottenere i risultati, con filtri opzionali"""
    worker_type = request.args.get('worker_type')
    target = request.args.get('target')
    status = request.args.get('status')
    limit = int(request.args.get('limit', 50))
    filtered = results_store
    if worker_type:
        filtered = [r for r in filtered if r.get('worker_type') == worker_type]
    if target:
        filtered = [r for r in filtered if r.get('target') == target]
    if status:
        filtered = [r for r in filtered if r.get('status') == status]
    filtered = filtered[-limit:]
    return jsonify(filtered[::-1])  # Più recenti prima

@app.route('/api/results/<task_id>')
def get_result_detail(task_id):
    """API per dettaglio di un risultato"""
    for r in results_store:
        if r.get('task_id') == task_id:
            return jsonify(r)
    return jsonify({'error': 'Result not found'}), 404

@app.route('/api/raw_log/<task_id>')
def get_raw_log(task_id):
    """Scarica il file di log grezzo associato a un risultato (se esiste)"""
    for r in results_store:
        if r.get('task_id') == task_id:
            raw_path = r.get('raw_output_path')
            if raw_path and os.path.exists(raw_path):
                return send_file(raw_path, as_attachment=True)
            else:
                return jsonify({'error': 'Log file not found'}), 404
    return jsonify({'error': 'Result not found'}), 404

@app.route('/api/status')
def get_status():
    """API per lo stato del sistema"""
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
        connection.close()
        rabbitmq_status = 'online'
    except:
        rabbitmq_status = 'offline'
    return jsonify({
        'rabbitmq': rabbitmq_status,
        'results_count': len(results_store),
        'scan_status': scan_status,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/graph')
def get_graph():
    """Restituisce una porzione del grafo Neo4j (nodi e relazioni) per la visualizzazione"""
    NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
    NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
    NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    nodes = []
    edges = []
    node_ids = set()
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100
            """)
            for record in result:
                n = record['n']
                m = record['m']
                r = record['r']
                for node in [n, m]:
                    if node.id not in node_ids:
                        nodes.append({
                            'id': node.id,
                            'labels': list(node.labels),
                            'properties': dict(node)
                        })
                        node_ids.add(node.id)
                edges.append({
                    'from': n.id,
                    'to': m.id,
                    'type': r.type,
                    'properties': dict(r)
                })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        driver.close()
    return jsonify({'nodes': nodes, 'edges': edges})

@app.route('/api/interesting_targets')
def get_interesting_targets():
    # Estrae asset interessanti da Neo4j/StateManager e assegna priorità/motivazione dettagliata
    try:
        from orchestrator.state_manager import StateManager
        sm = StateManager()
        state = sm.get_system_state()
        interesting = []
        for asset in state.get('anomalous_assets', []):
            banner = asset.get('banner', '').lower() if asset.get('banner') else ''
            tech = asset.get('tech', '').lower() if asset.get('tech') else ''
            port = asset.get('port', 80) if asset.get('port') else 80
            cve = asset.get('cve', None)
            takeover = asset.get('cname_takeover', False)
            service = asset.get('service', None)
            threat_intelligence = json.loads(asset.get('threat_intelligence', '{}')) if asset.get('threat_intelligence') else {}

            priority = 'low'
            reasons = []
            if takeover:
                priority = 'high'
                reasons.append('Possibile subdomain takeover!')
            if any(x in banner for x in ['error', 'forbidden', 'unauthorized', 'exposed', 'test', 'dev']) or any(x in tech for x in ['jenkins', 'apache', 'nginx', 'tomcat', 'iis']):
                if priority != 'high':
                    priority = 'medium'
                reasons.append(f"Banner/tech sospetto: {banner or tech}")
            if cve:
                priority = 'high'
                reasons.append(f"CVE rilevata: {cve}")
            if port in [8000, 8080, 8443, 5000, 5601, 9000, 10000, 3000, 8888]:
                reasons.append(f"Porta interessante: {port}")
            if service:
                reasons.append(f"Servizio: {service}")
            
            # Add threat intelligence to reasons and adjust priority
            if threat_intelligence:
                if threat_intelligence.get('virustotal', {}).get('data', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
                    priority = 'critical'
                    reasons.append(f"VirusTotal: Rilevato come malevolo ({threat_intelligence['virustotal']['data']['last_analysis_stats']['malicious']} motori)")
                if threat_intelligence.get('abuseipdb', {}).get('data', {}).get('abuseConfidenceScore', 0) > 50:
                    if priority != 'critical':
                        priority = 'high'
                    reasons.append(f"AbuseIPDB: Alto punteggio di abuso ({threat_intelligence['abuseipdb']['data']['abuseConfidenceScore']}%)")

            motivation = "; ".join(reasons) if reasons else 'Nuovo asset rilevato.'
            
            exploit_chain_results = json.loads(asset.get('exploit_chain_results', '{}')) if asset.get('exploit_chain_results') else {}
            compromised_assets = json.loads(asset.get('compromised_assets', '[]')) if asset.get('compromised_assets') else []

            if exploit_chain_results:
                reasons.append(f"Exploit Chain: {exploit_chain_results.get('status', 'unknown')}")
                if exploit_chain_results.get('status') == 'success':
                    priority = 'critical'
                    reasons.append("Exploit Chain: Successo!")
            if compromised_assets:
                priority = 'critical'
                reasons.append(f"Asset compromessi: {len(compromised_assets)}")

            interesting.append({
                'ip': asset.get('ip'),
                'tech': asset.get('tech'),
                'banner': asset.get('banner'),
                'port': port,
                'cve': cve,
                'takeover': takeover,
                'service': service,
                'priority': priority,
                'motivation': motivation,
                'threat_intelligence': threat_intelligence, # Include raw TI data
                'exploit_chain_results': exploit_chain_results,
                'compromised_assets': compromised_assets,
                'full_asset_data': asset # Include full asset data for detailed view
            })
        # Slack notification solo per nuovi high
        if interesting:
            high_targets = [obj for obj in interesting if obj['priority'] in ['high', 'critical']]
            for obj in high_targets:
                notify_slack(f"🔴 Nuovo obiettivo critico: {obj['ip']} - {obj['motivation']}")
            interesting_metric.inc(len(interesting))
        return jsonify(interesting)
    except Exception as e:
        logger.error(f"Error in get_interesting_targets: {e}", exc_info=True)
        return jsonify([])

@app.route('/api/manual_action', methods=['POST'])
def manual_action():
    data = request.get_json()
    action = data.get('action')
    target = data.get('target')
    parameters = data.get('parameters', {})
    if not action or not target:
        return jsonify({'error': 'action e target richiesti'}), 400
    # Dispatch su RabbitMQ (come orchestrator)
    try:
        import pika
        RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
        RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
        RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
        channel = connection.channel()
        task = {'target': target, 'timestamp': datetime.now().isoformat()}
        task.update(parameters)
        queue = None
        if action == 'nmap_scan':
            queue = 'nmap_tasks'
        elif action == 'nuclei_scan':
            queue = 'nuclei_tasks'
        elif action == 'naabu_scan':
            queue = 'naabu_tasks'
        elif action == 'httpx_probe':
            queue = 'httpx_tasks'
        elif action == 'subfinder':
            queue = 'subfinder_tasks'
        elif action == 'msf_exploit':
            queue = 'msf_tasks'
        elif action == 'privesc':
            queue = 'privesc_tasks'
        elif action == 'threat_intel_lookup':
            queue = 'threat_intel_tasks'
        elif action == 'exploit_adaptation':
            queue = 'exploit_adaptation_tasks'
        else:
            return jsonify({'error': f'Azione non supportata: {action}'}), 400
        channel.queue_declare(queue=queue, durable=True)
        channel.basic_publish(
            exchange='',
            routing_key=queue,
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        connection.close()
        return jsonify({'status': f'Azione {action} inviata per {target}'}), 200
    except Exception as e:
        logger.error(f"Error in manual_action: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_burp')
def export_burp():
    # Esporta asset interessanti (high/medium) in CSV per Burp con dettagli
    try:
        from orchestrator.state_manager import StateManager
        sm = StateManager()
        state = sm.get_system_state()
        interesting = []
        for asset in state.get('anomalous_assets', []):
            banner = asset.get('banner', '').lower() if asset.get('banner') else ''
            tech = asset.get('tech', '').lower() if asset.get('tech') else ''
            port = asset.get('port', 80) if asset.get('port') else 80
            cve = asset.get('cve', None)
            takeover = asset.get('cname_takeover', False)
            service = asset.get('service', None)
            threat_intelligence = json.loads(asset.get('threat_intelligence', '{}')) if asset.get('threat_intelligence') else {}

            priority = 'low'
            reasons = []
            if takeover:
                priority = 'high'
                reasons.append('Possibile subdomain takeover!')
            if any(x in banner for x in ['error', 'forbidden', 'unauthorized', 'exposed', 'test', 'dev']) or any(x in tech for x in ['jenkins', 'apache', 'nginx', 'tomcat', 'iis']):
                if priority != 'high':
                    priority = 'medium'
                reasons.append(f"Banner/tech sospetto: {banner or tech}")
            if cve:
                priority = 'high'
                reasons.append(f"CVE rilevata: {cve}")
            if port in [8000, 8080, 8443, 5000, 5601, 9000, 10000, 3000, 8888]:
                reasons.append(f"Porta interessante: {port}")
            if service:
                reasons.append(f"Servizio: {service}")
            
            # Add threat intelligence to reasons and adjust priority
            if threat_intelligence:
                if threat_intelligence.get('virustotal', {}).get('data', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
                    priority = 'critical'
                    reasons.append(f"VirusTotal: Rilevato come malevolo ({threat_intelligence['virustotal']['data']['last_analysis_stats']['malicious']} motori)")
                if threat_intelligence.get('abuseipdb', {}).get('data', {}).get('abuseConfidenceScore', 0) > 50:
                    if priority != 'critical':
                        priority = 'high'
                    reasons.append(f"AbuseIPDB: Alto punteggio di abuso ({threat_intelligence['abuseipdb']['data']['abuseConfidenceScore']}%)")

            motivation = "; ".join(reasons) if reasons else 'Nuovo asset rilevato.'
            if priority in ['high', 'medium', 'critical']:
                interesting.append({
                    'host': asset.get('ip'),
                    'banner': asset.get('banner'),
                    'port': port,
                    'cve': cve,
                    'takeover': takeover,
                    'service': service,
                    'motivation': motivation,
                    'priority': priority,
                    'virustotal_malicious': threat_intelligence.get('virustotal', {}).get('data', {}).get('last_analysis_stats', {}).get('malicious', 0),
                    'abuseipdb_score': threat_intelligence.get('abuseipdb', {}).get('data', {}).get('abuseConfidenceScore', 0),
                    'exploit_chain_status': exploit_chain_results.get('status', 'N/A'),
                    'compromised_assets_count': len(compromised_assets)
                })
        # CSV export
        si = StringIO()
        fieldnames = ['host', 'banner', 'port', 'cve', 'takeover', 'service', 'motivation', 'priority', 'virustotal_malicious', 'abuseipdb_score', 'exploit_chain_status', 'compromised_assets_count']
        writer = csv.DictWriter(si, fieldnames=fieldnames)
        writer.writeheader()
        for row in interesting:
            writer.writerow(row)
        output = si.getvalue()
        return app.response_class(
            output,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=burp_targets.csv'}
        )
    except Exception as e:
        logger.error(f"Error in export_burp: {e}", exc_info=True)
        return 'Errore esportazione', 500

@app.route('/api/export_json')
def export_json():
    # Esporta asset interessanti (high/medium) in JSON con dettagli
    try:
        from orchestrator.state_manager import StateManager
        sm = StateManager()
        state = sm.get_system_state()
        interesting = []
        for asset in state.get('anomalous_assets', []):
            banner = asset.get('banner', '').lower() if asset.get('banner') else ''
            tech = asset.get('tech', '').lower() if asset.get('tech') else ''
            port = asset.get('port', 80) if asset.get('port') else 80
            cve = asset.get('cve', None)
            takeover = asset.get('cname_takeover', False)
            service = asset.get('service', None)
            threat_intelligence = json.loads(asset.get('threat_intelligence', '{}')) if asset.get('threat_intelligence') else {}

            priority = 'low'
            reasons = []
            if takeover:
                priority = 'high'
                reasons.append('Possibile subdomain takeover!')
            if any(x in banner for x in ['error', 'forbidden', 'unauthorized', 'exposed', 'test', 'dev']) or any(x in tech for x in ['jenkins', 'apache', 'nginx', 'tomcat', 'iis']):
                if priority != 'high':
                    priority = 'medium'
                reasons.append(f"Banner/tech sospetto: {banner or tech}")
            if cve:
                priority = 'high'
                reasons.append(f"CVE rilevata: {cve}")
            if port in [8000, 8080, 8443, 5000, 5601, 9000, 10000, 3000, 8888]:
                reasons.append(f"Porta interessante: {port}")
            if service:
                reasons.append(f"Servizio: {service}")
            
            # Add threat intelligence to reasons and adjust priority
            if threat_intelligence:
                if threat_intelligence.get('virustotal', {}).get('data', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
                    priority = 'critical'
                    reasons.append(f"VirusTotal: Rilevato come malevolo ({threat_intelligence['virustotal']['data']['last_analysis_stats']['malicious']} motori)")
                if threat_intelligence.get('abuseipdb', {}).get('data', {}).get('abuseConfidenceScore', 0) > 50:
                    if priority != 'critical':
                        priority = 'high'
                    reasons.append(f"AbuseIPDB: Alto punteggio di abuso ({threat_intelligence['abuseipdb']['data']['abuseConfidenceScore']}%)")

            motivation = "; ".join(reasons) if reasons else 'Nuovo asset rilevato.'
            if priority in ['high', 'medium', 'critical']:
                interesting.append({
                    'host': asset.get('ip'),
                    'banner': asset.get('banner'),
                    'port': port,
                    'cve': cve,
                    'takeover': takeover,
                    'service': service,
                    'motivation': motivation,
                    'priority': priority,
                    'threat_intelligence': threat_intelligence, # Include raw TI data
                    'exploit_chain_results': exploit_chain_results,
                    'compromised_assets': compromised_assets
                })
        return app.response_class(
            json.dumps(interesting, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment;filename=interesting_targets.json'}
        )
    except Exception as e:
        logger.error(f"Error in export_json: {e}", exc_info=True)
        return 'Errore esportazione', 500

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

if __name__ == '__main__':
    listener_thread = threading.Thread(target=listen_results_queue, daemon=True)
    listener_thread.start()
    app.run(host='0.0.0.0', port=5000, debug=True)
