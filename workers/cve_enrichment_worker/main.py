import os
import json
import pika
from datetime import datetime
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from core.net import NetGatewayClient
net_client = NetGatewayClient()
from flask import Flask, jsonify
import threading
import uuid
from neo4j import GraphDatabase
import logging
import sys
import time

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
QUEUE = 'cve_enrichment_tasks'
RESULTS_QUEUE = 'results_queue'

# API Configuration
NVD_API_KEY = os.getenv('NVD_API_KEY')  # Optional but recommended
EXPLOITDB_API_URL = "https://www.exploit-db.com/api/v1/search"
VULNERS_API_KEY = os.getenv('VULNERS_API_KEY')

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("cve_enrichment_worker")

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
    app.run(host='0.0.0.0', port=8092, debug=False, use_reloader=False)

def query_nvd_api(cve_id):
    """Query NVD API for CVE details"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": cve_id}
        headers = {}
        
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        resp = net_client.request('GET', url, params=params, headers=headers, timeout=30)
        if int(resp.get('status_code', 0)) == 200:
            try:
                data = json.loads(resp.get('body') or '{}')
            except Exception:
                data = {}
        else:
            data = {}
        # Shim per compatibilità con codice esistente
        class _R: pass
        response = _R()
        response.status_code = int(resp.get('status_code', 0))
        response.json = lambda: data
        
        if response.status_code == 200:
            data = response.json()
            if data.get("totalResults", 0) > 0:
                vuln = data["vulnerabilities"][0]["cve"]
                
                # Extract CVSS score
                cvss_score = 0.0
                cvss_vector = ""
                
                if "metrics" in vuln:
                    if "cvssMetricV31" in vuln["metrics"]:
                        cvss_data = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        cvss_vector = cvss_data.get("vectorString", "")
                    elif "cvssMetricV30" in vuln["metrics"]:
                        cvss_data = vuln["metrics"]["cvssMetricV30"][0]["cvssData"]
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        cvss_vector = cvss_data.get("vectorString", "")
                    elif "cvssMetricV2" in vuln["metrics"]:
                        cvss_data = vuln["metrics"]["cvssMetricV2"][0]["cvssData"]
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        cvss_vector = cvss_data.get("vectorString", "")
                
                return {
                    "cve_id": cve_id,
                    "description": vuln.get("descriptions", [{}])[0].get("value", ""),
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "published_date": vuln.get("published", ""),
                    "last_modified": vuln.get("lastModified", ""),
                    "source": "NVD"
                }
        
        # Rate limiting
        time.sleep(0.6)  # NVD rate limit without API key
        
    except Exception as e:
        logger.error(f"Errore query NVD per {cve_id}: {e}")
    
    return None

def query_exploitdb(cve_id):
    """Query ExploitDB for available exploits"""
    try:
        params = {"cve": cve_id}
        resp = net_client.request('GET', EXPLOITDB_API_URL, params=params, timeout=30)
        if int(resp.get('status_code', 0)) == 200:
            try:
                data = json.loads(resp.get('body') or '{}')
            except Exception:
                data = {}
        else:
            data = {}
        class _R: pass
        response = _R()
        response.status_code = int(resp.get('status_code', 0))
        response.json = lambda: data
        
        if response.status_code == 200:
            data = response.json()
            exploits = []
            
            for exploit in data.get("data", []):
                exploits.append({
                    "id": exploit.get("id"),
                    "title": exploit.get("title"),
                    "type": exploit.get("type"),
                    "platform": exploit.get("platform"),
                    "date": exploit.get("date_published"),
                    "url": f"https://www.exploit-db.com/exploits/{exploit.get('id')}"
                })
            
            return exploits
    
    except Exception as e:
        logger.error(f"Errore query ExploitDB per {cve_id}: {e}")
    
    return []

def suggest_msf_modules(cve_id, product=None, version=None):
    """Suggest Metasploit modules based on CVE and product info"""
    # This is a simplified mapping - in production, you'd want a more comprehensive database
    msf_suggestions = []
    
    # Common CVE to MSF module mappings
    cve_msf_map = {
        "CVE-2017-0144": ["exploit/windows/smb/ms17_010_eternalblue"],
        "CVE-2014-6271": ["exploit/multi/http/bash_env_cgi_inject"],
        "CVE-2021-44228": ["exploit/multi/http/log4j_header_injection"],
        "CVE-2019-0708": ["exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
        "CVE-2020-1472": ["exploit/windows/dcerpc/cve_2020_1472_zerologon"]
    }
    
    if cve_id in cve_msf_map:
        msf_suggestions.extend(cve_msf_map[cve_id])
    
    # Product-based suggestions
    if product:
        product_lower = product.lower()
        if "apache" in product_lower:
            msf_suggestions.append("auxiliary/scanner/http/apache_*")
        elif "nginx" in product_lower:
            msf_suggestions.append("auxiliary/scanner/http/nginx_*")
        elif "ssh" in product_lower:
            msf_suggestions.append("auxiliary/scanner/ssh/*")
        elif "ftp" in product_lower:
            msf_suggestions.append("auxiliary/scanner/ftp/*")
    
    return list(set(msf_suggestions))  # Remove duplicates

def write_to_db(cve_data):
    """Write CVE enrichment data to Neo4j"""
    if not db_driver or not cve_data:
        return
    
    now = datetime.utcnow().isoformat()
    
    with db_driver.session() as session:
        session.run("""
            MERGE (c:CVE {id: $cve_id})
            SET c.description = $description,
                c.cvss_score = $cvss_score,
                c.cvss_vector = $cvss_vector,
                c.published_date = $published_date,
                c.last_modified = $last_modified,
                c.exploits_available = $exploits_available,
                c.msf_modules = $msf_modules,
                c.last_enriched = $now
        """, 
        cve_id=cve_data["cve_id"],
        description=cve_data.get("description", ""),
        cvss_score=cve_data.get("cvss_score", 0.0),
        cvss_vector=cve_data.get("cvss_vector", ""),
        published_date=cve_data.get("published_date", ""),
        last_modified=cve_data.get("last_modified", ""),
        exploits_available=len(cve_data.get("exploits", [])) > 0,
        msf_modules=cve_data.get("msf_modules", []),
        now=now)

def enrich_cve(cve_id, product=None, version=None):
    """Enrich CVE with data from multiple sources"""
    enrichment_data = {"cve_id": cve_id}
    
    # Query NVD
    nvd_data = query_nvd_api(cve_id)
    if nvd_data:
        enrichment_data.update(nvd_data)
    
    # Query ExploitDB
    exploits = query_exploitdb(cve_id)
    enrichment_data["exploits"] = exploits
    
    # Suggest MSF modules
    msf_modules = suggest_msf_modules(cve_id, product, version)
    enrichment_data["msf_modules"] = msf_modules
    
    # Calculate risk score (simplified)
    risk_score = 0
    if enrichment_data.get("cvss_score", 0) > 7.0:
        risk_score += 3
    elif enrichment_data.get("cvss_score", 0) > 4.0:
        risk_score += 2
    else:
        risk_score += 1
    
    if exploits:
        risk_score += 2
    
    if msf_modules:
        risk_score += 1
    
    enrichment_data["risk_score"] = min(risk_score, 5)  # Cap at 5
    
    return enrichment_data

def process_cve_enrichment_task(channel, method, properties, body):
    try:
        task = json.loads(body)
        task_id, correlation_id, attempt = extract_task_info(task)
        
        cve_id = task.get('cve_id', '')
        product = task.get('product', '')
        version = task.get('version', '')
        
        logger.info(f"[+] Ricevuto task CVE enrichment: {cve_id} (task_id={task_id})")
        
        if not cve_id:
            status = "failure"
            summary = "CVE ID non specificato."
            enrichment_data = {}
        else:
            enrichment_data = enrich_cve(cve_id, product, version)
            
            if enrichment_data.get("cvss_score", 0) > 0 or enrichment_data.get("exploits"):
                write_to_db(enrichment_data)
                status = "success"
                summary = f"CVE {cve_id} arricchito: CVSS {enrichment_data.get('cvss_score', 'N/A')}, {len(enrichment_data.get('exploits', []))} exploits."
            else:
                status = "partial"
                summary = f"CVE {cve_id}: dati limitati disponibili."
        
        result_message = create_result_message(
            task_id=task_id,
            worker_type="cve_enrichment_worker",
            target=cve_id,
            status=status,
            summary=summary,
            data={"cve_enrichment": enrichment_data},
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
        
        logger.info(f"[>>>] Risultato pubblicato su results_queue per {cve_id} (task_id={task_id})")
        
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
            channel.basic_consume(queue=QUEUE, on_message_callback=process_cve_enrichment_task)
            health_status["status"] = "ok"
            logger.info("[*] CVE Enrichment worker in ascolto su coda cve_enrichment_tasks...")
            channel.start_consuming()
        except Exception as e:
            health_status["status"] = "error"
            logger.error(f"[!] Errore: {e}")
            import time
            time.sleep(5)

if __name__ == '__main__':
    main()