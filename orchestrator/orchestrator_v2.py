import logging
import json
import time
import threading
from typing import Dict, List, Any, Optional
from flask import Flask, jsonify, request
import pika
import requests
from datetime import datetime
import os
import uuid
import csv

class OrchestratorV2:
    """
    Orchestrator V2 - Sistema di pianificazione autonoma per A.A.P.T.
    Integra StateManager e LLMPlanner per decisioni autonome
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.setup_logging()
        
        # Configurazione
        self.rabbitmq_host = os.getenv('RABBITMQ_HOST', 'rabbitmq')
        self.rabbitmq_port = int(os.getenv('RABBITMQ_PORT', 5672))
        self.rabbitmq_user = os.getenv('RABBITMQ_USER', 'guest')
        self.rabbitmq_pass = os.getenv('RABBITMQ_PASS', 'guest')
        
        # Componenti
        self.state_manager = None
        self.llm_planner = None
        self.connection = None
        self.channel = None
        
        # Stato del sistema
        self.is_running = False
        self.current_cycle = 0
        self.last_action = None
        self.stats = {
            'cycles_completed': 0,
            'actions_executed': 0,
            'errors': 0,
            'start_time': None
        }
        
        # Flask app per healthcheck
        self.app = Flask(__name__)
        self.setup_flask_routes()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('orchestrator_v2.log')
            ]
        )
        
    def setup_flask_routes(self):
        @self.app.route('/health')
        def health():
            return jsonify({
                'status': 'healthy' if self.is_running else 'stopped',
                'cycle': self.current_cycle,
                'stats': self.stats,
                'last_action': self.last_action
            })
            
        @self.app.route('/status')
        def status():
            try:
                state = self.state_manager.get_system_state() if self.state_manager else {}
                return jsonify({
                    'orchestrator_status': 'running' if self.is_running else 'stopped',
                    'system_state': state,
                    'current_cycle': self.current_cycle,
                    'stats': self.stats
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
                
        @self.app.route('/manual_action', methods=['POST'])
        def manual_action():
            try:
                data = request.get_json()
                action = data.get('action')
                target = data.get('target')
                
                if not action or not target:
                    return jsonify({'error': 'action e target richiesti'}), 400
                
                self.execute_action(action, target, data.get('parameters', {}))
                return jsonify({'status': 'action_executed'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500

    def initialize(self):
        """Inizializza tutti i componenti"""
        try:
            self.logger.info("Inizializzazione Orchestrator V2...")
            
            # Inizializza StateManager
            from state_manager import StateManager
            self.state_manager = StateManager()
            self.logger.info("StateManager inizializzato")
            
            # Inizializza LLMPlanner
            from llm_planner import LLMPlanner
            self.llm_planner = LLMPlanner()
            self.logger.info("LLMPlanner inizializzato")
            
            # Connessione RabbitMQ
            self.connect_rabbitmq()
            self.logger.info("Connessione RabbitMQ stabilita")
            
            self.logger.info("Orchestrator V2 inizializzato con successo")
            return True
        except Exception as e:
            self.logger.error(f"Errore nell'inizializzazione: {e}")
            return False

    def connect_rabbitmq(self):
        """Connessione a RabbitMQ"""
        try:
            credentials = pika.PlainCredentials(self.rabbitmq_user, self.rabbitmq_pass)
            parameters = pika.ConnectionParameters(
                host=self.rabbitmq_host,
                port=self.rabbitmq_port,
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )
            
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            
            # Dichiara le code
            self.channel.queue_declare(queue='nmap_tasks', durable=True)
            self.channel.queue_declare(queue='nuclei_tasks', durable=True)
            self.channel.queue_declare(queue='orchestrator_results', durable=True)
            
            self.logger.info("Connessione RabbitMQ stabilita")
            
        except Exception as e:
            self.logger.error(f"Errore connessione RabbitMQ: {e}")
            raise

    def start(self):
        """Avvia il loop principale dell'orchestrator"""
        if not self.initialize():
            self.logger.error("Inizializzazione fallita")
            return False
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        # Avvia Flask in thread separato
        flask_thread = threading.Thread(target=self._run_flask, daemon=True)
        flask_thread.start()
        # Avvia thread event-driven per RabbitMQ
        event_thread = threading.Thread(target=self._event_loop, daemon=True)
        event_thread.start()
        self.logger.info("Orchestrator V2 avviato (event-driven + timer fallback)")
        try:
            while self.is_running:
                time.sleep(30)  # Fallback: ciclo ogni 30 secondi
        except KeyboardInterrupt:
            self.logger.info("Interruzione richiesta dall'utente")
        except Exception as e:
            self.logger.error(f"Errore nel loop principale: {e}")
        finally:
            self.stop()

    def recon_cycle(self):
        """Lancia subfinder sui domini target configurati"""
        config_domains = os.getenv('AAPT_DOMAINS', '').split(',')
        for domain in config_domains:
            domain = domain.strip()
            if domain:
                self.logger.info(f"[RECON] Lancio subfinder su {domain}")
                self.execute_action('subfinder', domain, {})

    def probe_cycle(self):
        """Lancia httpx_probe sui sottodomini non ancora probati (da SQLite)"""
        unprobed = self.state_manager.get_unprobed_subdomains_sqlite()
        for sub in unprobed:
            self.logger.info(f"[PROBE] Nuovo subdominio: {sub}, lancio httpx_probe")
            self.execute_action('httpx_probe', sub, {})

    def portscan_cycle(self):
        """Lancia naabu_scan sugli host attivi non ancora scansionati (da SQLite)"""
        unscanned = self.state_manager.get_unscanned_hosts_sqlite()
        for host in unscanned:
            self.logger.info(f"[PORTSCAN] Host attivo: {host['ip']}, lancio naabu_scan")
            self.execute_action('naabu_scan', host['ip'], {})

    def is_interesting_asset(self, host):
        """Determina se un asset è interessante per la promozione in Neo4j (ora usa anche port, cve, cname_takeover, banner)"""
        interesting_ports = {8000, 8080, 8443, 5000, 5601, 9000, 10000, 3000, 8888}
        keywords = ['jenkins', 'admin', 'login', 'grafana', 'kibana', 'gitlab', 'sonarqube', 'tomcat', 'nginx', 'apache', 'iis', 'exposed', 'test', 'dev']
        port = host.get('port', 80)
        banner = (host.get('banner') or '').lower()
        cve = host.get('cve')
        cname_takeover = host.get('cname_takeover', False)
        reasons = []
        if port in interesting_ports:
            reasons.append(f"porta {port}")
        for kw in keywords:
            if kw in banner:
                reasons.append(f"banner contiene '{kw}'")
        if cve:
            reasons.append(f"CVE {cve}")
        if cname_takeover:
            reasons.append("possibile takeover CNAME")
        return (len(reasons) > 0, reasons)

    def log_audit(self, action_type, asset, motivation, parameters=None):
        """Scrive una riga di audit trail su audit_log.csv"""
        log_path = 'audit_log.csv'
        with open(log_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                action_type,
                asset,
                motivation,
                json.dumps(parameters or {})
            ])

    def run_cycle(self):
        """Esegue i cicli asincroni e triggera LLM solo su asset ad alta priorità, promuovendo asset interessanti in Neo4j"""
        try:
            self.current_cycle += 1
            self.logger.info(f"[CYCLE] Inizio ciclo {self.current_cycle}")
            self.recon_cycle()
            self.probe_cycle()
            self.portscan_cycle()
            # Promozione asset interessanti da SQLite a Neo4j (con batch e rate limiting se necessario)
            unscanned = self.state_manager.get_unscanned_hosts_sqlite()
            promoted_count = 0
            max_promotions = 20  # Rate limit promozioni per ciclo
            for host in unscanned:
                is_interesting, reasons = self.is_interesting_asset(host)
                if is_interesting:
                    motivation = ', '.join(reasons)
                    self.logger.info(f"[PROMOTE] Promuovo asset interessante in Neo4j: {host} | Motivazione: {motivation}")
                    self.state_manager.promote_to_graph(host)
                    self.log_audit('promote_asset', host.get('ip') or host.get('subdomain'), motivation, host)
                    promoted_count += 1
                    if promoted_count >= max_promotions:
                        self.logger.info(f"[PROMOTE] Raggiunto limite promozioni per ciclo ({max_promotions})")
                        break
            # Trigger LLM solo se asset ad alta priorità
            if hasattr(self.state_manager, 'has_high_priority_asset') and self.state_manager.has_high_priority_asset():
                system_state = self.state_manager.get_system_state()
                action_plan = self.llm_planner.plan_next_action(system_state)
                self.logger.info(f"[LLM] Piano generato: {action_plan}")
                if action_plan.get('action') not in ['wait', None]:
                    self.execute_action(
                        action_plan['action'],
                        action_plan['target'],
                        action_plan.get('parameters')
                    )
                    self.log_audit('llm_action', action_plan.get('target'), action_plan.get('action'), action_plan)
                    self.stats['actions_executed'] += 1
                self.last_action = action_plan
            self.stats['cycles_completed'] += 1
            self.logger.info(f"[CYCLE] Ciclo {self.current_cycle} completato")
        except Exception as e:
            self.logger.error(f"Errore nel ciclo {self.current_cycle}: {e}")
            self.stats['errors'] += 1

    def execute_action(self, action: str, target: str, parameters: Dict[str, Any]):
        """Esegue un'azione pianificata"""
        try:
            self.logger.info(f"Esecuzione azione: {action} su {target}")
            if action == 'subfinder':
                self._send_subfinder_task(target, parameters)
            elif action == 'httpx_probe':
                self._send_httpx_task(target, parameters)
            elif action == 'naabu_scan':
                self._send_naabu_task(target, parameters)
            elif action == 'nmap_scan':
                self._send_nmap_task(target, parameters)
            elif action == 'nuclei_scan':
                self._send_nuclei_task(target, parameters)
            elif action == 'msf_exploit':
                self._send_msf_task(target, parameters)
            elif action == 'privesc':
                self._send_privesc_task(target, parameters)
            elif action == 'analyze':
                self._analyze_target(target)
            else:
                self.logger.warning(f"Azione non riconosciuta: {action}")
        except Exception as e:
            self.logger.error(f"Errore nell'esecuzione azione {action}: {e}")

    def _send_subfinder_task(self, target: str, parameters: Dict[str, Any]):
        """Invia task subfinder a RabbitMQ"""
        task = {
            'domain': target,
            'task_id': parameters.get('task_id', str(uuid.uuid4())),
            'timestamp': datetime.now().isoformat(),
            'orchestrator_cycle': self.current_cycle
        }
        self.channel.basic_publish(
            exchange='',
            routing_key='subfinder_tasks',
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        self.logger.info(f"Task subfinder inviato per {target} con parametri: {task}")

    def _send_httpx_task(self, target: str, parameters: Dict[str, Any]):
        """Invia task httpx a RabbitMQ"""
        task = {
            'target': target,
            'task_id': parameters.get('task_id', str(uuid.uuid4())),
            'timestamp': datetime.now().isoformat(),
            'orchestrator_cycle': self.current_cycle
        }
        self.channel.basic_publish(
            exchange='',
            routing_key='httpx_tasks',
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        self.logger.info(f"Task httpx inviato per {target} con parametri: {task}")

    def _send_naabu_task(self, target: str, parameters: Dict[str, Any]):
        """Invia task naabu a RabbitMQ"""
        task = {
            'target': target,
            'task_id': parameters.get('task_id', str(uuid.uuid4())),
            'timestamp': datetime.now().isoformat(),
            'orchestrator_cycle': self.current_cycle
        }
        self.channel.basic_publish(
            exchange='',
            routing_key='naabu_tasks',
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        self.logger.info(f"Task naabu inviato per {target} con parametri: {task}")

    def _send_nmap_task(self, target: str, parameters: Dict[str, Any]):
        """Invia task nmap a RabbitMQ"""
        task = {
            'target': target,
            'ports': parameters.get('ports', '1-100'),
            'scan_type': parameters.get('scan_type', 'fast'),
            'nmap_args': parameters.get('nmap_args', ''),
            'timestamp': datetime.now().isoformat(),
            'orchestrator_cycle': self.current_cycle
        }
        self.channel.basic_publish(
            exchange='',
            routing_key='nmap_tasks',
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        self.logger.info(f"Task nmap inviato per {target} con parametri: {task}")

    def _send_nuclei_task(self, target: str, parameters: Dict[str, Any]):
        """Invia task nuclei a RabbitMQ"""
        task = {
            'target': target,
            'templates': parameters.get('templates', 'cves,defaults'),
            'severity': parameters.get('severity', 'medium,high,critical'),
            'timestamp': datetime.now().isoformat(),
            'orchestrator_cycle': self.current_cycle
        }
        self.channel.basic_publish(
            exchange='',
            routing_key='nuclei_tasks',
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        self.logger.info(f"Task nuclei inviato per {target} con parametri: {task}")
    
    def _analyze_target(self, target: str):
        """Analizza i risultati di un target"""
        try:
            target_details = self.state_manager.get_target_details(target)
            if target_details:
                analysis = self.llm_planner.analyze_results(target_details)
                self.logger.info(f"Analisi target {target}: {analysis}")
                
                # Esegui le raccomandazioni
                for rec in analysis.get('recommendations', []):
                    self.execute_action(
                        rec['action'],
                        rec['target'],
                        rec.get('parameters')
                    )
            else:
                self.logger.warning(f"Nessun dettaglio trovato per target {target}")
                
        except Exception as e:
            self.logger.error(f"Errore nell'analisi target {target}: {e}")
    
    def _send_msf_task(self, target: str, parameters: Dict[str, Any]):
        """Invia task Metasploit a RabbitMQ"""
        task = {
            'target': target,
            'exploit': parameters.get('exploit'),
            'payload': parameters.get('payload', 'windows/meterpreter/reverse_tcp'),
            'lhost': parameters.get('lhost', '127.0.0.1'),
            'lport': parameters.get('lport', '4444'),
            'options': parameters.get('options', {}),
            'timestamp': datetime.now().isoformat(),
            'orchestrator_cycle': self.current_cycle
        }
        self.channel.basic_publish(
            exchange='',
            routing_key='msf_tasks',
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        self.logger.info(f"Task Metasploit inviato per {target} con parametri: {task}")
    
    def _send_privesc_task(self, target: str, parameters: Dict[str, Any]):
        """Invia task privesc a RabbitMQ"""
        task = {
            'shell_id': parameters.get('shell_id'),
            'script': parameters.get('script', 'linpeas'),  # default linpeas
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'orchestrator_cycle': self.current_cycle
        }
        self.channel.basic_publish(
            exchange='',
            routing_key='privesc_tasks',
            body=json.dumps(task),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        self.logger.info(f"Task privesc inviato per {target} con parametri: {task}")
    
    def _run_flask(self):
        """Avvia Flask in thread separato"""
        self.app.run(host='0.0.0.0', port=51, debug=False)
    
    def _event_loop(self):
        """Ascolta la coda 'orchestrator_results' e triggera run_cycle() su nuovi messaggi."""
        self.logger.info("Avvio event loop RabbitMQ su 'orchestrator_results'")
        def callback(ch, method, properties, body):
            try:
                self.logger.info("Nuovo messaggio su orchestrator_results: aggiorno stato e triggero run_cycle()")
                result = json.loads(body)
                if self.state_manager:
                    self.state_manager.process_result_message(result)
                else:
                    self.logger.warning("StateManager non inizializzato, impossibile aggiornare stato.")
            except Exception as e:
                self.logger.error(f"Errore nel parsing/aggiornamento risultato: {e}")
            self.run_cycle()
        try:
            self.channel.basic_consume(queue='orchestrator_results', on_message_callback=callback, auto_ack=True)
            self.channel.start_consuming()
        except Exception as e:
            self.logger.error(f"Errore nell'event loop RabbitMQ: {e}")
    
    def stop(self):
        """Arresta l'orchestrator"""
        self.logger.info("Arresto Orchestrator V2...")
        self.is_running = False
        
        if self.state_manager:
            self.state_manager.close()
        
        if self.llm_planner:
            self.llm_planner.close()
            
        if self.connection and not self.connection.is_closed:
            self.connection.close()
            
        self.logger.info("Orchestrator V2 arrestato")

if __name__ == "__main__":
    orchestrator = OrchestratorV2()
    orchestrator.start() 