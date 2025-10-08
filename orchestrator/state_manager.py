import logging
from typing import Dict, List, Optional, Any
from neo4j import GraphDatabase
import json
from datetime import datetime, timedelta
import sqlite3

class StateManager:
    """
    Gestisce lo stato del sistema interrogando Neo4j e fornendo
    un riassunto strutturato per il planner LLM
    """
    def __init__(self, neo4j_uri: str = "bolt://neo4j:7687", username: str = "neo4j", password: str = "password"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(username, password))
        self.logger = logging.getLogger(__name__)
        self._cache = None
        self._cache_time = 0
        
    def close(self):
        """Chiude la connessione a Neo4j"""
        if self.driver:
            self.driver.close()
    
    def get_system_state(self, limit=50) -> Dict[str, Any]:
        """Ottiene un riassunto completo dello stato del sistema, con caching di 15s. Include campi per pipeline passiva. Usa paginazione/limite per performance."""
        import time
        now = time.time()
        if self._cache and (now - self._cache_time < 15):
            return self._cache
        try:
            with self.driver.session() as session:
                state = {
                    'targets': self._get_targets_summary(session),
                    'scans': self._get_scans_summary(session),
                    'findings': self._get_findings_summary(session),
                    'vulnerabilities': self._get_vulnerabilities_summary(session),
                    'recent_activity': self._get_recent_activity(session),
                    'system_health': self._get_system_health(session)
                }
                # --- Ricognizione passiva: nuovi subdomini mai probati ---
                new_subdomains = []
                query = f"""
                MATCH (s:Subdomain)
                WHERE NOT (s)-[:PROBED_BY]->(:HttpxProbe)
                RETURN s.name as name
                LIMIT {limit}
                """
                for record in session.run(query):
                    new_subdomains.append(record['name'])
                state['new_subdomains'] = new_subdomains
                # --- Asset attivi non ancora scansionati da naabu ---
                active_targets = []
                query = f"""
                MATCH (h:Host)
                WHERE h.state = 'active' AND NOT (h)-[:SCANNED_BY]->(:NaabuScan)
                RETURN h.ip as ip, h.domain as domain
                LIMIT {limit}
                """
                for record in session.run(query):
                    active_targets.append({'ip': record['ip'], 'domain': record.get('domain')})
                state['active_targets'] = active_targets
                # --- Asset interessanti per nuclei mirato ---
                interesting_assets = []
                query = f"""
                MATCH (h:Host)-[:HAS_TECH]->(t:Tech)
                WHERE t.cve IS NOT NULL OR t.banner =~ '.*(Apache|Jenkins|Tomcat|nginx|IIS).*' OR t.cname_takeover = true
                RETURN h.ip as ip, t.name as tech, t.cve as cve, t.banner as banner
                LIMIT {limit}
                """
                for record in session.run(query):
                    interesting_assets.append({
                        'ip': record['ip'],
                        'tech': record['tech'],
                        'cve': record['cve'],
                        'banner': record['banner'],
                        'should_nuclei': True,
                        'suggested_templates': record['cve'] if record['cve'] else ''
                    })
                state['interesting_assets'] = interesting_assets
                # --- Asset anomali (takeover, banner strani, errori) ---
                anomalous_assets = []
                query = f"""
                MATCH (h:Host)-[:HAS_TECH]->(t:Tech)
                WHERE t.cname_takeover = true OR t.banner =~ '.*(error|forbidden|unauthorized|exposed|test|dev).*'
                RETURN h.ip as ip, t.name as tech, t.banner as banner, t.port as port, t.cve as cve, t.cname_takeover as cname_takeover, t.service as service
                LIMIT {limit}
                """
                for record in session.run(query):
                    anomalous_assets.append({
                        'ip': record['ip'],
                        'tech': record['tech'],
                        'banner': record['banner'],
                        'port': record.get('port', 80),
                        'cve': record.get('cve'),
                        'cname_takeover': record.get('cname_takeover', False),
                        'service': record.get('service')
                    })
                state['anomalous_assets'] = anomalous_assets
                self._cache = state
                self._cache_time = now
                return state
        except Exception as e:
            self.logger.error(f"Errore nel recupero dello stato: {e}")
            return {"error": str(e)}
    
    def invalidate_cache(self):
        """Invalida manualmente il cache dello stato di sistema."""
        self._cache = None
        self._cache_time = 0
    
    def _get_targets_summary(self, session) -> Dict[str, Any]:
        """Epilogo dei target nel sistema"""
        query = """
        MATCH (t:Target)
        RETURN count(t) as total_targets,
               count(CASE WHEN t.status = 'active' THEN t END) as active_targets,
               count(CASE WHEN t.status = 'completed' THEN t END) as completed_targets,
               count(CASE WHEN t.status = 'failed' THEN t END) as failed_targets
        """
        result = session.run(query).single()
        return {
            "total": result["total_targets"],
            "active": result["active_targets"],
            "completed": result["completed_targets"],
            "failed": result["failed_targets"]
        }
    
    def _get_scans_summary(self, session) -> Dict[str, Any]:
        """Epilogo degli scan nel sistema"""
        query = """
        MATCH (s:Scan)
        RETURN count(s) as total_scans,
               count(CASE WHEN s.status = 'running' THEN s END) as running_scans,
               count(CASE WHEN s.status = 'completed' THEN s END) as completed_scans,
               count(CASE WHEN s.status = 'failed' THEN s END) as failed_scans,
               count(CASE WHEN s.type = 'nmap' THEN s END) as nmap_scans,
               count(CASE WHEN s.type = 'nuclei' THEN s END) as nuclei_scans
        """
        result = session.run(query).single()
        return {
            "total": result["total_scans"],
            "running": result["running_scans"],
            "completed": result["completed_scans"],
            "failed": result["failed_scans"],
            "by_type": {
                "nmap": result["nmap_scans"],
                "nuclei": result["nuclei_scans"]
            }
        }
    
    def _get_findings_summary(self, session) -> Dict[str, Any]:
        """alogo dei findings"""
        query = """
        MATCH (f:Finding)
        RETURN count(f) as total_findings,
               count(CASE WHEN f.severity = 'critical' THEN f END) as critical_findings,
               count(CASE WHEN f.severity = 'high' THEN f END) as high_findings,
               count(CASE WHEN f.severity = 'medium' THEN f END) as medium_findings,
               count(CASE WHEN f.severity = 'low' THEN f END) as low_findings
        """
        result = session.run(query).single()
        return {
            "total": result["total_findings"],
            "by_severity": {
                "critical": result["critical_findings"],
                "high": result["high_findings"],
                "medium": result["medium_findings"],
                "low": result["low_findings"]
            }
        }
    
    def _get_vulnerabilities_summary(self, session) -> Dict[str, Any]:
        """alogo delle vulnerabilità"""
        query = """
        MATCH (v:Vulnerability)
        RETURN count(v) as total_vulns,
               count(CASE WHEN v.severity = 'critical' THEN v END) as critical_vulns,
               count(CASE WHEN v.severity = 'high' THEN v END) as high_vulns,
               count(CASE WHEN v.severity = 'medium' THEN v END) as medium_vulns,
               count(CASE WHEN v.severity = 'low' THEN v END) as low_vulns
        """
        result = session.run(query).single()
        return {
            "total": result["total_vulns"],
            "by_severity": {
                "critical": result["critical_vulns"],
                "high": result["high_vulns"],
                "medium": result["medium_vulns"],
                "low": result["low_vulns"]
            }
        }
    
    def _get_recent_activity(self, session) -> List[Dict[str, Any]]:
        """Attività recenti (ultime 24)"""
        query = """
        MATCH (s:Scan)
        WHERE s.timestamp > datetime() - duration({hours: 24})
        RETURN s.type as type, s.status as status, s.target as target, s.timestamp as timestamp
        ORDER BY s.timestamp DESC
        LIMIT 10
        """
 
        results = session.run(query)
        activities = []
        for record in results:
            activities.append({
              "type": record["type"],
                "status": record["status"],
                "target": record["target"],
               "timestamp": str(record["timestamp"])
            })
        return activities
    
    def _get_system_health(self, session) -> Dict[str, Any]:
        """Salute del sistema"""
        query = """
        MATCH (s:Scan)
        WHERE s.timestamp > datetime() - duration({hours: 1})
        RETURN count(s) as recent_scans,
               count(CASE WHEN s.status = 'failed' THEN s END) as recent_failures
        """
        
        result = session.run(query).single()
        
        # Calcola il tasso di successo
        recent_scans = result["recent_scans"] if result else 0
        recent_failures = result["recent_failures"] if result else 0
        success_rate = 0 if recent_scans == 0 else ((recent_scans - recent_failures) / recent_scans) * 100   
        return {
            "recent_scans": recent_scans,
            "recent_failures": recent_failures,
            "success_rate": round(success_rate, 2),
            "status": "healthy" if success_rate > 80 else "degraded" if success_rate > 50 else "unhealthy"
        }
    
    def get_pending_tasks(self) -> List[Dict[str, Any]]:
        """Ottiene i task in attesa di esecuzione"""
        try:
            with self.driver.session() as session:
                query = """
                MATCH (t:Target)
                WHERE t.status = 'active' OR t.status = 'pending'
                RETURN t.ip as ip, t.domain as domain, t.status as status, t.created_at as created_at
                ORDER BY t.created_at ASC
                """
                results = session.run(query)
                tasks = []
                for record in results:
                    tasks.append({
                      "ip": record["ip"],
                        "domain": record["domain"],
                        "status": record["status"],
                        "created_at": str(record["created_at"])
                    })
                return tasks
        except Exception as e:
            self.logger.error(f"Errore nel recupero dei task pendenti: {e}")
            return []
    
    def get_target_details(self, target_ip: str) -> Optional[Dict[str, Any]]:
        """Dettagli specifici di un target"""
        try:
            with self.driver.session() as session:
                query = """
                MATCH (t:Target {ip: $ip})
                OPTIONAL MATCH (t)-[:HAS_SCAN]->(s:Scan)
                OPTIONAL MATCH (s)-[:FOUND]->(f:Finding)
                OPTIONAL MATCH (s)-[:DETECTED]->(v:Vulnerability)
                RETURN t, 
                       collect(DISTINCT s) as scans,
                       collect(DISTINCT f) as findings,
                       collect(DISTINCT v) as vulnerabilities,
                       t.threat_intelligence as threat_intelligence,
                       t.access_level as access_level,
                       t.compromised_status as compromised_status
                """
                result = session.run(query, ip=target_ip).single()
                if result:
                    return {
                        "target": dict(result["t"]),
                        "scans": [dict(scan) for scan in result["scans"]],
                        "findings": [dict(finding) for finding in result["findings"]],
                        "vulnerabilities": [dict(vuln) for vuln in result["vulnerabilities"]],
                        "threat_intelligence": result["threat_intelligence"],
                        "access_level": result["access_level"],
                        "compromised_status": result["compromised_status"]
                    }
                return None
        except Exception as e:
            self.logger.error(f"Errore nel recupero dettagli target {target_ip}: {e}")
            return None

    def process_result_message(self, result: dict):
        """
        Interpreta un messaggio di risultato standard e aggiorna il grafo Neo4j.
        Questa è la funzione che traduce i risultati in conoscenza.
        """
        worker_type = result.get('worker_type')
        target = result.get('target')
        data = result.get('data', {})
        if not worker_type or not target:
            self.logger.warning(f"Messaggio risultato senza worker_type o target: {result}")
            return
        try:
            with self.driver.session() as session:
                # --- Logica per Nmap ---
                if worker_type == 'nmap_worker' and data.get('open_ports'):
                    for port_info in data['open_ports']:
                        session.run("""
                            MERGE (h:Host {ip: $ip})
                            MERGE (s:Service {port: $port, protocol: $protocol})
                            ON CREATE SET s.name = $service_name, s.version = $version
                            SET s.last_seen = $timestamp
                            MERGE (h)-[:RUNS_SERVICE]->(s)
                        """,
                        ip=target,
                        port=port_info['port'],
                        protocol=port_info['protocol'],
                        service_name=port_info['service'],
                        version=port_info.get('version', ''),
                        timestamp=result.get('timestamp'))
                # --- Logica per Nuclei ---
                elif worker_type == 'nuclei_worker' and data.get('vulnerabilities_found'):
                    for vuln in data['vulnerabilities_found']:
                        session.run("""
                            MATCH (h:Host {ip: $ip})
                            MERGE (v:Vulnerability {name: $name})
                            ON CREATE SET v.severity = $severity, v.cve = $cve
                            SET v.last_seen = $timestamp
                            MERGE (h)-[:IS_VULNERABLE_TO]->(v)
                        """,
                        ip=target,
                        name=vuln['name'],
                        severity=vuln['severity'],
                        cve=vuln.get('cve', 'N/A'),
                        timestamp=result.get('timestamp'))
                # --- Logica per Metasploit ---
                elif worker_type == 'msf_worker' and data.get('exploit_successful'):
                    shell_info = data.get('shell_obtained')
                    if shell_info:
                        session.run("""
                            MATCH (h:Host {ip: $ip})
                            MERGE (s:Shell {id: $shell_id})
                            ON CREATE SET s.access_level = $access_level, s.os = $os
                            SET s.last_seen = $timestamp
                            MERGE (h)-[:HAS_SHELL]->(s)
                        """,
                        ip=target,
                        shell_id=shell_info['shell_id'],
                        access_level=shell_info['access_level'],
                        os=shell_info['os'],
                        timestamp=result.get('timestamp'))
                # --- Logica per Privesc ---
                elif worker_type == 'privesc_worker' and data.get('findings'):
                    for finding in data['findings']:
                        session.run("""
                            MATCH (h:Host {ip: $ip})
                            MERGE (f:Finding {description: $desc})
                            ON CREATE SET f.type = $type, f.suggestion = $suggestion
                            SET f.last_seen = $timestamp
                            MERGE (h)-[:HAS_FINDING]->(f)
                        """,
                        ip=target,
                        desc=finding['description'],
                        type=finding['type'],
                        suggestion=finding.get('exploit_suggestion', ''),
                        timestamp=result.get('timestamp'))
                # --- Logica per Threat Intelligence Worker ---
                elif worker_type == 'threat_intel_worker' and data.get('threat_intelligence'):
                    threat_intel_data = data['threat_intelligence']
                    session.run("""
                        MERGE (h:Host {ip: $ip})
                        SET h.threat_intelligence = $threat_intel_data,
                            h.threat_intel_last_updated = $timestamp
                    """,
                    ip=target,
                    threat_intel_data=json.dumps(threat_intel_data), # Store as JSON string
                    timestamp=result.get('timestamp'))
                # --- Logica per Exploit Adaptation Worker ---
                elif worker_type == 'exploit_adaptation_worker' and data.get('exploit_chain_step'):
                    exploit_step_data = data['exploit_chain_step']
                    exploit_successful = exploit_step_data.get('exploit_successful', False)
                    access_level = exploit_step_data.get('exploit_details', {}).get('access_level')

                    if exploit_successful:
                        session.run("""
                            MERGE (h:Host {ip: $ip})
                            SET h.compromised_status = TRUE,
                                h.access_level = $access_level,
                                h.last_compromised = $timestamp
                            MERGE (e:ExploitAttempt {task_id: $task_id})
                            ON CREATE SET e.exploit_module = $exploit_module,
                                          e.payload = $payload,
                                          e.timestamp = $timestamp,
                                          e.status = 'success'
                            MERGE (h)-[:COMPROMISED_BY]->(e)
                        """,
                        ip=target,
                        access_level=access_level,
                        timestamp=result.get('timestamp'),
                        task_id=result.get('task_id'),
                        exploit_module=exploit_step_data.get('exploit_details', {}).get('exploit_module'),
                        payload=exploit_step_data.get('exploit_details', {}).get('payload'))
                    else:
                        session.run("""
                            MERGE (h:Host {ip: $ip})
                            MERGE (e:ExploitAttempt {task_id: $task_id})
                            ON CREATE SET e.exploit_module = $exploit_module,
                                          e.payload = $payload,
                                          e.timestamp = $timestamp,
                                          e.status = 'failure',
                                          e.reason = $reason
                            MERGE (h)-[:ATTEMPTED_EXPLOIT]->(e)
                        """,
                        ip=target,
                        timestamp=result.get('timestamp'),
                        task_id=result.get('task_id'),
                        exploit_module=exploit_step_data.get('exploit_details', {}).get('exploit_module'),
                        payload=exploit_step_data.get('exploit_details', {}).get('payload'),
                        reason=exploit_step_data.get('exploit_details', {}).get('reason'))
                else:
                    self.logger.info(f"Risultato worker_type={worker_type} ignorato o senza dati rilevanti.")
        except Exception as e:
            self.logger.error(f"Errore in process_result_message: {e}", exc_info=True)
        self.invalidate_cache()

    def get_unprobed_subdomains_sqlite(self):
        """Restituisce sottodomini trovati da subfinder che non hanno ancora un risultato httpx (da recon.db)"""
        conn = sqlite3.connect('recon.db')
        cur = conn.cursor()
        cur.execute("""
            SELECT s.subdomain
            FROM subfinder_results s
            LEFT JOIN httpx_results h ON s.subdomain = h.subdomain
            WHERE h.subdomain IS NULL
        """)
        result = [row[0] for row in cur.fetchall()]
        conn.close()
        return result

    def get_unscanned_hosts_sqlite(self):
        """Restituisce host attivi che non hanno ancora un risultato naabu (da recon.db)"""
        conn = sqlite3.connect('recon.db')
        cur = conn.cursor()
        cur.execute("""
            SELECT h.subdomain, h.ip
            FROM httpx_results h
            LEFT JOIN naabu_results n ON h.subdomain = n.subdomain
            WHERE n.subdomain IS NULL AND h.status_code IS NOT NULL
        """)
        result = [{'subdomain': row[0], 'ip': row[1]} for row in cur.fetchall()]
        conn.close()
        return result

    def promote_to_graph(self, target_info):
        """Promuove un asset interessante da SQLite a Neo4j come nodo Host/Service"""
        with self.driver.session() as session:
            session.run("""
                MERGE (h:Host {ip: $ip})
                SET h += $props
                MERGE (s:Service {port: $port, protocol: $proto})
                MERGE (h)-[:RUNS_SERVICE]->(s)
            """,
            ip=target_info['ip'],
            port=target_info.get('port', 80),
            proto=target_info.get('proto', 'tcp'),
            props=target_info) 

    def has_high_priority_asset(self):
        """Ritorna True se esiste almeno un asset con vulnerabilità critica in Neo4j"""
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (h:Host)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
                    WHERE v.severity = 'critical'
                    RETURN h LIMIT 1
                """)
                return result.single() is not None
        except Exception as e:
            self.logger.error(f"Errore in has_high_priority_asset: {e}")
            return False
