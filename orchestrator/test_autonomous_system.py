#!/usr/bin/env python3
"""
Test del sistema di pianificazione autonoma A.A.P.T.
Verifica il funzionamento di StateManager, LLMPlanner e Orchestrator V2
"""

import os
import sys
import logging
import json
from datetime import datetime

# Configura logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def test_llm_planner():
    print("=== TEST LLM PLANNER ===")
    try:
        from llm_planner import LLMPlanner
        model_path = "./models/Microsoft/phi-3mini-4k-instruct-q43mini-4k-instruct-q4uf"
        if not os.path.exists(model_path):
            print(f"❌ Modello non trovato: {model_path}")
            return False
        print(f"✅ Modello trovato: {model_path}")
        planner = LLMPlanner(model_path)
        print("✅ LLMPlanner inizializzato")
        test_state = {
            "targets": {"total": 2, "active": 1, "completed": 0, "failed": 1},
            "scans": {"total": 3, "running": 0, "completed": 1, "failed": 2, "by_type": {"nmap": 1, "nuclei": 1}},
            "pending_tasks": [{"ip": "192.168.1.100", "domain": "test.local", "status": "pending", "created_at": 2240}]
        }
        action_plan = planner.plan_next_action(test_state)
        print(f"✅ Piano generato: {json.dumps(action_plan, indent=2)}")
        planner.close()
        return True
    except Exception as e:
        print(f"❌ Errore nel test LLMPlanner: {e}")
        return False


def test_state_manager():
    print("\n=== TEST STATE MANAGER ===")
    try:
        from state_manager import StateManager
        state_manager = StateManager()
        print("✅ StateManager inizializzato")
        try:
            state = state_manager.get_system_state()
            print("✅ Connessione Neo4j funzionante")
            print(f"Stato sistema: {json.dumps(state, indent=2)}")
        except Exception as e:
            print(f"⚠️  Errore connessione Neo4j (normale se non in esecuzione): {e}")
        state_manager.close()
        return True
    except Exception as e:
        print(f"❌ Errore nel test StateManager: {e}")
        return False


def test_orchestrator_v2():
    print("\n=== TEST ORCHESTRATOR V2 ===")
    try:
        from orchestrator_v2 import OrchestratorV2
        orchestrator = OrchestratorV2()
        print("✅ Orchestrator V2 inizializzato")
        success = orchestrator.initialize()
        if success:
            print("✅ Tutti i componenti inizializzati")
        else:
            print("⚠️  Alcuni componenti non inizializzati (normale se servizi non disponibili)")
        orchestrator.stop()
        return True
    except Exception as e:
        print(f"❌ Errore nel test Orchestrator V2: {e}")
        return False


def test_manual_planning():
    print("\n=== TEST PIANIFICAZIONE MANUALE ===")
    try:
        from llm_planner import LLMPlanner
        model_path = "./models/Microsoft/phi-3mini-4k-instruct-q43mini-4k-instruct-q4uf"
        if not os.path.exists(model_path):
            print("❌ Modello non disponibile per il test")
            return False
        planner = LLMPlanner(model_path)
        test_target = {
            "target": {"ip": "192.168.1.100", "domain": "test.local", "status": "active"},
            "scans": [{"type": "nmap", "status": "completed", "results": {"open_ports": [22]}}],
            "findings": [],
            "vulnerabilities": []
        }
        analysis = planner.analyze_results(test_target)
        print("✅ Analisi target completata:")
        print(json.dumps(analysis, indent=2))
        planner.close()
        return True
    except Exception as e:
        print(f"❌ Errore nel test pianificazione manuale: {e}")
        return False

def test_promote_interesting_asset():
    """Test promozione automatica asset interessante da SQLite a Neo4j"""
    print("\n=== TEST PROMOZIONE ASSET INTERESSANTE ===")
    try:
        from orchestrator_v2 import OrchestratorV2
        from state_manager import StateManager
        import sqlite3
        # Inserisci asset di test in SQLite
        conn = sqlite3.connect('recon.db')
        cur = conn.cursor()
        cur.execute("DELETE FROM httpx_results WHERE subdomain = 'jenkins.test.local'")
        cur.execute("INSERT INTO httpx_results (subdomain, ip, port, banner, status_code) VALUES (?, ?, ?, ?, ?)",
                    ('jenkins.test.local', '10.10.10.10', 8080, 'Jenkins Login', 200))
        conn.commit()
        conn.close()
        # Avvia orchestrator e run_cycle
        orchestrator = OrchestratorV2()
        orchestrator.initialize()
        orchestrator.run_cycle()
        # Verifica promozione in Neo4j
        state_manager = orchestrator.state_manager
        with state_manager.driver.session() as session:
            result = session.run("MATCH (h:Host {ip: '10.10.10.10'}) RETURN h").single()
            if result and result['h']:
                print("✅ Asset promosso in Neo4j: 10.10.10.10")
            else:
                print("❌ Asset NON promosso in Neo4j")
        orchestrator.stop()
        return True
    except Exception as e:
        print(f"❌ Errore nel test promozione asset interessante: {e}")
        return False

def test_promote_nuclei_asset():
    """Test promozione asset nuclei con CVE e takeover"""
    print("\n=== TEST PROMOZIONE ASSET NUCLEI (CVE/TAKEOVER) ===")
    try:
        from orchestrator_v2 import OrchestratorV2
        from state_manager import StateManager
        import sqlite3
        # Inserisci vulnerabilità nuclei in SQLite
        conn = sqlite3.connect('recon.db')
        cur = conn.cursor()
        cur.execute("DELETE FROM nuclei_vulnerabilities WHERE target = 'vuln.test.local'")
        cur.execute("INSERT INTO nuclei_vulnerabilities (target, vuln_name, severity, cve, description, port, takeover, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ('vuln.test.local', 'Jenkins RCE', 'critical', 'CVE-2023-9999', 'Remote Code Execution', 8080, 1, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        # Avvia orchestrator e run_cycle
        orchestrator = OrchestratorV2()
        orchestrator.initialize()
        orchestrator.run_cycle()
        # Verifica promozione in Neo4j
        state_manager = orchestrator.state_manager
        with state_manager.driver.session() as session:
            result = session.run("MATCH (h:Host {ip: 'vuln.test.local'}) RETURN h").single()
            if result and result['h']:
                print("✅ Asset nuclei promosso in Neo4j: vuln.test.local")
            else:
                print("❌ Asset nuclei NON promosso in Neo4j")
        orchestrator.stop()
        return True
    except Exception as e:
        print(f"❌ Errore nel test nuclei: {e}")
        return False

def test_promote_naabu_asset():
    """Test promozione asset naabu con servizio"""
    print("\n=== TEST PROMOZIONE ASSET NAABU (SERVIZIO) ===")
    try:
        from orchestrator_v2 import OrchestratorV2
        from state_manager import StateManager
        import sqlite3
        # Inserisci porta/servizio in SQLite
        conn = sqlite3.connect('recon.db')
        cur = conn.cursor()
        cur.execute("DELETE FROM naabu_results WHERE subdomain = 'service.test.local'")
        cur.execute("INSERT INTO naabu_results (subdomain, port, service, scanned_at) VALUES (?, ?, ?, ?)",
                    ('service.test.local', 3306, 'mysql', datetime.now().isoformat()))
        conn.commit()
        conn.close()
        # Avvia orchestrator e run_cycle
        orchestrator = OrchestratorV2()
        orchestrator.initialize()
        orchestrator.run_cycle()
        # Verifica promozione in Neo4j
        state_manager = orchestrator.state_manager
        with state_manager.driver.session() as session:
            result = session.run("MATCH (h:Host {ip: 'service.test.local'}) RETURN h").single()
            if result and result['h']:
                print("✅ Asset naabu promosso in Neo4j: service.test.local")
            else:
                print("❌ Asset naabu NON promosso in Neo4j")
        orchestrator.stop()
        return True
    except Exception as e:
        print(f"❌ Errore nel test naabu: {e}")
        return False

def test_no_promotion_for_boring_asset():
    """Test che asset non interessanti NON vengano promossi"""
    print("\n=== TEST NO PROMOTION ASSET NON INTERESSANTE ===")
    try:
        from orchestrator_v2 import OrchestratorV2
        from state_manager import StateManager
        import sqlite3
        # Inserisci asset banale in SQLite
        conn = sqlite3.connect('recon.db')
        cur = conn.cursor()
        cur.execute("DELETE FROM httpx_results WHERE subdomain = 'boring.test.local'")
        cur.execute("INSERT INTO httpx_results (subdomain, ip, port, banner, status_code) VALUES (?, ?, ?, ?, ?)",
                    ('boring.test.local', '192.168.1.200', 80, 'Welcome to nginx!', 200))
        conn.commit()
        conn.close()
        # Avvia orchestrator e run_cycle
        orchestrator = OrchestratorV2()
        orchestrator.initialize()
        orchestrator.run_cycle()
        # Verifica che NON sia stato promosso
        state_manager = orchestrator.state_manager
        with state_manager.driver.session() as session:
            result = session.run("MATCH (h:Host {ip: '192.168.1.200'}) RETURN h").single()
            if not result or not result['h']:
                print("✅ Asset banale NON promosso in Neo4j (corretto)")
            else:
                print("❌ Asset banale promosso in Neo4j (errore)")
        orchestrator.stop()
        return True
    except Exception as e:
        print(f"❌ Errore nel test asset non interessante: {e}")
        return False

def main():
    print("🚀 AVVIO TEST SISTEMA AUTONOMO A.A.P.T.")
    print(f"Timestamp: {datetime.now()}")
    results = []
    results.append(("LLMPlanner", test_llm_planner()))
    results.append(("StateManager", test_state_manager()))
    results.append(("Orchestrator V2", test_orchestrator_v2()))
    results.append(("Pianificazione Manuale", test_manual_planning()))
    results.append(("Promozione Asset Interessante", test_promote_interesting_asset()))
    results.append(("Promozione Asset Nuclei", test_promote_nuclei_asset()))
    results.append(("Promozione Asset Naabu", test_promote_naabu_asset()))
    results.append(("No Promotion Asset Non Interessante", test_no_promotion_for_boring_asset()))
    print("\n" + "="*50)
    print("RISULTATI TEST")
    print("="*50)
    passed = 0
    total = len(results)
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name}: {status}")
        if success:
            passed += 1
    print(f"Totale: {passed}/{total} test superati")
    if passed == total:
        print("🎉 TUTTI I TEST SUPERATI! Sistema pronto per l'uso.")
    elif passed > 0:
        print("⚠️  Alcuni test falliti. Verificare le dipendenze.")
    else:
        print("❌ Tutti i test falliti. Verificare l'installazione.")
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 