import os
import logging
from datetime import datetime, timedelta
from neo4j import GraphDatabase

NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
DAYS_INACTIVE = int(os.getenv('AAPT_CLEANUP_DAYS', '7'))

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("neo4j_cleanup")

def cleanup_neo4j():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    cutoff = (datetime.utcnow() - timedelta(days=DAYS_INACTIVE)).isoformat()
    with driver.session() as session:
        # Rimuovi host non più attivi (non visti/probati da X giorni)
        logger.info(f"[CLEANUP] Rimozione host non attivi da più di {DAYS_INACTIVE} giorni...")
        result = session.run("""
            MATCH (h:Host)
            WHERE h.last_seen < $cutoff
            DETACH DELETE h
            RETURN count(h) as removed
        """, cutoff=cutoff)
        removed = result.single()["removed"]
        logger.info(f"[CLEANUP] Host rimossi: {removed}")
        # Rimuovi findings/shell vecchi
        logger.info("[CLEANUP] Rimozione findings/shell/vuln vecchi...")
        session.run("""
            MATCH (f:Finding)
            WHERE f.last_seen < $cutoff
            DETACH DELETE f
        """, cutoff=cutoff)
        session.run("""
            MATCH (s:Shell)
            WHERE s.last_seen < $cutoff
            DETACH DELETE s
        """, cutoff=cutoff)
        session.run("""
            MATCH (v:Vulnerability)
            WHERE v.last_seen < $cutoff
            DETACH DELETE v
        """, cutoff=cutoff)
        # Rimuovi host non più "interessanti" (no findings, no vuln, no shell, no relazioni attive)
        logger.info("[CLEANUP] Rimozione host non più interessanti...")
        result = session.run("""
            MATCH (h:Host)
            WHERE NOT (h)-[:HAS_FINDING|:IS_VULNERABLE_TO|:HAS_SHELL|:RUNS_SERVICE|:EXPOSES|:HAS_TECH|:SCANNED_BY|:PROBED_BY]->()
            DETACH DELETE h
            RETURN count(h) as removed
        """)
        logger.info(f"[CLEANUP] Host orfani rimossi: {result.single()['removed']}")

        logger.info("[CLEANUP] Rimozione vulnerabilità orfane...")
        result = session.run("""
            MATCH (v:Vulnerability)
            WHERE NOT ()-[:IS_VULNERABLE_TO]->(v)
            DETACH DELETE v
            RETURN count(v) as removed
        """)
        logger.info(f"[CLEANUP] Vulnerabilità orfane rimosse: {result.single()['removed']}")
        # Rimuovi relazioni orfane
        logger.info("[CLEANUP] Rimozione relazioni orfane...")
        session.run("""
            MATCH ()-[r]-() WHERE NOT exists(r) DETACH DELETE r
        """)
    driver.close()
    logger.info("[CLEANUP] Pulizia completata.")

if __name__ == '__main__':
    cleanup_neo4j() 