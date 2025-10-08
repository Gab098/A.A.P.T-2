import os
import shutil
from datetime import datetime
import subprocess

BACKUP_DIR = os.getenv('AAPT_BACKUP_DIR', './backups')
SQLITE_PATH = os.getenv('AAPT_SQLITE_PATH', './recon.db')
NEO4J_HOST = os.getenv('NEO4J_HOST', 'localhost')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')

os.makedirs(BACKUP_DIR, exist_ok=True)

def backup_sqlite():
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    dest = os.path.join(BACKUP_DIR, f'recon_{ts}.db')
    shutil.copy2(SQLITE_PATH, dest)
    print(f'[BACKUP] SQLite backup creato: {dest}')

def backup_neo4j():
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    dest = os.path.join(BACKUP_DIR, f'neo4j_{ts}.dump')
    # Usa cypher-shell per esportare tutto il db
    cmd = f"cypher-shell -u {NEO4J_USER} -p {NEO4J_PASS} -a bolt://{NEO4J_HOST}:7687 'CALL apoc.export.cypher.all(\"{dest}\", {{format: \"plain\"}})'"
    print(f'[BACKUP] Eseguo backup Neo4j: {cmd}')
    subprocess.run(cmd, shell=True, check=False)
    print(f'[BACKUP] Neo4j backup creato: {dest}')

def restore_sqlite(backup_file):
    shutil.copy2(backup_file, SQLITE_PATH)
    print(f'[RESTORE] SQLite ripristinato da: {backup_file}')

def restore_neo4j(dump_file):
    # Usa cypher-shell per importare il dump
    cmd = f"cypher-shell -u {NEO4J_USER} -p {NEO4J_PASS} -a bolt://{NEO4J_HOST}:7687 -f {dump_file}"
    print(f'[RESTORE] Eseguo restore Neo4j: {cmd}')
    subprocess.run(cmd, shell=True, check=False)
    print(f'[RESTORE] Neo4j ripristinato da: {dump_file}')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Backup/Restore AAPT (SQLite & Neo4j)')
    parser.add_argument('--backup', action='store_true', help='Esegui backup')
    parser.add_argument('--restore_sqlite', type=str, help='Ripristina SQLite da file')
    parser.add_argument('--restore_neo4j', type=str, help='Ripristina Neo4j da dump')
    args = parser.parse_args()
    if args.backup:
        backup_sqlite()
        backup_neo4j()
    if args.restore_sqlite:
        restore_sqlite(args.restore_sqlite)
    if args.restore_neo4j:
        restore_neo4j(args.restore_neo4j) 