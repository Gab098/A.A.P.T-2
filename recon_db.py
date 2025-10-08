import sqlite3
from datetime import datetime

DB_PATH = 'recon.db'

SCHEMA = '''
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    subdomain TEXT,
    discovered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_subdomains_subdomain ON subdomains(subdomain);
CREATE TABLE IF NOT EXISTS httpx_probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain TEXT,
    status_code INTEGER,
    title TEXT,
    tech TEXT,
    server TEXT,
    cname TEXT,
    ip TEXT,
    banner TEXT,
    port INTEGER,
    cve TEXT,
    cname_takeover INTEGER,
    probed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_httpx_probes_subdomain ON httpx_probes(subdomain);
CREATE INDEX IF NOT EXISTS idx_httpx_probes_ip ON httpx_probes(ip);
CREATE INDEX IF NOT EXISTS idx_httpx_probes_port ON httpx_probes(port);
CREATE INDEX IF NOT EXISTS idx_httpx_probes_cve ON httpx_probes(cve);
CREATE TABLE IF NOT EXISTS naabu_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain TEXT,
    port INTEGER,
    service TEXT,
    scanned_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_naabu_results_subdomain ON naabu_results(subdomain);
CREATE INDEX IF NOT EXISTS idx_naabu_results_port ON naabu_results(port);
CREATE TABLE IF NOT EXISTS nuclei_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    vuln_name TEXT,
    severity TEXT,
    cve TEXT,
    description TEXT,
    port INTEGER,
    takeover INTEGER,
    detected_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_nuclei_vuln_target ON nuclei_vulnerabilities(target);
CREATE INDEX IF NOT EXISTS idx_nuclei_vuln_cve ON nuclei_vulnerabilities(cve);
CREATE INDEX IF NOT EXISTS idx_nuclei_vuln_port ON nuclei_vulnerabilities(port);
'''

def get_conn():
    return sqlite3.connect(DB_PATH)

def setup_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)

# --- Inserimento ---
def insert_subdomain(domain, subdomain):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO subdomains (domain, subdomain, discovered_at) VALUES (?, ?, ?)",
            (domain, subdomain, datetime.utcnow().isoformat())
        )
        conn.commit()

def insert_httpx_probe(subdomain, status_code, title, tech, server, cname, ip, banner, port=80, cve=None, cname_takeover=0):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO httpx_probes (subdomain, status_code, title, tech, server, cname, ip, banner, port, cve, cname_takeover, probed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (subdomain, status_code, title, tech, server, cname, ip, banner, port, cve, cname_takeover, datetime.utcnow().isoformat())
        )
        conn.commit()

def insert_naabu_result(subdomain, port, service=None):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO naabu_results (subdomain, port, service, scanned_at) VALUES (?, ?, ?, ?)",
            (subdomain, port, service, datetime.utcnow().isoformat())
        )
        conn.commit()

def insert_nuclei_vulnerability(target, vuln_name, severity, cve, description, port=80, takeover=0):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO nuclei_vulnerabilities (target, vuln_name, severity, cve, description, port, takeover, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (target, vuln_name, severity, cve, description, port, takeover, datetime.utcnow().isoformat())
        )
        conn.commit()

# --- Query asset attivi/interessanti ---
def get_active_assets():
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT DISTINCT subdomain FROM httpx_probes WHERE status_code BETWEEN 200 AND 499"
        )
        return [row[0] for row in cur.fetchall()]

def get_interesting_assets():
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT subdomain, tech, banner FROM httpx_probes WHERE tech LIKE '%Jenkins%' OR banner LIKE '%Apache%' OR banner LIKE '%nginx%' OR banner LIKE '%error%'"
        )
        return [dict(subdomain=row[0], tech=row[1], banner=row[2]) for row in cur.fetchall()]

if __name__ == '__main__':
    setup_db()
    print('SQLite recon.db ready.') 