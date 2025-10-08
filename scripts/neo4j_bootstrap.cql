// Neo4j Bootstrap Script - Constraints and Indexes for AAPT
// Run with: cypher-shell -u neo4j -p aapt_secret_db_pw -f neo4j_bootstrap.cql

// Constraints for uniqueness
CREATE CONSTRAINT domain_name_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT subdomain_name_unique IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE;
CREATE CONSTRAINT host_ip_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE;
CREATE CONSTRAINT shell_id_unique IF NOT EXISTS FOR (s:Shell) REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT vuln_name_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.name IS UNIQUE;
CREATE CONSTRAINT tech_composite_unique IF NOT EXISTS FOR (t:Tech) REQUIRE (t.name, t.port, t.host) IS UNIQUE;

// Performance indexes
CREATE INDEX host_ip_idx IF NOT EXISTS FOR (h:Host) ON (h.ip);
CREATE INDEX host_state_idx IF NOT EXISTS FOR (h:Host) ON (h.state);
CREATE INDEX host_last_seen_idx IF NOT EXISTS FOR (h:Host) ON (h.last_seen);

CREATE INDEX subdomain_name_idx IF NOT EXISTS FOR (s:Subdomain) ON (s.name);
CREATE INDEX subdomain_last_seen_idx IF NOT EXISTS FOR (s:Subdomain) ON (s.last_seen);

CREATE INDEX service_port_idx IF NOT EXISTS FOR (s:Service) ON (s.port);
CREATE INDEX service_protocol_idx IF NOT EXISTS FOR (s:Service) ON (s.protocol);
CREATE INDEX service_composite_idx IF NOT EXISTS FOR (s:Service) ON (s.port, s.protocol);

CREATE INDEX vuln_name_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.name);
CREATE INDEX vuln_severity_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);
CREATE INDEX vuln_cve_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve);

CREATE INDEX tech_name_idx IF NOT EXISTS FOR (t:Tech) ON (t.name);
CREATE INDEX tech_port_idx IF NOT EXISTS FOR (t:Tech) ON (t.port);
CREATE INDEX tech_cve_idx IF NOT EXISTS FOR (t:Tech) ON (t.cve);

CREATE INDEX finding_type_idx IF NOT EXISTS FOR (f:Finding) ON (f.type);
CREATE INDEX finding_severity_idx IF NOT EXISTS FOR (f:Finding) ON (f.severity);

CREATE INDEX shell_access_level_idx IF NOT EXISTS FOR (s:Shell) ON (s.access_level);
CREATE INDEX shell_last_seen_idx IF NOT EXISTS FOR (s:Shell) ON (s.last_seen);

// Composite indexes for common queries
CREATE INDEX host_state_last_seen_idx IF NOT EXISTS FOR (h:Host) ON (h.state, h.last_seen);
CREATE INDEX vuln_severity_cve_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity, v.cve);