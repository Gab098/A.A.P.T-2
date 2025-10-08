# AAPT Enhanced Deployment Guide

This guide covers deploying the enhanced AAPT framework with new workers, reliability improvements, and Kubernetes support.

## 🚀 Quick Start

### Docker Compose (Recommended for Development)

```bash
# Navigate to framework directory
cd c:\Users\buica\Desktop\otherside\AAPT\AAPT\aapt_framework

# Start core services
docker-compose up -d rabbitmq neo4j

# Wait for services to be ready (check logs)
docker-compose logs rabbitmq neo4j

# Bootstrap Neo4j with constraints and indexes
docker exec neo4j cypher-shell -u neo4j -p aapt_secret_db_pw -f /app/scripts/neo4j_bootstrap.cql

# Start all workers and orchestrator
docker-compose up -d

# Start with passive scheduling (orchestrator v3)
docker-compose --profile autonomous up -d orchestrator_v3
```

### Kubernetes (Production)

```bash
# Install KEDA for autoscaling (if not already installed)
kubectl apply -f https://github.com/kedacore/keda/releases/download/v2.12.0/keda-2.12.0.yaml

# Apply AAPT manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rabbitmq-definitions.yaml
kubectl apply -f k8s/rabbitmq.yaml
kubectl apply -f k8s/neo4j.yaml

# Wait for core services
kubectl -n aapt wait --for=condition=ready pod -l app=rabbitmq --timeout=300s
kubectl -n aapt wait --for=condition=ready pod -l app=neo4j --timeout=300s

# Bootstrap Neo4j
kubectl -n aapt exec deployment/neo4j -- cypher-shell -u neo4j -p aapt_secret_db_pw -f /app/scripts/neo4j_bootstrap.cql

# Create secrets (replace with your actual keys)
kubectl -n aapt create secret generic shodan-secret --from-literal=api_key=YOUR_SHODAN_KEY
kubectl -n aapt create secret generic censys-secret --from-literal=api_id=YOUR_CENSYS_ID --from-literal=api_secret=YOUR_CENSYS_SECRET
kubectl -n aapt create secret generic nvd-secret --from-literal=api_key=YOUR_NVD_KEY

# Deploy workers and services
kubectl apply -f k8s/ui.yaml
kubectl apply -f k8s/orchestrator.yaml
kubectl apply -f k8s/workers.yaml

# Enable autoscaling
kubectl apply -f k8s/keda-autoscaling.yaml

# Apply OPSEC profiles
kubectl apply -f k8s/opsec-profiles.yaml
```

## 🔧 Configuration

### Environment Variables

#### Core Settings
- `RABBITMQ_HOST`: RabbitMQ hostname (default: rabbitmq)
- `NEO4J_URI`: Neo4j connection URI (default: bolt://neo4j:7687)
- `AAPT_VERSION`: Framework version for result schema (default: 0.2.0)

#### Throttling & OPSEC
- `AAPT_NMAP_TIMING`: Nmap timing template T0-T5 (default: T3)
- `AAPT_NMAP_RANDOMIZE_HOSTS`: Randomize host order (default: true)
- `AAPT_MASSCAN_RATE`: Masscan packets/sec (default: 1000)
- `AAPT_HTTPX_THREADS`: HTTPx concurrent threads (default: 50)
- `AAPT_HTTPX_RATE_LIMIT`: HTTPx requests/sec (default: 150)
- `AAPT_SUBFINDER_RATE`: Subfinder rate limit (default: 100)
- `AAPT_DNSX_RATE_LIMIT`: DNSx queries/sec (default: 1000)

#### Passive Scheduling (Orchestrator V3)
- `AAPT_PASSIVE_INTERVAL`: Scheduling interval in seconds (default: 300)
- `AAPT_SUBDOMAIN_REFRESH_HOURS`: Hours before re-resolving subdomains (default: 24)
- `AAPT_HTTP_PROBE_REFRESH_HOURS`: Hours before re-probing HTTP (default: 12)

#### API Keys
- `SHODAN_API_KEY`: Shodan API key for enrichment
- `CENSYS_API_ID` / `CENSYS_API_SECRET`: Censys API credentials
- `NVD_API_KEY`: NVD API key (optional but recommended)

### OPSEC Profiles

Apply different operational security profiles:

```bash
# Kubernetes
kubectl -n aapt create configmap opsec-manager --from-file=k8s/opsec-profiles.yaml
kubectl -n aapt exec deployment/orchestrator-v3 -- python /etc/opsec-profiles/apply_profile.py stealth

# Available profiles: default, stealth, aggressive, red_team
```

## 🏗️ Architecture Overview

### New Components

#### Workers
- **httpx_worker**: HTTP probing, tech detection, subdomain takeover detection
- **dnsx_worker**: DNS resolution and validation
- **cve_enrichment_worker**: CVE data enrichment from NVD/ExploitDB
- **Enhanced privesc_worker**: BloodHound, Mimikatz, Impacket integration

#### Infrastructure
- **RabbitMQ with DLQ**: Dead letter queues and retry mechanisms
- **Neo4j with Constraints**: Performance indexes and data integrity
- **KEDA Autoscaling**: Queue-based worker scaling
- **Orchestrator V3**: Passive reconnaissance scheduling

### Data Flow

```
Subfinder → DNSx → HTTPx → Nuclei (reactive)
     ↓        ↓       ↓        ↓
   Neo4j ← Results Queue ← Workers
     ↓
State Manager → Orchestrator V3 → Passive Tasks
```

## 🔍 Monitoring & Health Checks

### Health Endpoints
- Orchestrator V3: `http://localhost:5152/health`
- Workers: `http://localhost:808X/health` (where X = worker port)
- System Status: `http://localhost:5152/status`

### Queue Monitoring
- RabbitMQ Management: `http://localhost:15672` (aapt_user/aapt_secret_pw)
- Queue depths, DLQ contents, message rates

### Neo4j Monitoring
- Neo4j Browser: `http://localhost:7474` (neo4j/aapt_secret_db_pw)
- Graph statistics, constraint violations, query performance

## 🎯 Usage Examples

### Manual Task Submission

```bash
# Subdomain enumeration
curl -X POST http://localhost:5152/manual_action \
  -H "Content-Type: application/json" \
  -d '{"action": "subfinder", "target": "example.com"}'

# HTTP probing
curl -X POST http://localhost:5152/manual_action \
  -H "Content-Type: application/json" \
  -d '{"action": "httpx_probe", "target": "sub.example.com"}'

# CVE enrichment
curl -X POST http://localhost:5152/manual_action \
  -H "Content-Type: application/json" \
  -d '{"action": "cve_enrich", "target": "CVE-2021-44228", "parameters": {"product": "log4j"}}'

# Privilege escalation
curl -X POST http://localhost:5152/manual_action \
  -H "Content-Type: application/json" \
  -d '{"action": "privesc", "target": "192.168.1.10", "parameters": {"action": "linpeas"}}'
```

### Passive Reconnaissance

The Orchestrator V3 automatically schedules:
- DNS resolution for unresolved subdomains
- HTTP probing for newly resolved hosts  
- CVE enrichment for discovered technologies
- Nuclei scans for interesting services

## 🛠️ Troubleshooting

### Common Issues

#### RabbitMQ Connection Errors
```bash
# Check RabbitMQ status
docker-compose logs rabbitmq
kubectl -n aapt logs deployment/rabbitmq

# Verify queue definitions loaded
curl -u aapt_user:aapt_secret_pw http://localhost:15672/api/queues
```

#### Neo4j Constraint Violations
```bash
# Check constraints
docker exec neo4j cypher-shell -u neo4j -p aapt_secret_db_pw "SHOW CONSTRAINTS"

# Re-run bootstrap if needed
docker exec neo4j cypher-shell -u neo4j -p aapt_secret_db_pw -f /app/scripts/neo4j_bootstrap.cql
```

#### Worker Health Issues
```bash
# Check worker logs
docker-compose logs httpx_worker
kubectl -n aapt logs deployment/httpx-worker

# Verify tool installation
docker exec httpx_worker httpx -version
```

### Performance Tuning

#### High Load Scenarios
- Increase worker replicas in Kubernetes
- Adjust OPSEC profile to 'aggressive' for speed
- Scale RabbitMQ and Neo4j resources

#### Stealth Operations
- Apply 'stealth' or 'red_team' OPSEC profile
- Reduce rate limits and increase delays
- Use proxy chains (configure in worker env)

## 📊 Metrics & Observability

### Key Metrics to Monitor
- Queue depths (should drain within reasonable time)
- Worker processing rates (tasks/minute)
- Neo4j query performance (<200ms for dashboard queries)
- Error rates in DLQ queues

### Grafana Dashboard Queries (if using Prometheus)
```promql
# Queue depth
rabbitmq_queue_messages{queue=~".*_tasks"}

# Worker processing rate
rate(aapt_results_total[5m])

# Error rate
rate(aapt_errors_total[5m])
```

## 🔐 Security Considerations

### Production Hardening
- Change default passwords in docker-compose.yml
- Use Kubernetes secrets for sensitive data
- Apply NetworkPolicies to restrict worker egress
- Run containers as non-root users
- Enable TLS for RabbitMQ and Neo4j

### Operational Security
- Use stealth OPSEC profiles for red team engagements
- Configure proxy chains for attribution avoidance
- Monitor for defensive tool detection
- Implement rate limiting and jitter

## 📈 Scaling Guidelines

### Horizontal Scaling
- KEDA automatically scales workers based on queue length
- Increase maxReplicaCount in ScaledObjects for higher throughput
- Consider sharding Neo4j for very large datasets

### Vertical Scaling
- Increase worker resource limits in Kubernetes
- Scale RabbitMQ and Neo4j memory/CPU
- Optimize Neo4j heap size and page cache

---

## 🎉 What's New in This Release

### ✅ Reliability & Data Model
- RabbitMQ DLQ and retry topology
- Neo4j constraints and performance indexes
- Standardized result schema v1.1 with versioning

### ✅ Expanded Reconnaissance
- HTTPx worker for web fingerprinting
- DNSx worker for DNS resolution
- CVE enrichment with NVD/ExploitDB integration
- Enhanced subdomain takeover detection

### ✅ Post-Exploitation
- BloodHound/SharpHound collection
- Mimikatz credential dumping
- Impacket secretsdump integration
- Structured credential storage

### ✅ Kubernetes Production
- KEDA autoscaling based on queue depth
- OPSEC profiles via ConfigMaps
- Security contexts and NetworkPolicies
- Comprehensive health checks

### ✅ Passive Automation
- Orchestrator V3 with intelligent scheduling
- Reactive task chaining (subfinder → dnsx → httpx → nuclei)
- Stale data refresh automation
- CVE enrichment pipeline

This enhanced AAPT framework provides production-grade reliability, expanded coverage, and intelligent automation while maintaining the flexibility for manual operations and red team tradecraft.