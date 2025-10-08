# 🛡️ Threat Intelligence Worker

The `threat_intel_worker` is a specialized component of the A.A.P.T. framework designed to enrich reconnaissance and vulnerability data with real-time threat intelligence from external sources. This worker integrates with various threat intelligence platforms to provide additional context on identified assets (IPs, domains, URLs, file hashes), helping to identify known malicious indicators, assess asset reputation, and provide crucial data for the LLM-driven prioritization system.

## ✨ Features

*   **External API Integration**: Connects with leading threat intelligence services like VirusTotal and AbuseIPDB.
*   **Data Enrichment**: Gathers reputation scores, known malicious associations, and other relevant threat data.
*   **Standardized Output**: Publishes enriched results to the `results_queue` following the A.A.P.T. standardized JSON schema (v1.2+).
*   **LLM-Driven Prioritization Support**: Provides critical threat context to the `llm_planner` for more intelligent decision-making.
*   **Configurable API Keys**: Secure management of API keys via environment variables.

## ⚙️ How it Works

1.  **Task Reception**: The worker listens on the `threat_intel_tasks` RabbitMQ queue for new tasks, typically triggered by the `orchestrator` after initial asset discovery (e.g., by `httpx_worker` or `naabu_worker`).
2.  **API Queries**: Upon receiving a target (IP, domain, URL, or hash), the worker queries configured external threat intelligence APIs.
3.  **Data Processing**: Responses from these APIs are processed, normalized, and structured into the `threat_intelligence` field within the A.A.P.T. result schema.
4.  **Result Publication**: The enriched result, containing the threat intelligence data, is published to the `results_queue` for further processing by the `state_manager` (for Neo4j updates) and the `ui` (for display).

## 🚀 Getting Started

### Prerequisites

*   **RabbitMQ**: A running RabbitMQ instance accessible by the worker.
*   **API Keys**: Obtain API keys for desired threat intelligence services (e.g., VirusTotal, AbuseIPDB).

### Configuration

Set the following environment variables for the worker:

```bash
# RabbitMQ Connection
RABBITMQ_HOST=rabbitmq
RABBITMQ_USER=aapt_user
RABBITMQ_PASS=your_secure_rabbitmq_password_here

# Threat Intelligence API Keys (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

### Running the Worker (Docker)

To build and run the worker using Docker:

```bash
# Navigate to the A.A.P.T. root directory
cd AAPT/aapt_framework/workers/threat_intel_worker

# Build the Docker image
docker build -t aapt-threat-intel-worker .

# Run the container (example, adjust environment variables as needed)
docker run -d \
  --name aapt-threat-intel-worker \
  -e RABBITMQ_HOST=your_rabbitmq_host \
  -e RABBITMQ_USER=your_rabbitmq_user \
  -e RABBITMQ_PASS=your_rabbitmq_pass \
  -e VIRUSTOTAL_API_KEY=your_virustotal_key \
  -e ABUSEIPDB_API_KEY=your_abuseipdb_key \
  aapt-threat-intel-worker
```

For integration with the full A.A.P.T. system, refer to the `docker-compose.yml` and `k8s/workers.yaml` configurations in the main framework documentation.

## 📦 Dependencies

The worker relies on the following Python packages:

*   `pika`
*   `requests`

These are listed in `requirements.txt`.

## 📈 Healthcheck

The worker does not expose a direct HTTP healthcheck endpoint. Its operational status can be monitored by observing its logs and the successful processing of messages in the RabbitMQ queues.

## 📝 License

This project is open source. See the main A.A.P.T. framework `LICENSE` file for details.
