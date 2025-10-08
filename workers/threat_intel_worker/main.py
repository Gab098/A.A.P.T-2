import os
import json
import pika
import time
import requests
from datetime import datetime
import uuid
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Environment variables for RabbitMQ
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'localhost')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'guest')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'guest')

# Environment variables for API keys
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')

# Queue names
TASK_QUEUE = 'threat_intel_tasks'
RESULTS_QUEUE = 'results_queue'

# Worker type
WORKER_TYPE = 'threat_intel_worker'
PRODUCER_VERSION = '0.1.0' # Version of this worker

def get_rabbitmq_connection():
    """Establishes and returns a RabbitMQ connection."""
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    parameters = pika.ConnectionParameters(RABBITMQ_HOST,
                                           5672,
                                           '/',
                                           credentials,
                                           heartbeat=600)
    return pika.BlockingConnection(parameters)

def publish_result(channel, result_data):
    """Publishes results to the results queue."""
    try:
        channel.basic_publish(
            exchange='',
            routing_key=RESULTS_QUEUE,
            body=json.dumps(result_data),
            properties=pika.BasicProperties(
                delivery_mode=2,  # make message persistent
            )
        )
        logging.info(f"Published result for task {result_data.get('task_id')}")
    except Exception as e:
        logging.error(f"Failed to publish result: {e}")

def query_virustotal(target):
    """Queries VirusTotal for a given target (domain/IP/URL/hash)."""
    if not VIRUSTOTAL_API_KEY:
        logging.warning("VIRUSTOTAL_API_KEY not set. Skipping VirusTotal query.")
        return None

    url = "https://www.virustotal.com/api/v3/search"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    params = {"query": target}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal query failed for {target}: {e}")
        return None

def query_abuseipdb(target):
    """Queries AbuseIPDB for a given IP address."""
    if not ABUSEIPDB_API_KEY:
        logging.warning("ABUSEIPDB_API_KEY not set. Skipping AbuseIPDB query.")
        return None

    # AbuseIPDB only works for IP addresses
    if not is_ip_address(target):
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": target,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"AbuseIPDB query failed for {target}: {e}")
        return None

def is_ip_address(target):
    """Simple check if the target looks like an IP address."""
    try:
        parts = target.split('.')
        if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
            return True
    except ValueError:
        pass
    return False

def process_task(ch, method, properties, body):
    """Callback function to process incoming tasks."""
    try:
        task = json.loads(body)
        target = task.get('target')
        task_id = task.get('task_id', str(uuid.uuid4()))
        correlation_id = task.get('correlation_id', task_id)

        logging.info(f"Processing threat intelligence task for target: {target} (Task ID: {task_id})")

        threat_intel_data = {}
        summary_parts = []

        # Query VirusTotal
        vt_result = query_virustotal(target)
        if vt_result:
            threat_intel_data['virustotal'] = vt_result
            if vt_result.get('data') and vt_result['data'].get('last_analysis_stats'):
                stats = vt_result['data']['last_analysis_stats']
                summary_parts.append(f"VT: Malicious={stats.get('malicious', 0)}, Suspicious={stats.get('suspicious', 0)}")

        # Query AbuseIPDB
        abuse_result = query_abuseipdb(target)
        if abuse_result and abuse_result.get('data'):
            threat_intel_data['abuseipdb'] = abuse_result
            abuse_score = abuse_result['data'].get('abuseConfidenceScore')
            if abuse_score is not None:
                summary_parts.append(f"AbuseIPDB Score: {abuse_score}%")

        status = "success" if threat_intel_data else "partial"
        summary = f"Threat Intel for {target}: {', '.join(summary_parts) if summary_parts else 'No significant data found or APIs not configured.'}"

        result_data = {
            "schema_version": "1.2",
            "producer_version": PRODUCER_VERSION,
            "task_id": task_id,
            "correlation_id": correlation_id,
            "attempt": 1,
            "worker_type": WORKER_TYPE,
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": {
                "threat_intelligence": threat_intel_data
            },
            "raw_output_path": None,
            "message_type": "threat_intel_result",
            "media": None,
            "reason_codes": []
        }

        publish_result(ch, result_data)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except json.JSONDecodeError:
        logging.error(f"Failed to decode JSON from message: {body.decode()}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Don't requeue malformed messages
    except Exception as e:
        logging.error(f"Error processing task: {e}", exc_info=True)
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True) # Requeue on unexpected errors

def main():
    """Main function to set up RabbitMQ consumer."""
    retries = 5
    for i in range(retries):
        try:
            connection = get_rabbitmq_connection()
            channel = connection.channel()
            channel.queue_declare(queue=TASK_QUEUE, durable=True)
            channel.queue_declare(queue=RESULTS_QUEUE, durable=True)

            channel.basic_consume(queue=TASK_QUEUE, on_message_callback=process_task)

            logging.info(f"[{WORKER_TYPE}] Waiting for messages in {TASK_QUEUE}. To exit press CTRL+C")
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError as e:
            logging.error(f"RabbitMQ connection error: {e}. Retrying in 10 seconds... ({i+1}/{retries})")
            time.sleep(10)
        except KeyboardInterrupt:
            logging.info("Exiting worker.")
            break
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            break
    else:
        logging.error("Failed to connect to RabbitMQ after multiple retries. Exiting.")

if __name__ == '__main__':
    main()
