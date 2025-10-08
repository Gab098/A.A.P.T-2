import os
import pika
import json
import subprocess
import uuid
import sys
from datetime import datetime
import threading
from flask import Flask, jsonify

from aapt_framework.common.error_handler import handle_error
from aapt_framework.common.secrets import get_secret

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

def run_flask_app():
    app.run(host='0.0.0.0', port=8080)

def parse_prowler_output(output):
    """
    A simple parser to extract key information from Prowler's output.
    This is a placeholder and should be adapted to the specific Prowler output format.
    """
    findings = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "summary": {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
        }
    }
    # Example parsing logic
    for line in output.splitlines():
        if "[CRITICAL]" in line:
            findings["critical"].append(line)
            findings["summary"]["critical_count"] += 1
        elif "[HIGH]" in line:
            findings["high"].append(line)
            findings["summary"]["high_count"] += 1
    
    findings["summary"]["total_findings"] = len(findings["critical"]) + len(findings["high"]) + len(findings["medium"]) + len(findings["low"])
    return findings

def main():
    # Start Flask app in a separate thread
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    # Ensure logs directory exists
    os.makedirs('logs', exist_ok=True)

    rabbitmq_host = os.environ.get('RABBITMQ_HOST', 'localhost')
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
    channel = connection.channel()

    channel.queue_declare(queue='cloud_recon_tasks', durable=True)
    channel.queue_declare(queue='results_queue', durable=True)

    def callback(ch, method, properties, body):
        task_data = json.loads(body)
        target = task_data.get('target')
        cloud_provider = task_data.get('cloud_provider', 'aws') # Default to AWS
        correlation_id = str(uuid.uuid4())

        print(f" [x] Received task for target: {target} on provider: {cloud_provider}")

        # Prowler execution logic
        try:
            # Securely get credentials
            # For AWS, Prowler typically uses environment variables or AWS CLI profiles.
            # For Azure, it uses environment variables or Azure CLI login.
            # We'll assume credentials are set up in the environment or via profiles.

            prowler_command = ['prowler', cloud_provider]
            
            if cloud_provider.lower() == 'aws':
                aws_profile = get_secret('AWS_PROFILE', default='default')
                prowler_command.extend(['--profile', aws_profile])
            elif cloud_provider.lower() == 'azure':
                subscription_id = get_secret('AZURE_SUBSCRIPTION_ID')
                if subscription_id:
                    prowler_command.extend(['--subscription-id', subscription_id])
            elif cloud_provider.lower() == 'gcp':
                # Prowler for GCP typically relies on gcloud authentication
                # No specific command-line args for credentials usually needed if gcloud is configured
                pass
            else:
                raise ValueError(f"Unsupported cloud provider: {cloud_provider}")

            print(f"Executing command: {' '.join(prowler_command)}")
            result = subprocess.run(
                prowler_command,
                capture_output=True,
                text=True,
                check=True,
                env=os.environ # Pass current environment variables
            )
            raw_output = result.stdout
            status = "success"
            summary = f"Cloud reconnaissance completed successfully for {target} on {cloud_provider}."
        except subprocess.CalledProcessError as e:
            error_message = handle_error(e, "ProwlerExecutionError", f"Prowler command failed: {e.stderr}")
            raw_output = e.stderr
            status = "failure"
            summary = f"Prowler execution failed for {target} on {cloud_provider}."
        except ValueError as e:
            error_message = handle_error(e, "ConfigurationError", str(e))
            raw_output = str(e)
            status = "failure"
            summary = f"Configuration error for {target} on {cloud_provider}."
        except Exception as e:
            error_message = handle_error(e, "UnexpectedError", str(e))
            raw_output = str(e)
            status = "failure"
            summary = f"An unexpected error occurred during cloud reconnaissance for {target} on {cloud_provider}."
        
        # Save raw output to a log file
        log_filename = f"prowler_{target.replace('/', '_')}_{correlation_id}.log"
        log_filepath = os.path.join('logs', log_filename)
        with open(log_filepath, 'w') as f:
            f.write(raw_output)

        # Parse the output to enrich the data field
        parsed_data = {}
        if status == "success":
            parsed_data = parse_prowler_output(raw_output)

        result_message = {
            "schema_version": "1.2",
            "producer_version": "0.3.0", # Aligned with SCHEMA_COMPLETO_AAPT.md
            "task_id": str(uuid.uuid4()),
            "correlation_id": correlation_id,
            "attempt": 1,
            "worker_type": "cloud_recon_worker",
            "target": target,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "data": parsed_data,
            "raw_output_path": log_filepath,
            "message_type": None,
            "media": None,
            "reason_codes": None
        }

        channel.basic_publish(
            exchange='',
            routing_key='results_queue',
            body=json.dumps(result_message),
            properties=pika.BasicProperties(
                delivery_mode=2,  # make message persistent
            ))

        ch.basic_ack(delivery_tag=method.delivery_tag)
        print(f" [x] Task for {target} processed and result sent.")

    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue='cloud_recon_tasks', on_message_callback=callback)

    print(' [*] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
