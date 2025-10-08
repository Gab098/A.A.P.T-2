import os
import json
import uuid
import pika
from datetime import datetime

# Placeholder: in futuro integrare BLIP/CLIP e gestione immagini

RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'aapt_user')
RABBITMQ_PASS = os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)

QUEUE = 'vision_tasks'
RESULTS_QUEUE = 'results_queue'


def publish_result(channel, message: dict):
    channel.basic_publish(
        exchange='',
        routing_key=RESULTS_QUEUE,
        body=json.dumps(message)
    )


def create_result(task_id: str, target: str, caption: str, tags: list[str]):
    return {
        "schema_version": "1.2",
        "producer_version": os.getenv('AAPT_VERSION', '0.3.0'),
        "task_id": task_id,
        "correlation_id": task_id,
        "attempt": 1,
        "worker_type": "vision_worker",
        "target": target,
        "status": "success",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "summary": "Caption generated",
        "data": {
            "caption": caption,
            "tags": tags,
        },
        "raw_output_path": None,
        "message_type": "vision",
        "media": {"image_ref": target},
        "reason_codes": ["vision:caption"]
    }


def main():
    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST, credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE, durable=True)
            channel.queue_declare(queue=RESULTS_QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)

            def callback(ch, method, properties, body):
                try:
                    task = json.loads(body)
                    task_id = task.get('task_id', str(uuid.uuid4()))
                    image_ref = task.get('image_ref') or task.get('image_url') or 'unknown://image'
                    # TODO: load image, run BLIP/CLIP and produce caption/tags
                    caption = "Image processed (placeholder)"
                    tags = ["placeholder"]
                    result = create_result(task_id, image_ref, caption, tags)
                    publish_result(channel, result)
                except Exception as e:
                    # publish failure
                    result = {
                        "schema_version": "1.2",
                        "task_id": task.get('task_id', 'unknown'),
                        "worker_type": "vision_worker",
                        "target": task.get('image_ref', 'unknown'),
                        "status": "failure",
                        "timestamp": datetime.utcnow().isoformat() + 'Z',
                        "summary": f"Error: {str(e)}",
                        "data": {}
                    }
                    publish_result(channel, result)
                finally:
                    ch.basic_ack(delivery_tag=method.delivery_tag)

            channel.basic_consume(queue=QUEUE, on_message_callback=callback)
            channel.start_consuming()
        except Exception as e:
            import time
            print(f"vision_worker error: {e}")
            time.sleep(5)


if __name__ == '__main__':
    main()
