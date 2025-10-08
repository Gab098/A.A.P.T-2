import os
import json
import pika
from neo4j import GraphDatabase
from jinja2 import Environment, FileSystemLoader
import logging
import sys
from datetime import datetime # Import datetime for filename generation
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from orchestrator.state_manager import StateManager

# Configurazione del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Variabili d'ambiente
RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASS = os.getenv('NEO4J_PASS')

# Code per la gestione sicura delle credenziali (da implementare)
if not NEO4J_PASS:
    logging.error("La password di Neo4j non è impostata. Terminazione.")
    exit(1)

class ReportingWorker:
    def __init__(self):
        self.neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        self.state_manager = StateManager() # Initialize StateManager
        self.jinja_env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
        self.setup_rabbitmq()

    def setup_rabbitmq(self):
        """Configura la connessione e le code RabbitMQ."""
        try:
            self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
            self.channel = self.connection.channel()
            self.channel.queue_declare(queue='reporting_queue', durable=True)
            self.channel.basic_consume(queue='reporting_queue', on_message_callback=self.process_task, auto_ack=True)
            logging.info("Connesso a RabbitMQ e in attesa di messaggi.")
        except pika.exceptions.AMQPConnectionError as e:
            logging.error(f"Errore di connessione a RabbitMQ: {e}")
            # Aggiungere logica di retry qui
            exit(1)

    def fetch_data_for_report(self):
        """Estrae tutti i dati pertinenti per il report dallo StateManager."""
        state = self.state_manager.get_system_state()
        return state.get('anomalous_assets', [])

    def generate_report(self, data, template_name='report_template.md'):
        """Genera il report utilizzando un template Jinja2."""
        template = self.jinja_env.get_template(template_name)
        report_content = template.render(assets=data)
        
        # Salva il report in un file
        output_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        output_path = os.path.join('/app/reports', output_filename) # Assuming /app/reports exists in container
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(report_content)
        logging.info(f"Report generato: {output_path}")
        return output_path

    def process_task(self, ch, method, properties, body):
        """Funzione di callback per elaborare i messaggi dalla coda."""
        try:
            task = json.loads(body)
            # task_id is not directly used for fetching data anymore, but can be kept for logging
            task_id = task.get('task_id') 
            if not task_id:
                logging.warning("Messaggio ricevuto senza task_id. Procedo con la generazione del report generale.")

            logging.info(f"Ricevuto task di reporting (task_id: {task_id if task_id else 'N/A'})")
            
            # 1. Estrai i dati dallo StateManager
            report_data = self.fetch_data_for_report()
            
            if not report_data:
                logging.warning(f"Nessun dato sugli asset anomali trovato per il report.")
                # Optionally generate an empty report or a report indicating no findings
                self.generate_report([])
                return

            # 2. Genera il report
            self.generate_report(report_data)

        except json.JSONDecodeError:
            logging.error("Errore nel decodificare il messaggio JSON.")
        except Exception as e:
            logging.error(f"Si è verificato un errore imprevisto: {e}")

    def start_consuming(self):
        """Avvia il consumo dei messaggi."""
        try:
            self.channel.start_consuming()
        except KeyboardInterrupt:
            self.channel.stop_consuming()
        finally:
            self.connection.close()
            self.neo4j_driver.close()
            logging.info("Connessioni chiuse.")

if __name__ == '__main__':
    worker = ReportingWorker()
    worker.start_consuming()
