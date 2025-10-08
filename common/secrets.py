"""
AAPT Secrets Management - Sistema di gestione sicura delle credenziali
"""
import os
import logging
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
import base64
import json

logger = logging.getLogger(__name__)

class SecretsManager:
    """Gestisce i secrets in modo sicuro con crittografia"""
    
    def __init__(self, encryption_key: Optional[str] = None):
        self.encryption_key = encryption_key or os.getenv('AAPT_ENCRYPTION_KEY')
        if self.encryption_key:
            try:
                self.cipher = Fernet(self.encryption_key.encode())
            except Exception as e:
                logger.warning(f"Errore inizializzazione crittografia: {e}")
                self.cipher = None
        else:
            logger.warning("Nessuna chiave di crittografia configurata")
            self.cipher = None
    
    def encrypt_secret(self, secret: str) -> str:
        """Crittografa un secret"""
        if not self.cipher:
            return secret
        try:
            return self.cipher.encrypt(secret.encode()).decode()
        except Exception as e:
            logger.error(f"Errore crittografia secret: {e}")
            return secret
    
    def decrypt_secret(self, encrypted_secret: str) -> str:
        """Decrittografa un secret"""
        if not self.cipher:
            return encrypted_secret
        try:
            return self.cipher.decrypt(encrypted_secret.encode()).decode()
        except Exception as e:
            logger.error(f"Errore decrittografia secret: {e}")
            return encrypted_secret

class ConfigManager:
    """Gestisce la configurazione dell'applicazione con validazione"""
    
    def __init__(self):
        self.secrets_manager = SecretsManager()
        self._config = {}
        self._load_config()
    
    def _load_config(self):
        """Carica la configurazione da variabili d'ambiente"""
        self._config = {
            # RabbitMQ
            'rabbitmq': {
                'host': os.getenv('RABBITMQ_HOST', 'rabbitmq'),
                'user': os.getenv('RABBITMQ_USER', 'aapt_user'),
                'password': self.secrets_manager.decrypt_secret(
                    os.getenv('RABBITMQ_PASS', 'aapt_secret_pw')
                ),
                'port': int(os.getenv('RABBITMQ_PORT', '5672'))
            },
            
            # Neo4j
            'neo4j': {
                'uri': os.getenv('NEO4J_URI', 'bolt://neo4j:7687'),
                'user': os.getenv('NEO4J_USER', 'neo4j'),
                'password': self.secrets_manager.decrypt_secret(
                    os.getenv('NEO4J_PASS', 'aapt_secret_db_pw')
                )
            },
            
            # API Keys
            'api_keys': {
                'shodan': os.getenv('SHODAN_API_KEY'),
                'censys_id': os.getenv('CENSYS_API_ID'),
                'censys_secret': os.getenv('CENSYS_API_SECRET'),
                'nvd': os.getenv('NVD_API_KEY')
            },
            
            # Slack
            'slack': {
                'webhook_url': os.getenv('AAPT_SLACK_WEBHOOK')
            },
            
            # LLM
            'llm': {
                'router_url': os.getenv('LLM_ROUTER_URL', 'http://llm-router:8082'),
                'model_path': os.getenv('MODEL_PATH', './models/'),
                'confidence_threshold': float(os.getenv('LLM_CONFIDENCE_THRESHOLD', '0.6'))
            }
        }
    
    def get_config(self, section: str = None) -> Dict[str, Any]:
        """Ottiene la configurazione per una sezione o tutta la config"""
        if section:
            return self._config.get(section, {})
        return self._config
    
    def validate_config(self) -> bool:
        """Valida che la configurazione sia completa"""
        required_sections = ['rabbitmq', 'neo4j']
        
        for section in required_sections:
            if section not in self._config:
                logger.error(f"Sezione config mancante: {section}")
                return False
            
            config_section = self._config[section]
            if not all(config_section.values()):
                logger.error(f"Configurazione incompleta per sezione: {section}")
                return False
        
        return True

def get_secure_config() -> ConfigManager:
    """Factory function per ottenere configurazione sicura"""
    return ConfigManager()

def validate_input(target: str, input_type: str = "target") -> bool:
    """Valida input per prevenire injection attacks"""
    if not target or not isinstance(target, str):
        return False
    
    # Rimuovi caratteri pericolosi
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    if any(char in target for char in dangerous_chars):
        logger.warning(f"Input sospetto rilevato: {target}")
        return False
    
    # Validazione specifica per tipo
    if input_type == "target":
        # Validazione IP o dominio
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not (re.match(ip_pattern, target) or re.match(domain_pattern, target)):
            logger.warning(f"Formato target non valido: {target}")
            return False
    
    return True

def sanitize_filename(filename: str) -> str:
    """Sanitizza nomi file per prevenire path traversal"""
    import re
    # Rimuovi caratteri pericolosi
    sanitized = re.sub(r'[^\w\-_\.]', '_', filename)
    # Limita lunghezza
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    return sanitized
