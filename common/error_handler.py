"""
AAPT Error Handling - Sistema centralizzato per gestione errori
"""
import logging
import traceback
import json
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

class ErrorSeverity(Enum):
    """Livelli di severità degli errori"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Categorie di errori"""
    CONFIGURATION = "configuration"
    NETWORK = "network"
    DATABASE = "database"
    VALIDATION = "validation"
    EXECUTION = "execution"
    SECURITY = "security"
    UNKNOWN = "unknown"

class AAPTError(Exception):
    """Eccezione base per AAPT"""
    
    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.UNKNOWN, 
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM, 
                 context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.context = context or {}
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.traceback = traceback.format_exc()

class ConfigurationError(AAPTError):
    """Errore di configurazione"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorCategory.CONFIGURATION, ErrorSeverity.HIGH, context)

class NetworkError(AAPTError):
    """Errore di rete"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorCategory.NETWORK, ErrorSeverity.MEDIUM, context)

class DatabaseError(AAPTError):
    """Errore di database"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorCategory.DATABASE, ErrorSeverity.HIGH, context)

class ValidationError(AAPTError):
    """Errore di validazione"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorCategory.VALIDATION, ErrorSeverity.LOW, context)

class SecurityError(AAPTError):
    """Errore di sicurezza"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorCategory.SECURITY, ErrorSeverity.CRITICAL, context)

class ErrorHandler:
    """Gestore centralizzato degli errori"""
    
    def __init__(self, logger_name: str = "aapt_error_handler"):
        self.logger = logging.getLogger(logger_name)
        self.error_count = 0
        self.error_history = []
    
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Gestisce un errore e restituisce informazioni strutturate"""
        self.error_count += 1
        
        error_info = {
            "error_id": f"err_{self.error_count}_{int(datetime.utcnow().timestamp())}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": type(error).__name__,
            "message": str(error),
            "context": context or {},
            "traceback": traceback.format_exc()
        }
        
        # Determina categoria e severità
        if isinstance(error, AAPTError):
            error_info["category"] = error.category.value
            error_info["severity"] = error.severity.value
        else:
            error_info["category"] = ErrorCategory.UNKNOWN.value
            error_info["severity"] = ErrorSeverity.MEDIUM.value
        
        # Log appropriato basato su severità
        severity = error_info["severity"]
        if severity == ErrorSeverity.CRITICAL.value:
            self.logger.critical(f"CRITICAL ERROR: {error_info}")
        elif severity == ErrorSeverity.HIGH.value:
            self.logger.error(f"HIGH ERROR: {error_info}")
        elif severity == ErrorSeverity.MEDIUM.value:
            self.logger.warning(f"MEDIUM ERROR: {error_info}")
        else:
            self.logger.info(f"LOW ERROR: {error_info}")
        
        # Aggiungi alla history (mantieni solo ultimi 100)
        self.error_history.append(error_info)
        if len(self.error_history) > 100:
            self.error_history.pop(0)
        
        return error_info
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Ottiene un riassunto degli errori"""
        if not self.error_history:
            return {"total_errors": 0, "by_severity": {}, "by_category": {}}
        
        by_severity = {}
        by_category = {}
        
        for error in self.error_history:
            severity = error.get("severity", "unknown")
            category = error.get("category", "unknown")
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1
        
        return {
            "total_errors": len(self.error_history),
            "by_severity": by_severity,
            "by_category": by_category,
            "recent_errors": self.error_history[-5:]  # Ultimi 5 errori
        }

def safe_execute(func, *args, error_handler: Optional[ErrorHandler] = None, 
                context: Optional[Dict[str, Any]] = None, **kwargs):
    """Esegue una funzione in modo sicuro con gestione errori"""
    if not error_handler:
        error_handler = ErrorHandler()
    
    try:
        return func(*args, **kwargs)
    except Exception as e:
        error_info = error_handler.handle_error(e, context)
        return None, error_info

def retry_on_failure(max_retries: int = 3, delay: float = 1.0, 
                    backoff_factor: float = 2.0):
    """Decorator per retry automatico su fallimento"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_error = None
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    if attempt < max_retries:
                        import time
                        time.sleep(current_delay)
                        current_delay *= backoff_factor
                        continue
                    else:
                        raise last_error
            
            return None
        return wrapper
    return decorator

# Istanza globale per uso comune
global_error_handler = ErrorHandler("aapt_global")

def handle_global_error(error: Exception, context: Optional[Dict[str, Any]] = None):
    """Gestisce errori globali"""
    return global_error_handler.handle_error(error, context)
