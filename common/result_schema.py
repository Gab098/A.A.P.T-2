"""
AAPT Result Schema v1.1 - Standardized message format for all workers
"""
from datetime import datetime
from typing import Dict, Any, Optional
import uuid
import os

SCHEMA_VERSION = "1.2"
PRODUCER_VERSION = os.getenv('AAPT_VERSION', '0.3.0')

def create_result_message(
    task_id: str,
    worker_type: str,
    target: str,
    status: str,
    summary: str,
    data: Dict[str, Any],
    correlation_id: Optional[str] = None,
    attempt: int = 1,
    raw_output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a standardized result message following AAPT schema v1.1
    
    Args:
        task_id: Unique task identifier
        worker_type: Type of worker (e.g., 'nmap_worker', 'subfinder_worker')
        target: Target being scanned/processed
        status: 'success', 'failure', 'partial'
        summary: Human-readable summary of results
        data: Worker-specific result data
        correlation_id: Optional correlation ID for tracing
        attempt: Attempt number (for retries)
        raw_output_path: Optional path to raw output file
    
    Returns:
        Standardized result message dictionary
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "producer_version": PRODUCER_VERSION,
        "task_id": task_id,
        "correlation_id": correlation_id or task_id,
        "attempt": attempt,
        "worker_type": worker_type,
        "target": target,
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "data": data,
        "raw_output_path": raw_output_path,
        # estensioni opzionali v1.2
        "message_type": None,
        "media": None,
        "reason_codes": None,
    }

def validate_result_message(message: Dict[str, Any]) -> bool:
    """
    Validate that a message conforms to the expected schema
    
    Args:
        message: Message to validate
        
    Returns:
        True if valid, False otherwise
    """
    required_fields = [
        "schema_version", "task_id", "worker_type", "target", 
        "status", "timestamp", "summary", "data"
    ]
    
    for field in required_fields:
        if field not in message:
            return False
    
    # Validate status values
    if message["status"] not in ["success", "failure", "partial"]:
        return False
        
    return True

def extract_task_info(task: Dict[str, Any]) -> tuple:
    """
    Extract common task information for result creation
    
    Args:
        task: Task message from queue
        
    Returns:
        Tuple of (task_id, correlation_id, attempt)
    """
    task_id = task.get('task_id', str(uuid.uuid4()))
    correlation_id = task.get('correlation_id', task_id)
    attempt = int(task.get('attempt', 1))
    
    return task_id, correlation_id, attempt