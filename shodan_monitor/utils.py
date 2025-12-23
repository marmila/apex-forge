import logging
import signal
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import List, Tuple
import ipaddress

logger = logging.getLogger(__name__)

class GracefulShutdown:
    """Context manager for graceful shutdown handling."""
    def __init__(self, shutdown_callback=None):
        self.shutdown_callback = shutdown_callback
        self.should_exit = False

    def __enter__(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.shutdown_callback:
            self.shutdown_callback()

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.should_exit = True

class Timer:
    """Context manager for timing code blocks using timezone-aware UTC."""
    def __init__(self, name: str = "operation"):
        self.name = name
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        self.start_time = datetime.now(timezone.utc)
        logger.debug(f"Starting {self.name}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = datetime.now(timezone.utc)
        duration = (self.end_time - self.start_time).total_seconds()

        if exc_type is None:
            logger.debug(f"Completed {self.name} in {duration:.2f}s")
        else:
            logger.error(f"{self.name} failed after {duration:.2f}s")

    @property
    def duration(self) -> float:
        """Get duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now(timezone.utc) - self.start_time).total_seconds()
        return 0.0

def validate_ip_list(ips: List[str]) -> Tuple[List[str], List[str]]:
    """Validate a list of IP addresses."""
    valid, invalid = [], []
    for ip in ips:
        ip = ip.strip()
        if not ip: continue
        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            invalid.append(ip)
    return valid, invalid

def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string."""
    if seconds < 60: return f"{seconds:.1f}s"
    if seconds < 3600: return f"{seconds/60:.1f}m"
    if seconds < 86400: return f"{seconds/3600:.1f}h"
    return f"{seconds/86400:.1f}d"

def safe_get(dictionary: dict, keys: List[str], default=None):
    """Safely get nested dictionary value."""
    current = dictionary
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current

def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def setup_logging(level: str = "INFO", log_file: str = None):
    """Configure logging with a clean format."""
    log_level = getattr(logging, level.upper())
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=handlers
    )