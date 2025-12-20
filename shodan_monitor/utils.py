"""
Utility functions for Shodan Security Monitor.
"""
import logging
import signal
import sys
import time
from datetime import datetime, timedelta
from typing import List, Tuple
import ipaddress


logger = logging.getLogger(__name__)


class GracefulShutdown:
    """
    Context manager for graceful shutdown handling.
    """
    def __init__(self, shutdown_callback=None):
        self.shutdown_callback = shutdown_callback
        self.should_exit = False

    def __enter__(self):
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup
        if self.shutdown_callback:
            self.shutdown_callback()

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.should_exit = True


class Timer:
    """Context manager for timing code blocks."""

    def __init__(self, name: str = "operation"):
        self.name = name
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        self.start_time = datetime.utcnow()
        logger.debug(f"Starting {self.name}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = datetime.utcnow()
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
            return (datetime.utcnow() - self.start_time).total_seconds()
        return 0.0


def validate_ip_list(ips: List[str]) -> Tuple[List[str], List[str]]:
    """
    Validate a list of IP addresses.

    Returns:
        Tuple of (valid_ips, invalid_ips)
    """
    valid = []
    invalid = []

    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue

        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            invalid.append(ip)

    return valid, invalid


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def safe_get(dictionary: dict, keys: List[str], default=None):
    """
    Safely get nested dictionary value.

    Args:
        dictionary: Dictionary to search
        keys: List of keys to traverse
        default: Default value if key not found

    Returns:
        Value or default
    """
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


def parse_time_string(time_str: str) -> timedelta:
    """
    Parse time string like '1h', '30m', '2d' to timedelta.

    Args:
        time_str: Time string (e.g., '1h', '30m', '2d')

    Returns:
        timedelta
    """
    time_str = time_str.lower().strip()

    if time_str.endswith('s'):
        seconds = int(time_str[:-1])
        return timedelta(seconds=seconds)
    elif time_str.endswith('m'):
        minutes = int(time_str[:-1])
        return timedelta(minutes=minutes)
    elif time_str.endswith('h'):
        hours = int(time_str[:-1])
        return timedelta(hours=hours)
    elif time_str.endswith('d'):
        days = int(time_str[:-1])
        return timedelta(days=days)
    else:
        # Assume seconds if no unit
        seconds = int(time_str)
        return timedelta(seconds=seconds)


def setup_logging(level: str = "INFO", log_file: str = None):
    """
    Configure logging for the application.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to log to (in addition to stdout)
    """
    log_level = getattr(logging, level.upper())

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=handlers
    )