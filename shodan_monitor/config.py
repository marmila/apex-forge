"""
Configuration management for Shodan Security Monitor.
Optimized for K3s/Kustomize environment variable injection.
"""
import os
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Configuration error."""
    pass


class LogLevel(str, Enum):
    """Logging levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class DatabaseConfig:
    """Database configuration for k3s PostgreSQL."""
    host: str
    name: str
    user: str
    password: str
    port: int = 5432
    min_connections: int = 1
    max_connections: int = 10

    @classmethod
    def from_env(cls) -> 'DatabaseConfig':
        """
        Create DatabaseConfig from environment variables.
        Defaults match typical k3s/PostgreSQL setup.
        """
        return cls(
            # K3s service DNS name by default
            host=os.getenv("DB_HOST", "shodan-postgres.shodan-monitor.svc.cluster.local"),
            name=os.getenv("DB_NAME", "shodan"),
            user=os.getenv("DB_USER", "shodan"),
            password=os.getenv("DB_PASS", "shodan"),
            port=int(os.getenv("DB_PORT", "5432")),
            min_connections=int(os.getenv("DB_MIN_CONNECTIONS", "1")),
            max_connections=int(os.getenv("DB_MAX_CONNECTIONS", "10")),
        )

    def get_connection_string(self, show_password: bool = False) -> str:
        """Get PostgreSQL connection string."""
        password = self.password if show_password else "***"
        return f"postgresql://{self.user}:{password}@{self.host}:{self.port}/{self.name}"


@dataclass
class ShodanConfig:
    """Shodan API configuration."""
    api_key: str
    max_retries: int = 3
    request_delay: float = 1.0  # Seconds between requests
    timeout_seconds: int = 30   # API timeout

    @classmethod
    def from_env(cls) -> 'ShodanConfig':
        """
        Create ShodanConfig from environment variables.
        API key is REQUIRED from Kustomize secrets.
        """
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise ConfigError(
                "SHODAN_API_KEY environment variable is required. "
                "Check your Kustomize secrets.yaml"
            )

        return cls(
            api_key=api_key,
            max_retries=int(os.getenv("SHODAN_MAX_RETRIES", "3")),
            request_delay=float(os.getenv("REQUEST_DELAY", "1.0")),
            timeout_seconds=int(os.getenv("SHODAN_TIMEOUT", "30")),
        )


@dataclass
class CollectorConfig:
    """
    Collector runtime configuration.
    All values should come from Kustomize configMaps.
    """
    interval_seconds: int = 21600  # 6 hours default
    scan_timeout_minutes: int = 30  # Mark scans as timeout after this
    log_level: LogLevel = LogLevel.INFO
    enable_cleanup: bool = True    # Auto-cleanup stuck scans

    @classmethod
    def from_env(cls) -> 'CollectorConfig':
        """Create CollectorConfig from environment variables."""
        return cls(
            interval_seconds=int(os.getenv("INTERVAL_SECONDS", "21600")),
            scan_timeout_minutes=int(os.getenv("SCAN_TIMEOUT_MINUTES", "30")),
            log_level=LogLevel(os.getenv("LOG_LEVEL", "INFO").upper()),
            enable_cleanup=os.getenv("ENABLE_CLEANUP", "true").lower() == "true",
        )


class TargetManager:
    """
    Manages target IPs loaded from Kustomize environment variables.

    Kustomize should inject targets via environment variables like:
    - TARGETS_WEB="1.2.3.4,5.6.7.8"
    - TARGETS_DATABASE="10.0.0.1,10.0.0.2"
    - TARGETS_ALL (fallback for backward compatibility)
    """

    def __init__(self):
        self.groups: Dict[str, List[str]] = {}
        self.all_targets: List[str] = []
        self._load_targets()

    def _load_targets(self) -> None:
        """Load targets from all TARGETS_* environment variables."""
        for env_name, env_value in os.environ.items():
            if not env_name.startswith("TARGETS_"):
                continue

            group_name = env_name.replace("TARGETS_", "").lower()
            targets = self._parse_target_list(env_value)

            if targets:
                self.groups[group_name] = targets
                logger.info(f"Loaded target group '{group_name}' with {len(targets)} IPs")

        # Fallback for backward compatibility or simple setups
        if not self.groups:
            fallback = os.getenv("TARGETS")
            if fallback:
                targets = self._parse_target_list(fallback)
                if targets:
                    self.groups["default"] = targets
                    logger.info(f"Loaded {len(targets)} targets from TARGETS variable")

        if not self.groups:
            logger.warning("No TARGETS_* environment variables found")
            self.groups = {}
            self.all_targets = []
        else:
            # Flatten and deduplicate
            all_ips = set()
            for group_targets in self.groups.values():
                all_ips.update(group_targets)
            self.all_targets = sorted(all_ips)

    def _parse_target_list(self, value: str) -> List[str]:
        """
        Parse comma-separated IP list.
        Supports: "1.2.3.4, 5.6.7.8" or "1.2.3.4,5.6.7.8"
        """
        if not value:
            return []

        targets = []
        for item in value.split(","):
            item = item.strip()
            if item:
                # Basic IP validation
                if self._is_valid_ip(item):
                    targets.append(item)
                else:
                    logger.warning(f"Invalid IP address in target list: {item}")

        return targets

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Basic IP address validation."""
        import ipaddress
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def get_group(self, group_name: str) -> List[str]:
        """Get targets for a specific group."""
        return self.groups.get(group_name, []).copy()

    def get_all_targets(self) -> List[str]:
        """Get all unique targets."""
        return self.all_targets.copy()

    def get_groups(self) -> Dict[str, List[str]]:
        """Get all target groups."""
        return {k: v.copy() for k, v in self.groups.items()}

    def has_targets(self) -> bool:
        """Check if any targets are configured."""
        return len(self.all_targets) > 0

    def summary(self) -> str:
        """Get configuration summary (safe for logging)."""
        if not self.groups:
            return "No targets configured"

        summary_parts = []
        for group_name, targets in self.groups.items():
            # Show only first 2 IPs for security
            sample = targets[:2]
            sample_str = ", ".join(sample)
            if len(targets) > 2:
                sample_str += f", ... (+{len(targets)-2} more)"
            summary_parts.append(f"{group_name}: {sample_str}")

        return f"{len(self.all_targets)} targets in {len(self.groups)} groups: " + \
               "; ".join(summary_parts)


class Config:
    """
    Main configuration class for Shodan Security Monitor.
    Designed for K3s/Kustomize deployment.
    """

    def __init__(self):
        # Setup basic logging first
        self._setup_initial_logging()

        # Load configurations
        self.database = DatabaseConfig.from_env()
        self.shodan = ShodanConfig.from_env()
        self.collector = CollectorConfig.from_env()
        self.targets = TargetManager()

        # Validate
        self._validate()

        # Reconfigure logging with final level
        self._setup_final_logging()

        logger.info("Configuration loaded for k3s deployment")
        logger.info(f"Database: {self.database.get_connection_string()}")
        logger.info(f"Targets: {self.targets.summary()}")
        logger.info(f"Scan interval: {self.collector.interval_seconds}s "
                   f"({self.collector.interval_seconds/3600:.1f}h)")

    def _setup_initial_logging(self) -> None:
        """Setup basic logging before full config is loaded."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
            handlers=[logging.StreamHandler()]
        )

    def _setup_final_logging(self) -> None:
        """Reconfigure logging with the configured log level."""
        log_level = getattr(logging, self.collector.log_level.value)
        logging.getLogger().setLevel(log_level)
        logger.info(f"Log level set to {self.collector.log_level.value}")

    def _validate(self) -> None:
        """Validate configuration."""
        # Check we have targets
        if not self.targets.has_targets():
            logger.warning("No targets configured. Collector will run but scan nothing.")

        # Validate interval is reasonable
        if self.collector.interval_seconds < 60:
            logger.warning(f"Scan interval {self.collector.interval_seconds}s is very short. "
                          "Shodan may rate limit you.")

        # Log security notice
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("DEBUG logging enabled - IPs may be visible in logs")
        else:
            logger.info("INFO logging - IPs are hidden for security")

    def get_targets_for_scan(self, group_filter: Optional[str] = None) -> List[str]:
        """
        Get targets for scanning.

        Args:
            group_filter: Optional group name to scan only that group.
                         If None, scan all targets.

        Returns:
            List of IP addresses to scan.
        """
        if group_filter:
            targets = self.targets.get_group(group_filter)
            if not targets:
                logger.warning(f"No targets found in group '{group_filter}'")
            return targets
        else:
            return self.targets.get_all_targets()


# Global configuration instance
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """
    Get or create the global configuration instance.
    This should be called after environment variables are set (by k3s).
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance


def reload_config() -> Config:
    """
    Reload configuration from environment variables.
    Useful if environment variables change (e.g., in k3s after config update).
    """
    global _config_instance
    _config_instance = Config()
    return _config_instance