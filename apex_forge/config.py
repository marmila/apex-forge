"""
Configuration management for Shodan Intelligence Sentinel (SIS).
Optimized for K3s environment variable injection and YAML-based threat profiles.
"""
import os
import logging
import yaml
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class ConfigError(Exception):
    """Configuration error."""
    pass

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class DatabaseConfig:
    """PostgreSQL configuration for structured analytics."""
    host: str = os.getenv("DB_HOST", "shodan-postgres.shodan-monitor.svc.cluster.local")
    name: str = os.getenv("DB_NAME", "shodan")
    user: str = os.getenv("DB_USER", "shodan")
    password: str = os.getenv("DB_PASS", "shodan")
    port: int = int(os.getenv("DB_PORT", "5432"))
    min_connections: int = 1
    max_connections: int = 10

@dataclass
class MongoConfig:
    """MongoDB configuration for raw banner storage."""
    uri: str = os.getenv("MONGO_URL", "mongodb://localhost:27017")
    db_name: str = os.getenv("MONGO_DB_NAME", "shodan_intelligence")
    collection: str = os.getenv("MONGO_COLLECTION", "raw_banners")

@dataclass
class ShodanConfig:
    """Shodan API configuration."""
    api_key: str = os.getenv("SHODAN_API_KEY", "")
    max_retries: int = int(os.getenv("MAX_RETRIES", "3"))
    request_delay: float = float(os.getenv("REQUEST_DELAY", "1.0"))
    # In un'ottica Threat Intel, l'intervallo è globale tra i profili
    scan_interval: int = int(os.getenv("INTERVAL_SECONDS", "21600"))

@dataclass
class Config:
    """Main configuration object."""
    shodan: ShodanConfig = field(default_factory=ShodanConfig)
    db: DatabaseConfig = field(default_factory=DatabaseConfig)
    mongo: MongoConfig = field(default_factory=MongoConfig)

    profiles_path: str = os.getenv("PROFILES_PATH", "profiles.yaml")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    def __post_init__(self):
        if not self.shodan.api_key:
            logger.warning("SHODAN_API_KEY is not set. Collector will fail to run.")

    def load_profiles(self) -> List[Dict[str, Any]]:
        """
        Loads intelligence profiles from the YAML file.
        Returns a list of dictionaries representing search targets.
        """
        if not os.path.exists(self.profiles_path):
            logger.error(f"Profiles file not found at: {self.profiles_path}")
            return []

        try:
            with open(self.profiles_path, 'r') as f:
                data = yaml.safe_load(f)
                profiles = data.get('intelligence_profiles', [])
                logger.info(f"Loaded {len(profiles)} intelligence profiles from {self.profiles_path}")
                return profiles
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML profiles: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error loading profiles: {e}")
            return []

# Global configuration instance
_config_instance: Optional[Config] = None

def get_config() -> Config:
    """Get or create the global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance

def reload_config() -> Config:
    """Reload configuration from environment variables."""
    global _config_instance
    _config_instance = Config()
    return _config_instance