"""
Configuration management for ApexForge.
Optimized for K3s environment variable injection and YAML-based threat profiles.
"""
import os
import logging
import yaml
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pydantic import ValidationError
from apex_forge.models import IntelProfile

logger = logging.getLogger("apexforge.config")

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
    db_name: str = os.getenv("MONGO_DB_NAME", "apexforge_intelligence")
    collection: str = os.getenv("MONGO_COLLECTION", "raw_banners")

@dataclass
class ShodanConfig:
    """Shodan API configuration."""
    api_key: str = os.getenv("SHODAN_API_KEY", "")
    vt_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    max_retries: int = int(os.getenv("MAX_RETRIES", "3"))
    request_delay: float = float(os.getenv("REQUEST_DELAY", "1.0"))
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
        # Only try Vault fallback if api_key is empty
        if not self.shodan.api_key:
            try:
                import hvac
                client = hvac.Client(url=os.getenv("VAULT_ADDR"))
                if client.is_authenticated():
                    secret = client.secrets.kv.v2.read_secret_version(path='shodan/api_key')
                    self.shodan.api_key = secret['data']['data']['value']
                    logger.info("Loaded SHODAN_API_KEY from Vault")
                else:
                    logger.warning("Vault authentication failed")
            except Exception as e:
                logger.debug(f"Vault not available or failed: {e}")

        # ONLY warn if key missing — do NOT raise error
        # The collector will fail later if needed, but init jobs can proceed
        if not self.shodan.api_key:
            logger.warning("SHODAN_API_KEY not found in env or Vault — collection will be disabled")

    def load_profiles(self) -> List[IntelProfile]:
        if not os.path.exists(self.profiles_path):
            logger.error(f"Profiles file not found at: {self.profiles_path}")
            return []

        try:
            with open(self.profiles_path, 'r') as f:
                data = yaml.safe_load(f)
                raw_profiles = data.get('intelligence_profiles', [])
                profiles = [IntelProfile(**p) for p in raw_profiles]
                logger.info(f"Loaded and validated {len(profiles)} intelligence profiles")
                return profiles
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML profiles: {e}")
            return []
        except ValidationError as e:
            logger.error(f"Profile validation failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error loading profiles: {e}")
            return []

# Global configuration instance
_config_instance: Optional[Config] = None

def get_config() -> Config:
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance

def reload_config() -> Config:
    global _config_instance
    _config_instance = Config()
    return _config_instance