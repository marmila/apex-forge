import shodan
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ShodanClient:
    """Wrapper around Shodan API."""

    def __init__(self, api_key: str):
        self.client = shodan.Shodan(api_key)
        logger.info("Shodan client initialized")

    def host(self, ip: str) -> Dict[str, Any]:
        """Fetch host information from Shodan (public API: host)."""
        logger.info("Querying Shodan host API for %s", ip)
        return self.client.host(ip)

    # alias semantico, se ti serve in futuro
    def scan_host(self, ip: str) -> Dict[str, Any]:
        return self.host(ip)
