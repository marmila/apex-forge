import time
import logging
from typing import Dict, Any, List, Optional, Generator
from dataclasses import dataclass
from enum import Enum
import backoff
import shodan
import requests
from shodan.exception import APIError

logger = logging.getLogger(__name__)

class ShodanErrorType(Enum):
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    INVALID_IP = "invalid_ip"
    NO_INFORMATION = "no_information"
    NETWORK_ERROR = "network_error"
    UNKNOWN = "unknown"

@dataclass
class ShodanError:
    type: ShodanErrorType
    message: str
    query: str
    retry_after: Optional[int] = None

class ShodanClient:
    """
    Enhanced Shodan Client for Threat Intelligence.
    Supports Search API, Cursor-based results, and InternetDB enrichment.
    """

    INTERNETDB_URL = "https://internetdb.shodan.io/"

    def __init__(self, api_key: str, max_retries: int = 5, request_delay: float = 2.0):
        if not api_key:
            raise ValueError("Shodan API key is required")

        self.api = shodan.Shodan(api_key)
        self.max_retries = max_retries
        self.request_delay = request_delay

    @backoff.on_exception(
        backoff.expo,
        (APIError, requests.exceptions.RequestException),
        max_tries=10,
        max_time=300,
        giveup=lambda e: isinstance(e, APIError) and "Rate limit" not in str(e)
    )
    def search_intel(self, query: str, limit: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Global search using search_cursor (efficient for Freelancer plan).
        Yields raw banners from Shodan.
        """
        logger.info(f"Executing global threat search: {query}")
        try:
            cursor = self.api.search_cursor(query)
            count = 0

            for banner in cursor:
                yield banner
                count += 1
                if limit and count >= limit:
                    break

                if count % 100 == 0:
                    time.sleep(self.request_delay)

        except APIError as e:
            logger.error(f"Shodan Search API Error: {e}")
            raise

    def get_internetdb_data(self, ip: str) -> Optional[Dict[str, Any]]:
        """Fetches rapid enrichment data from InternetDB (Free, no credits used)."""
        try:
            response = requests.get(f"{self.INTERNETDB_URL}{ip}", timeout=5)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.debug(f"InternetDB enrichment failed for {ip}: {e}")
            return None

    @backoff.on_exception(backoff.expo, APIError, max_tries=3)
    def get_host_details(self, ip: str) -> Dict[str, Any]:
        """Deep lookup for a specific host. Consumes 1 Shodan credit."""
        try:
            time.sleep(self.request_delay)
            return self.api.host(ip)
        except APIError as e:
            logger.error(f"Error fetching host details for {ip}: {e}")
            raise

    def get_api_info(self) -> Dict[str, Any]:
        """Check API key limits and plan information."""
        try:
            return self.api.info()
        except Exception as e:
            logger.error(f"Failed to fetch Shodan API info: {e}")
            return {}

class ShodanClientPool:
    """Pool of Shodan clients to handle multiple API keys if needed."""
    def __init__(self, api_keys: List[str]):
        if not api_keys:
            raise ValueError("At least one API key is required")
        self.clients = [ShodanClient(key) for key in api_keys]
        self.current_index = 0

    def get_client(self) -> ShodanClient:
        client = self.clients[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.clients)
        return client