import shodan
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ShodanClient:
    """
    Wrapper around the Shodan API.

    This class is responsible for:
    - calling the Shodan API
    - handling Shodan-specific errors
    - returning raw but predictable data structures
    """

    def __init__(self, api_key: str):
        self.client = shodan.Shodan(api_key)
        logger.info("Shodan client initialized")

    def host(self, ip: str) -> Dict[str, Any]:
        """
        Fetch host information from Shodan using the public host API.

        Returns the full Shodan response for the given IP.
        """
        logger.info("Querying Shodan host API for %s", ip)

        try:
            result = self.client.host(ip)
        except shodan.APIError as e:
            # Shodan-specific API errors (rate limit, not found, etc.)
            logger.error("Shodan API error for %s: %s", ip, e)
            raise
        except Exception:
            # Any other unexpected error
            logger.exception("Unexpected error while querying Shodan for %s", ip)
            raise

        services = result.get("data", [])
        logger.info(
            "Shodan response received | ip=%s services=%d",
            ip,
            len(services),
        )

        return result

    def extract_services(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract and normalize service-level data from a Shodan host result.

        This method isolates Shodan's data format from the rest of the codebase.
        """
        services: List[Dict[str, Any]] = []

        for item in result.get("data", []):
            services.append(
                {
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "banner": item.get("data"),
                    "vulns": item.get("vulns", []),
                    "cpe": item.get("cpe", []),
                }
            )

        return services

    # Semantic alias, kept for backward compatibility / future usage
    def scan_host(self, ip: str) -> Dict[str, Any]:
        return self.host(ip)
