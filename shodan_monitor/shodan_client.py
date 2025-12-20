import time
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import backoff
import shodan
from shodan.exception import APIError

logger = logging.getLogger(__name__)


class ShodanErrorType(Enum):
    """Types of Shodan API errors"""
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    INVALID_IP = "invalid_ip"
    NO_INFORMATION = "no_information"
    NETWORK_ERROR = "network_error"
    UNKNOWN = "unknown"


@dataclass
class ShodanError:
    """Structured error information"""
    type: ShodanErrorType
    message: str
    ip: str
    retry_after: Optional[int] = None  # Seconds to wait before retry


@dataclass
class Service:
    """Structured service data"""
    port: int
    transport: str = "tcp"
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    vulns: List[str] = None
    cpe: List[str] = None
    ssl: Optional[Dict] = None

    def __post_init__(self):
        if self.vulns is None:
            self.vulns = []
        if self.cpe is None:
            self.cpe = []


@dataclass
class HostResult:
    """Structured host scan result"""
    ip: str
    services: List[Service]
    org: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    country_name: Optional[str] = None
    last_update: Optional[str] = None
    ports: List[int] = None
    tags: List[str] = None

    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.tags is None:
            self.tags = []


class ShodanClient:
    """
    Robust wrapper around the Shodan API with retries, rate limiting,
    and structured error handling.
    """

    def __init__(self, api_key: str, max_retries: int = 3, request_delay: float = 1.0):
        """
        Args:
            api_key: Shodan API key
            max_retries: Maximum number of retry attempts for failed requests
            request_delay: Base delay between requests (seconds)
        """
        if not api_key or api_key.strip() == "":
            raise ValueError("Shodan API key is required")

        self.client = shodan.Shodan(api_key)
        self.max_retries = max_retries
        self.request_delay = request_delay
        self.last_request_time = 0
        logger.info("Shodan client initialized (max_retries=%d, request_delay=%.1fs)",
                   max_retries, request_delay)

    def _enforce_rate_limit(self):
        """Enforce minimum delay between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.request_delay:
            sleep_time = self.request_delay - time_since_last
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _classify_error(self, error: Exception, ip: str) -> ShodanError:
        """Classify Shodan API errors into structured types"""
        error_str = str(error).lower()

        if "rate limit" in error_str:
            # Extract retry time if available
            retry_after = None
            if "retry after" in error_str:
                import re
                match = re.search(r'retry after (\d+)', error_str)
                if match:
                    retry_after = int(match.group(1))

            return ShodanError(
                type=ShodanErrorType.RATE_LIMITED,
                message=str(error),
                ip=ip,
                retry_after=retry_after
            )
        elif "not found" in error_str or "no information" in error_str:
            return ShodanError(
                type=ShodanErrorType.NOT_FOUND,
                message=str(error),
                ip=ip
            )
        elif "invalid" in error_str:
            return ShodanError(
                type=ShodanErrorType.INVALID_IP,
                message=str(error),
                ip=ip
            )
        else:
            return ShodanError(
                type=ShodanErrorType.UNKNOWN,
                message=str(error),
                ip=ip
            )

    @backoff.on_exception(
        backoff.expo,
        (APIError, ConnectionError, TimeoutError),
        max_tries=3,
        max_time=30
    )
    def host(self, ip: str, retry_on_rate_limit: bool = True) -> HostResult:
        """
        Fetch host information from Shodan with retry logic.

        Args:
            ip: IP address to scan
            retry_on_rate_limit: Whether to retry on rate limit errors

        Returns:
            HostResult with structured data

        Raises:
            ShodanError: If the request fails after all retries
        """
        logger.info("Querying Shodan host API for %s", ip)

        # Validate IP format
        if not self._validate_ip(ip):
            raise ShodanError(
                type=ShodanErrorType.INVALID_IP,
                message=f"Invalid IP address format: {ip}",
                ip=ip
            )

        for attempt in range(self.max_retries + 1):
            try:
                self._enforce_rate_limit()

                logger.debug("Shodan API call attempt %d/%d for %s",
                           attempt + 1, self.max_retries + 1, ip)

                result = self.client.host(ip)

                # Parse and structure the response
                host_result = self._parse_host_response(result, ip)

                logger.info(
                    "Shodan response received | ip=%s services=%d ports=%s",
                    ip,
                    len(host_result.services),
                    host_result.ports
                )

                return host_result

            except APIError as e:
                error = self._classify_error(e, ip)

                # Handle rate limiting
                if error.type == ShodanErrorType.RATE_LIMITED:
                    if retry_on_rate_limit and attempt < self.max_retries:
                        wait_time = error.retry_after or (2 ** attempt)  # Exponential backoff
                        logger.warning(
                            "Rate limited for %s, waiting %ds (attempt %d/%d)",
                            ip, wait_time, attempt + 1, self.max_retries + 1
                        )
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error("Rate limit exceeded for %s after %d attempts",
                                   ip, attempt + 1)
                        raise error

                # Handle not found/no information
                elif error.type == ShodanErrorType.NOT_FOUND:
                    logger.info("No information available for %s", ip)
                    return HostResult(ip=ip, services=[])

                # Other errors
                else:
                    if attempt < self.max_retries:
                        logger.warning(
                            "Shodan API error for %s: %s, retrying...",
                            ip, error.message
                        )
                        time.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    else:
                        logger.error(
                            "Failed to query Shodan for %s after %d attempts: %s",
                            ip, self.max_retries + 1, error.message
                        )
                        raise error

            except (ConnectionError, TimeoutError) as e:
                if attempt < self.max_retries:
                    logger.warning(
                        "Network error for %s: %s, retrying...",
                        ip, str(e)
                    )
                    time.sleep(2 ** attempt)
                    continue
                else:
                    error = ShodanError(
                        type=ShodanErrorType.NETWORK_ERROR,
                        message=str(e),
                        ip=ip
                    )
                    logger.error(
                        "Network error for %s after %d attempts: %s",
                        ip, self.max_retries + 1, error.message
                    )
                    raise error

            except Exception as e:
                logger.exception("Unexpected error while querying Shodan for %s", ip)
                raise ShodanError(
                    type=ShodanErrorType.UNKNOWN,
                    message=str(e),
                    ip=ip
                )

        # Should never reach here
        raise ShodanError(
            type=ShodanErrorType.UNKNOWN,
            message=f"Failed to query {ip} after {self.max_retries + 1} attempts",
            ip=ip
        )

    def _validate_ip(self, ip: str) -> bool:
        """Basic IP validation"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _parse_host_response(self, result: Dict[str, Any], ip: str) -> HostResult:
        """Parse Shodan API response into structured HostResult"""
        services = []
        ports = []

        for item in result.get("data", []):
            service = Service(
                port=item.get("port"),
                transport=item.get("transport", "tcp"),
                product=item.get("product"),
                version=item.get("version"),
                banner=item.get("data"),
                vulns=list(item.get("vulns", [])),
                cpe=list(item.get("cpe", [])),
                ssl=item.get("ssl")
            )
            services.append(service)
            ports.append(service.port)

        return HostResult(
            ip=ip,
            services=services,
            org=result.get("org"),
            asn=result.get("asn"),
            country=result.get("country_code"),
            country_name=result.get("country_name"),
            last_update=result.get("last_update"),
            ports=ports,
            tags=result.get("tags", [])
        )

    def extract_services(self, result: HostResult) -> List[Service]:
        """Extract services from HostResult (backward compatibility)"""
        return result.services

    # Semantic alias, kept for backward compatibility
    def scan_host(self, ip: str) -> Dict[str, Any]:
        """
        Legacy method that returns raw Shodan response.
        Use host() method for new code.
        """
        result = self.host(ip)

        # Convert back to raw format for backward compatibility
        raw_result = {
            "data": [
                {
                    "port": svc.port,
                    "transport": svc.transport,
                    "product": svc.product,
                    "version": svc.version,
                    "data": svc.banner,
                    "vulns": svc.vulns,
                    "cpe": svc.cpe,
                    "ssl": svc.ssl
                }
                for svc in result.services
            ],
            "org": result.org,
            "asn": result.asn,
            "country_name": result.country_name,
            "last_update": result.last_update
        }

        return raw_result


class ShodanClientPool:
    """Pool of Shodan clients for multiple API keys (future use)"""

    def __init__(self, api_keys: List[str]):
        if not api_keys:
            raise ValueError("At least one API key is required")

        self.clients = [ShodanClient(key) for key in api_keys]
        self.current_index = 0
        logger.info("Initialized Shodan client pool with %d keys", len(api_keys))

    def get_client(self) -> ShodanClient:
        """Get next client in round-robin fashion"""
        client = self.clients[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.clients)
        return client

    def host(self, ip: str) -> HostResult:
        """Query Shodan using client pool"""
        # Simple round-robin for now
        client = self.get_client()
        return client.host(ip)