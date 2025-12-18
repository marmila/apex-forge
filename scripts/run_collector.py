import sys
import logging

from shodan_monitor.config import Config, ConfigError
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.collector import ShodanCollector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main() -> int:
    try:
        logger.info("Starting Shodan collector")
        client = ShodanClient(Config.SHODAN_API_KEY)
        collector = ShodanCollector(client)
        collector.run(Config.TARGETS)
        return 0

    except ConfigError as e:
        logger.error("Configuration error: %s", e)
        return 2

    except KeyboardInterrupt:
        logger.info("Collector interrupted by user")
        return 0

    except Exception:
        logger.exception("Collector crashed unexpectedly")
        return 1


if __name__ == "__main__":
    sys.exit(main())

