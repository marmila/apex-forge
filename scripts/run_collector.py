import sys

from shodan_monitor.config import Config, ConfigError
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.collector import ShodanCollector


def main() -> int:
    try:
        client = ShodanClient(Config.SHODAN_API_KEY)
        collector = ShodanCollector(client)
        collector.run(Config.TARGETS)
        return 0
    except ConfigError as e:
        print(f"Configuration error: {e}")
        return 2
    except Exception as e:
        print(f"Collector failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

