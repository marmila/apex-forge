import argparse
import logging
import sys
from shodan_monitor.config import get_config
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.collector import ShodanCollector
from shodan_monitor.db import get_database_stats

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("shodan.runner")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Shodan Intelligence Sentinel Runner")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single collection cycle across all profiles and exit"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Display high-level database and intelligence statistics"
    )
    return parser.parse_args()

def show_stats():
    """Display current intelligence statistics from the database."""
    stats = get_database_stats()
    print("\n--- Shodan Intelligence Sentinel Stats ---")
    print(f"Active Threat Profiles:   {stats.get('active_profiles', 0)}")
    print(f"Total Exposed Assets:     {stats.get('total_exposed_assets', 0)}")
    print("------------------------------------------\n")

def main():
    args = parse_args()
    config = get_config()

    if args.stats:
        show_stats()
        sys.exit(0)

    if not config.shodan.api_key:
        logger.error("SHODAN_API_KEY is missing in environment variables.")
        sys.exit(1)

    # Initialize components
    client = ShodanClient(
        api_key=config.shodan.api_key,
        max_retries=config.shodan.max_retries,
        request_delay=config.shodan.request_delay
    )

    collector = ShodanCollector(shodan_client=client)

    try:
        if args.once:
            collector.run_once()
        else:
            collector.run()
    except KeyboardInterrupt:
        logger.info("Runner interrupted by user")
    except Exception as e:
        logger.error(f"Critical error in runner: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

