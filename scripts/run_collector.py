import argparse
import logging
import sys
import os

from apex_forge.config import get_config
from apex_forge.shodan_client import ShodanClient
from apex_forge.collector import ApexForgeCollector  # <-- CORRETTO: nome classe aggiornato
from apex_forge.db import get_database_stats
from apex_forge.utils import setup_structured_logging

# Setup structured JSON logging for Kibana/ELK
setup_structured_logging(level=os.getenv("LOG_LEVEL", "INFO"))

logger = logging.getLogger("apexforge.collector")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="ApexForge Collector Runner")
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
    print("\n=== ApexForge Intelligence Stats ===")
    print(f"Active Threat Profiles:     {stats.get('active_profiles', 0)}")
    print(f"Total Exposed Assets:       {stats.get('total_exposed_assets', 0)}")
    print(f"Total High/Critical Assets: {stats.get('total_high_critical_assets', 0)}")
    print("========================================\n")

def main():
    args = parse_args()
    config = get_config()

    if args.stats:
        show_stats()
        sys.exit(0)

    if not config.shodan.api_key:
        logger.error("SHODAN_API_KEY is missing from environment (injected via Vault secret 'shodan-secret')")
        sys.exit(1)

    logger.info("Initializing ApexForge collector")

    # Initialize Shodan client
    client = ShodanClient(
        api_key=config.shodan.api_key,
        max_retries=config.shodan.max_retries,
        request_delay=config.shodan.request_delay
    )

    collector = ApexForgeCollector(shodan_client=client)  # <-- CORRETTO: classe giusta

    try:
        if args.once:
            logger.info("Running single collection cycle (--once)")
            collector.run_once()
        else:
            logger.info("Starting continuous collection loop")
            collector.run()
    except KeyboardInterrupt:
        logger.info("ApexForge collector interrupted by user")
    except Exception as e:
        logger.error(f"Critical error in ApexForge collector: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()

