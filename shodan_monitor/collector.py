import time
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from shodan_monitor.config import get_config
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.db import (
    save_raw_banner,
    update_intel_stats,
    log_intel_history,
    get_database_stats,
    close_connections,
    init_databases
)
from shodan_monitor.utils import GracefulShutdown, Timer, format_duration

logger = logging.getLogger(__name__)

@dataclass
class IntelligenceStats:
    """Statistics for an intelligence collection cycle."""
    profile_name: str
    total_processed: int = 0
    new_banners: int = 0
    errors: int = 0
    start_time: Optional[datetime] = None

class ShodanCollector:
    """
    Main collector for Shodan Intelligence Sentinel.
    Iterates through threat profiles and performs global searches.
    """

    def __init__(self, shodan_client: ShodanClient):
        self.client = shodan_client
        self.config = get_config()
        # Ensure DB tables exist
        init_databases()

    def run(self):
        """
        Main execution loop. Optimized for Kubernetes (k3s) deployment.
        """
        logger.info("Starting Shodan Intelligence Sentinel collector loop")

        with GracefulShutdown() as shutdown:
            while not shutdown.should_exit:
                loop_timer = Timer("main_loop")
                with loop_timer:
                    self.collect_all_profiles(shutdown)

                if shutdown.should_exit:
                    break

                interval = self.config.shodan.scan_interval
                logger.info(f"Cycle completed in {format_duration(loop_timer.duration)}. "
                            f"Sleeping for {interval} seconds...")

                # Sleep in small increments to remain responsive to shutdown signals
                stop_time = datetime.utcnow() + tuple([0, 0, interval]) # simplified for example
                wait_until = time.time() + interval
                while time.time() < wait_until and not shutdown.should_exit:
                    time.sleep(5)

        logger.info("Collector shutting down gracefully")
        close_connections()

    def collect_all_profiles(self, shutdown: GracefulShutdown):
        """Iterate through all configured intelligence profiles."""
        profiles = self.config.load_profiles()

        for profile in profiles:
            if shutdown.should_exit:
                break

            profile_name = profile.get('name', 'unknown')
            query = profile.get('query')

            if not query:
                logger.warning(f"Profile {profile_name} has no query. Skipping.")
                continue

            logger.info(f"Processing intelligence profile: {profile_name}")
            self._process_profile(profile, shutdown)

    def _process_profile(self, profile: Dict[str, Any], shutdown: GracefulShutdown):
        """
        Executes search for a specific profile and updates both MongoDB and PostgreSQL.
        """
        name = profile['name']
        query = profile['query']
        stats = IntelligenceStats(profile_name=name, start_time=datetime.utcnow())

        country_distribution = {}

        try:
            # Using cursor-based search for efficiency
            for banner in self.client.search_intel(query):
                if shutdown.should_exit:
                    break

                # 1. Save raw data to MongoDB for forensics
                save_raw_banner(banner, name)

                # 2. Update local aggregation for PostgreSQL
                stats.total_processed += 1
                country_code = banner.get('location', {}).get('country_code', 'Unknown')
                country_distribution[country_code] = country_distribution.get(country_code, 0) + 1

                if stats.total_processed % 100 == 0:
                    logger.info(f"[{name}] Processed {stats.total_processed} banners...")

            # 3. Finalize analytics in PostgreSQL
            update_intel_stats(name, stats.total_processed, country_distribution)
            log_intel_history(name, stats.total_processed)

            logger.info(f"Completed profile {name}: {stats.total_processed} total assets found.")

        except Exception as e:
            logger.error(f"Error processing profile {name}: {e}")
            stats.errors += 1

    def run_once(self):
        """Run a single collection cycle across all profiles."""
        logger.info("Executing single collection run")
        with GracefulShutdown() as shutdown:
            self.collect_all_profiles(shutdown)
        close_connections()








