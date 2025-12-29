import time
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from apex_forge.config import get_config
from apex_forge.shodan_client import ShodanClient
from apex_forge.db import (
    save_raw_banner,
    update_intel_stats,
    log_intel_history,
    close_connections,
    init_databases,
    get_last_checkpoint
)
from apex_forge.utils import GracefulShutdown, Timer, format_duration

logger = logging.getLogger(__name__)

@dataclass
class IntelligenceStats:
    """Statistics for an intelligence collection cycle."""
    profile_name: str
    total_processed: int = 0
    new_banners: int = 0
    errors: int = 0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class ShodanCollector:
    """
    Main collector for Shodan Intelligence Sentinel.
    Iterates through threat profiles and performs global searches with incremental support.
    """

    def __init__(self, shodan_client: ShodanClient):
        self.client = shodan_client
        self.config = get_config()
        init_databases()

    def run(self):
        """Main execution loop optimized for k3s."""
        logger.info("Starting Shodan Intelligence Sentinel collector loop")

        with GracefulShutdown() as shutdown:
            while not shutdown.should_exit:
                loop_timer = Timer("main_loop")
                with loop_timer:
                    self.collect_all_profiles(shutdown)

                # --- SHODAN QUOTA REPORT (v2.0.2) ---
                if not shutdown.should_exit:
                    try:
                        api_info = self.client.get_api_info()
                        credits = api_info.get('query_credits', 'N/A')
                        plan = api_info.get('plan', 'N/A')

                        logger.info("--- SHODAN QUOTA REPORT ---")
                        logger.info(f"Plan: {plan.upper()}")
                        logger.info(f"Remaining Query Credits: {credits}")
                        logger.info("---------------------------")
                    except Exception as e:
                        logger.warning(f"Could not retrieve Shodan quota report: {e}")
                # ------------------------------------

                if shutdown.should_exit:
                    break

                interval = self.config.shodan.scan_interval
                logger.info(f"Cycle completed in {format_duration(loop_timer.duration)}. "
                            f"Sleeping for {interval} seconds...")

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
        """Executes incremental search for a profile and updates storage."""
        name = profile['name']
        base_query = profile['query']
        stats = IntelligenceStats(profile_name=name)

        # Check for existing checkpoint to enable incremental ingest
        last_checkpoint = get_last_checkpoint(name)
        active_query = base_query

        if last_checkpoint:
            # Shodan date format for filters is DD/MM/YYYY
            date_str = last_checkpoint.strftime("%d/%m/%Y")
            active_query = f"{base_query} after:{date_str}"
            logger.info(f"Using incremental filter for {name}: {date_str}")
        else:
            logger.info(f"No checkpoint found for {name}. Performing full collection.")

        country_distribution = {}

        try:
            for banner in self.client.search_intel(active_query):
                if shutdown.should_exit:
                    break

                save_raw_banner(banner, name)

                stats.total_processed += 1
                location = banner.get('location')
                country_code = location.get('country_code', 'Unknown') if location else 'Unknown'

                country_distribution[country_code] = country_distribution.get(country_code, 0) + 1

                if stats.total_processed % 100 == 0:
                    logger.info(f"[{name}] Processed {stats.total_processed} banners...")

            logger.info(f"Completed profile {name}: {stats.total_processed} banners processed.")

        except Exception as e:
            logger.error(f"Error processing profile {name} at banner {stats.total_processed}: {e}")
            stats.errors += 1

        finally:
            # v2.0.3: Always save progress if at least one banner was processed.
            # This ensures checkpoints are updated even if the API cursor fails mid-run.
            if stats.total_processed > 0:
                logger.info(f"Saving partial progress for {name}: {stats.total_processed} assets.")
                update_intel_stats(name, stats.total_processed, country_distribution)
                log_intel_history(name, stats.total_processed)

    def run_once(self):
        """Run a single collection cycle across all profiles."""
        logger.info("Executing single collection run")
        with GracefulShutdown() as shutdown:
            self.collect_all_profiles(shutdown)
        close_connections()









