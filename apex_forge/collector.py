import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

from apex_forge.config import get_config
from apex_forge.shodan_client import ShodanClient
from apex_forge.db import (
    save_raw_banner,
    update_intel_stats,
    log_intel_history,
    close_connections,
    init_databases,
    get_last_checkpoint,
)
from apex_forge.utils import GracefulShutdown, Timer
from apex_forge.risk_scorer import RiskScorer
from apex_forge.enrichment import Enricher
from prometheus_client import Counter, Gauge, Histogram, start_http_server

logger = logging.getLogger("apexforge.collector")

# Prometheus metrics
BANNERS_PROCESSED = Counter(
    "apexforge_banners_processed_total",
    "Total number of banners processed",
    ["profile", "risk_level"]
)
BANNERS_ENRICHED = Counter(
    "apexforge_banners_enriched_total",
    "Number of banners enriched with InternetDB",
    ["profile"]
)
COLLECTION_DURATION = Histogram(
    "apexforge_collection_duration_seconds",
    "Duration of collection cycle per profile",
    ["profile"]
)
CURRENT_RISK_GAUGE = Gauge(
    "apexforge_current_high_critical_assets",
    "Current number of high/critical risk assets across all profiles"
)

@dataclass
class IntelligenceStats:
    profile_name: str
    total_processed: int = 0
    errors: int = 0
    high_critical_count: int = 0
    total_risk_sum: float = 0.0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class ApexForgeCollector:
    """
    Main collector for ApexForge – threat exposure hunting & risk analysis.
    """

    def __init__(self, shodan_client: ShodanClient):
        self.client = shodan_client
        self.config = get_config()
        self.risk_scorer = RiskScorer()
        self.enricher = Enricher(vt_api_key=self.config.shodan.vt_api_key)
        init_databases()

        start_http_server(8000)
        logger.info("Prometheus metrics server started on :8000")

    def collect_all_profiles(self, shutdown: GracefulShutdown):
        profiles = self.config.load_profiles()
        if not profiles:
            logger.warning("No intelligence profiles loaded – check profiles.yaml")
            return

        for profile_dict in profiles:
            if shutdown.should_exit:
                break

            name = profile_dict["name"]
            base_query = profile_dict["query"]
            enrich_internetdb = profile_dict.get("enrich_with_internetdb", True)
            max_results = profile_dict.get("max_results")  # NEW: Extract limit from profile

            stats = IntelligenceStats(profile_name=name)
            with COLLECTION_DURATION.labels(profile=name).time():
                self._process_profile(
                    name=name,
                    base_query=base_query,
                    stats=stats,
                    shutdown=shutdown,
                    enrich_internetdb=enrich_internetdb,
                    max_results=max_results  # NEW: Pass to processor
                )

            if stats.high_critical_count > 0:
                CURRENT_RISK_GAUGE.inc(stats.high_critical_count)

    def _process_profile(
        self,
        name: str,
        base_query: str,
        stats: IntelligenceStats,
        shutdown: GracefulShutdown,
        enrich_internetdb: bool,
        max_results: Optional[int] = None  # NEW: Accept limit
    ):
        logger.info(f"Starting collection for profile: {name} | Query: {base_query}")
        if max_results:
            logger.info(f"Limit set to {max_results} banners")

        last_checkpoint = get_last_checkpoint(name)
        if last_checkpoint:
            date_str = last_checkpoint.strftime("%d/%m/%Y")
            active_query = f"{base_query} after:{date_str}"
            logger.info(f"Incremental mode – using date filter: after:{date_str}")
        else:
            active_query = base_query
            logger.info("No checkpoint – performing full collection")

        country_distribution: Dict[str, int] = {}

        try:
            # NEW: Pass max_results to search_intel
            for banner in self.client.search_intel(active_query, limit=max_results):
                if shutdown.should_exit:
                    break

                # Risk scoring
                risk_analysis = self.risk_scorer.analyze_banner(banner)
                banner.setdefault("sis_metadata", {})["risk_analysis"] = risk_analysis

                # InternetDB enrichment
                if enrich_internetdb:
                    ip = banner.get("ip_str")
                    if ip:
                        enrichment = self.client.get_internetdb_data(ip)
                        if enrichment:
                            banner["internetdb_enrichment"] = enrichment
                            BANNERS_ENRICHED.labels(profile=name).inc()

                # Multi-source enrichment
                vt_data = self.enricher.enrich_with_virustotal(banner)
                if vt_data:
                    banner.setdefault("sis_metadata", {})["virustotal"] = vt_data

                cve_data = self.enricher.enrich_with_cvedb(banner)
                if cve_data:
                    banner["vulns_enriched"] = cve_data

                # Save to MongoDB
                save_raw_banner(banner, name)

                # Stats tracking
                stats.total_processed += 1

                if risk_analysis["level"] in ("HIGH", "CRITICAL"):
                    stats.high_critical_count += 1
                    stats.total_risk_sum += risk_analysis["score"]

                # Country distribution
                location = banner.get("location", {})
                country_code = location.get("country_code", "Unknown")
                country_distribution[country_code] = country_distribution.get(country_code, 0) + 1

                BANNERS_PROCESSED.labels(profile=name, risk_level=risk_analysis["level"]).inc()

                if stats.total_processed % 100 == 0:
                    avg_risk = stats.total_risk_sum / stats.total_processed if stats.total_processed > 0 else 0
                    logger.info(
                        f"[{name}] Processed {stats.total_processed} banners "
                        f"(High/Critical: {stats.high_critical_count}, Avg Risk: {avg_risk:.2f})"
                    )

            logger.info(
                f"Completed profile {name}: {stats.total_processed} banners, "
                f"{stats.high_critical_count} high/critical"
            )

        except Exception as e:
            logger.error(f"Error processing profile {name} at banner {stats.total_processed}: {e}", exc_info=True)
            stats.errors += 1

        finally:
            if stats.total_processed > 0:
                update_intel_stats(
                    name,
                    stats.total_processed,
                    country_distribution,
                    high_critical_new=stats.high_critical_count,
                    total_risk_sum=stats.total_risk_sum
                )
                log_intel_history(
                    name,
                    stats.total_processed,
                    high_critical_new=stats.high_critical_count
                )

    def run(self):
        logger.info("Starting ApexForge continuous collection loop")
        with GracefulShutdown() as shutdown:
            while not shutdown.should_exit:
                loop_timer = Timer("full_cycle")
                with loop_timer:
                    self.collect_all_profiles(shutdown)

                if not shutdown.should_exit:
                    time.sleep(self.config.shodan.scan_interval)

    def run_once(self):
        logger.info("Executing single collection run (--once)")
        with GracefulShutdown() as shutdown:
            self.collect_all_profiles(shutdown)
        close_connections()








