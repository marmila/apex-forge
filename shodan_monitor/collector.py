"""
Main collector for Shodan Security Monitor.
Designed for reliable operation in k3s with proper error handling and state management.
"""
import time
import logging
import signal
import sys
from datetime import datetime, timedelta
from typing import List, Optional
from dataclasses import dataclass
from contextlib import contextmanager

from shodan_monitor.config import get_config, Config
from shodan_monitor.shodan_client import ShodanClient, ShodanError, HostResult, Service
from shodan_monitor.db import (
    create_scan_run,
    update_scan_run,
    upsert_target,
    insert_service,
    batch_insert_services,
    cleanup_stuck_scans,
    get_database_stats,
)
from shodan_monitor.utils import GracefulShutdown, Timer, validate_ip_list, format_duration

logger = logging.getLogger(__name__)


@dataclass
class ScanStatistics:
    """Statistics for a scan run."""
    total_targets: int = 0
    successful_targets: int = 0
    failed_targets: int = 0
    total_services: int = 0
    total_vulnerabilities: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def duration(self) -> float:
        """Get scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.utcnow() - self.start_time).total_seconds()
        return 0.0

    @property
    def success_rate(self) -> float:
        """Get success rate as percentage."""
        if self.total_targets == 0:
            return 0.0
        return (self.successful_targets / self.total_targets) * 100


class ShodanCollector:
    """
    Robust Shodan data collector with proper state management.

    Features:
    - Graceful shutdown handling
    - Comprehensive error recovery
    - Progress tracking and logging
    - Automatic cleanup of stuck scans
    - Batch processing for efficiency
    """

    def __init__(self, client: ShodanClient):
        """
        Initialize collector.

        Args:
            client: ShodanClient instance
        """
        self.client = client
        self.config = get_config()
        self.should_stop = False

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info(
            "ShodanCollector initialized | targets=%d | interval=%ds | delay=%.1fs",
            len(self.config.targets.get_all_targets()),
            self.config.collector.interval_seconds,
            self.config.shodan.request_delay
        )

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.should_stop = True

    def run(self, group_filter: Optional[str] = None) -> None:
        """
        Main collector loop.

        Args:
            group_filter: Optional target group to scan. If None, scans all targets.
        """
        logger.info("Starting collector main loop")

        # Get targets to scan
        targets = self.config.get_targets_for_scan(group_filter)
        if not targets:
            logger.error("No targets to scan. Exiting.")
            return

        # Validate IPs
        valid_ips, invalid_ips = validate_ip_list(targets)
        if invalid_ips:
            logger.warning(f"Invalid IP addresses ignored: {invalid_ips}")

        if not valid_ips:
            logger.error("No valid IP addresses to scan. Exiting.")
            return

        logger.info(f"Starting scan loop with {len(valid_ips)} valid targets")

        # Main loop
        while not self.should_stop:
            try:
                self._run_single_scan(valid_ips)

                if self.should_stop:
                    break

                # Wait for next scan interval
                logger.info(
                    "Scan completed. Next scan in %s",
                    format_duration(self.config.collector.interval_seconds)
                )

                # Sleep in chunks to allow graceful shutdown
                sleep_interval = 5  # Check for shutdown every 5 seconds
                total_slept = 0
                while (total_slept < self.config.collector.interval_seconds
                       and not self.should_stop):
                    time.sleep(min(sleep_interval,
                                 self.config.collector.interval_seconds - total_slept))
                    total_slept += sleep_interval

            except KeyboardInterrupt:
                logger.info("Scan loop interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error in scan loop: {e}")
                # Wait before retrying
                if not self.should_stop:
                    time.sleep(60)  # Wait 1 minute before retry

        logger.info("Collector stopped")

    def _run_single_scan(self, targets: List[str]) -> None:
        """
        Run a single scan batch.

        Args:
            targets: List of IP addresses to scan
        """
        logger.info(f"Starting scan batch with {len(targets)} targets")

        stats = ScanStatistics(
            total_targets=len(targets),
            start_time=datetime.utcnow()
        )

        # Cleanup stuck scans from previous runs
        if self.config.collector.enable_cleanup:
            stuck_count = cleanup_stuck_scans(self.config.collector.scan_timeout_minutes)
            if stuck_count > 0:
                logger.warning(f"Cleaned up {stuck_count} stuck scans")

        # Create scan run record
        scan_id = create_scan_run(len(targets))
        logger.info(f"Created scan run: {scan_id}")

        try:
            # Scan each target
            for idx, ip in enumerate(targets, 1):
                if self.should_stop:
                    logger.info("Scan interrupted by shutdown signal")
                    break

                self._scan_single_target(scan_id, ip, idx, len(targets), stats)

            # Update scan run with final statistics
            self._finalize_scan(scan_id, stats, interrupted=self.should_stop)

        except Exception as e:
            logger.error(f"Error during scan batch: {e}")
            # Mark scan as failed
            update_scan_run(
                scan_id=scan_id,
                status="failed",
                successful_targets=stats.successful_targets,
                failed_targets=stats.failed_targets,
                total_services=stats.total_services
            )
            raise

        finally:
            # Log statistics
            self._log_scan_statistics(stats)

    def _scan_single_target(
        self,
        scan_id: str,
        ip: str,
        current: int,
        total: int,
        stats: ScanStatistics
    ) -> None:
        """
        Scan a single target and save results.

        Args:
            scan_id: Current scan run ID
            ip: Target IP address
            current: Current target index (for logging)
            total: Total number of targets
            stats: Statistics object to update
        """
        logger.info(f"[{current}/{total}] Scanning {ip}")

        try:
            with Timer(f"scan_{ip}"):
                # Query Shodan
                result = self.client.host(ip)

                # Update target information
                target_id = upsert_target(
                    scan_run_id=scan_id,
                    ip=ip,
                    asn=result.asn,
                    org=result.org,
                    country=result.country_name
                )

                # Process services
                services_processed = self._process_services(
                    scan_id=scan_id,
                    target_id=target_id,
                    services=result.services
                )

                # Update statistics
                stats.successful_targets += 1
                stats.total_services += services_processed
                stats.total_vulnerabilities += sum(len(s.vulns) for s in result.services)

                logger.info(
                    f"[{current}/{total}] {ip}: {services_processed} services, "
                    f"{len(result.services)} vulns"
                )

        except ShodanError as e:
            if e.type.name == "NOT_FOUND":
                logger.info(f"[{current}/{total}] {ip}: No information available in Shodan")
            else:
                logger.error(f"[{current}/{total}] {ip}: Shodan error - {e.message}")
            stats.failed_targets += 1

        except Exception as e:
            logger.error(f"[{current}/{total}] {ip}: Unexpected error - {str(e)}")
            stats.failed_targets += 1

        finally:
            # Rate limiting delay between targets
            if current < total and not self.should_stop:
                time.sleep(self.config.shodan.request_delay)

    def _process_services(
        self,
        scan_id: str,
        target_id: int,
        services: List[Service]
    ) -> int:
        """
        Process and save services for a target.

        Args:
            scan_id: Current scan run ID
            target_id: Target database ID
            services: List of Service objects

        Returns:
            Number of services processed
        """
        if not services:
            return 0

        services_processed = 0

        try:
            # Prepare services for batch insert
            service_data = []
            for service in services:
                # Calculate risk score (simple count for now - can be enhanced)
                risk_score = min(100, len(service.vulns) * 25)

                service_data.append({
                    'scan_run_id': scan_id,
                    'target_id': target_id,
                    'port': service.port,
                    'transport': service.transport,
                    'product': service.product,
                    'version': service.version,
                    'cpe': ', '.join(service.cpe) if service.cpe else None,
                    'vulns': service.vulns,
                    'risk_score': risk_score
                })

            # Insert services
            services_processed = batch_insert_services(service_data)

            # Fallback to individual inserts if batch fails
            if services_processed == 0 and service_data:
                logger.debug(f"Batch insert failed for {target_id}, falling back to individual")
                for svc in service_data:
                    try:
                        insert_service(
                            scan_run_id=svc['scan_run_id'],
                            target_id=svc['target_id'],
                            port=svc['port'],
                            transport=svc['transport'],
                            product=svc['product'],
                            version=svc['version'],
                            cpe=svc['cpe'],
                            vulns=svc['vulns'],
                            risk_score=svc['risk_score']
                        )
                        services_processed += 1
                    except Exception as e:
                        logger.warning(f"Failed to insert service: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error processing services for target {target_id}: {e}")
            # Try individual inserts as last resort
            for service in services:
                try:
                    risk_score = min(100, len(service.vulns) * 25)
                    insert_service(
                        scan_run_id=scan_id,
                        target_id=target_id,
                        port=service.port,
                        transport=service.transport,
                        product=service.product,
                        version=service.version,
                        cpe=', '.join(service.cpe) if service.cpe else None,
                        vulns=service.vulns,
                        risk_score=risk_score
                    )
                    services_processed += 1
                except Exception as insert_error:
                    logger.warning(f"Failed to insert service {service.port}: {insert_error}")
                    continue

        return services_processed

    def _finalize_scan(
        self,
        scan_id: str,
        stats: ScanStatistics,
        interrupted: bool = False
    ) -> None:
        """
        Finalize scan run with statistics.

        Args:
            scan_id: Scan run ID
            stats: Scan statistics
            interrupted: Whether scan was interrupted
        """
        stats.end_time = datetime.utcnow()

        # Determine status
        if interrupted:
            status = "failed"
            logger.info(f"Scan {scan_id} interrupted after {format_duration(stats.duration)}")
        elif stats.successful_targets == 0:
            status = "failed"
            logger.warning(f"Scan {scan_id} failed - no successful targets")
        else:
            status = "completed"
            logger.info(
                f"Scan {scan_id} completed: {stats.successful_targets}/"
                f"{stats.total_targets} targets ({stats.success_rate:.1f}%)"
            )

        # Update scan run
        update_scan_run(
            scan_id=scan_id,
            status=status,
            successful_targets=stats.successful_targets,
            failed_targets=stats.failed_targets,
            total_services=stats.total_services
        )

    def _log_scan_statistics(self, stats: ScanStatistics) -> None:
        """Log scan statistics."""
        duration_str = format_duration(stats.duration)

        logger.info(
            "Scan statistics: "
            f"Duration: {duration_str}, "
            f"Targets: {stats.successful_targets}/{stats.total_targets} "
            f"({stats.success_rate:.1f}%), "
            f"Services: {stats.total_services}, "
            f"Vulnerabilities: {stats.total_vulnerabilities}"
        )

        # Log database stats
        try:
            db_stats = get_database_stats()
            logger.info(
                f"Database: {db_stats['total_targets']} targets, "
                f"{db_stats['total_services']} services, "
                f"{db_stats['high_risk_services']} high-risk services"
            )
        except Exception as e:
            logger.debug(f"Could not get database stats: {e}")

    def scan_once(self, group_filter: Optional[str] = None) -> ScanStatistics:
        """
        Run a single scan and return statistics.
        Useful for manual execution or testing.

        Args:
            group_filter: Optional target group to scan

        Returns:
            ScanStatistics object
        """
        targets = self.config.get_targets_for_scan(group_filter)
        if not targets:
            logger.error("No targets to scan")
            return ScanStatistics()

        stats = ScanStatistics(
            total_targets=len(targets),
            start_time=datetime.utcnow()
        )

        scan_id = create_scan_run(len(targets))
        logger.info(f"Starting single scan: {scan_id}")

        try:
            for idx, ip in enumerate(targets, 1):
                self._scan_single_target(scan_id, ip, idx, len(targets), stats)

            self._finalize_scan(scan_id, stats)

        except Exception as e:
            logger.error(f"Error during single scan: {e}")
            update_scan_run(
                scan_id=scan_id,
                status="failed",
                successful_targets=stats.successful_targets,
                failed_targets=stats.failed_targets,
                total_services=stats.total_services
            )
            raise

        finally:
            self._log_scan_statistics(stats)

        return stats


@contextmanager
def collector_context():
    """
    Context manager for running collector with graceful shutdown.

    Example:
        with collector_context() as collector:
            collector.run()
    """
    config = get_config()
    client = ShodanClient(
        api_key=config.shodan.api_key,
        max_retries=config.shodan.max_retries,
        request_delay=config.shodan.request_delay
    )

    collector = ShodanCollector(client)

    try:
        yield collector
    finally:
        logger.info("Collector context cleaned up")








