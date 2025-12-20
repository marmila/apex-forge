"""
Entry point for Shodan Security Monitor collector.
"""
import sys
import logging
import argparse

from shodan_monitor.config import get_config, ConfigError
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.collector import ShodanCollector

logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Shodan Security Monitor Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit (for cron jobs)"
    )

    parser.add_argument(
        "--group",
        type=str,
        help="Scan only targets from this group (e.g., 'web', 'database')"
    )

    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        help="Only cleanup stuck scans and exit"
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show database statistics and exit"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate configuration and targets, then exit"
    )

    return parser.parse_args()


def setup_logging(debug: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[logging.StreamHandler()]
    )


def show_database_stats():
    """Display database statistics."""
    from shodan_monitor.db import get_database_stats

    try:
        stats = get_database_stats()

        print("\nDatabase Statistics")
        print("=" * 50)
        print(f"Total scan runs:    {stats['total_scans']}")
        print(f"Total targets:      {stats['total_targets']}")
        print(f"Total services:     {stats['total_services']}")
        print(f"High-risk services: {stats['high_risk_services']}")

        print("\nScan Status Distribution:")
        for status, count in stats['scan_status'].items():
            print(f"  {status:12} {count}")

        print("\nRecent Scans:")
        for scan in stats['recent_scans']:
            duration = ""
            if scan['finished_at'] and scan['started_at']:
                from datetime import datetime
                if isinstance(scan['finished_at'], str):
                    finished = datetime.fromisoformat(scan['finished_at'].replace('Z', '+00:00'))
                    started = datetime.fromisoformat(scan['started_at'].replace('Z', '+00:00'))
                    duration = finished - started
                    duration = f" ({duration})"

            print(f"  {scan['id'][:8]}... {scan['started_at']} "
                  f"{scan['status']}{duration}")

        print("=" * 50)

    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        return 1

    return 0


def cleanup_stuck_scans():
    """Cleanup stuck scans."""
    from shodan_monitor.db import cleanup_stuck_scans, get_stuck_scans
    from shodan_monitor.config import get_config

    config = get_config()

    try:
        # First show stuck scans
        stuck = get_stuck_scans(config.collector.scan_timeout_minutes)

        if not stuck:
            print("No stuck scans found")
            return 0

        print(f"Found {len(stuck)} stuck scans:")
        for scan in stuck:
            print(f"  {scan['id'][:8]}... running for {scan['running_for']}")

        # Clean them up
        count = cleanup_stuck_scans(config.collector.scan_timeout_minutes)
        print(f"\nCleaned up {count} stuck scans")

        return 0

    except Exception as e:
        logger.error(f"Failed to cleanup stuck scans: {e}")
        return 1


def validate_configuration():
    """Validate configuration and targets."""
    from shodan_monitor.config import get_config

    try:
        config = get_config()

        print("\nConfiguration Validation")
        print("=" * 50)
        print(f"Shodan API:      {'Configured' if config.shodan.api_key else 'Missing'}")
        print(f"Database:        {config.database.get_connection_string()}")
        print(f"Scan Interval:   {config.collector.interval_seconds}s")
        print(f"Request Delay:   {config.shodan.request_delay}s")
        print(f"Log Level:       {config.collector.log_level.value}")

        print("\nTarget Configuration:")
        if not config.targets.has_targets():
            print("No targets configured")
            return 1

        for group_name, targets in config.targets.get_groups().items():
            print(f"  {group_name}: {len(targets)} targets")
            # Show first 3 targets
            for ip in targets[:3]:
                print(f"    - {ip}")
            if len(targets) > 3:
                print(f"    ... and {len(targets) - 3} more")

        print("\nConfiguration is valid")
        print("=" * 50)

        return 0

    except ConfigError as e:
        print(f"\nConfiguration error: {e}")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        return 1


def main() -> int:
    """Main entry point."""
    args = parse_arguments()
    setup_logging(args.debug)

    logger.info("Starting Shodan Security Monitor Collector")

    try:
        # Load configuration
        config = get_config()

        # Special modes
        if args.stats:
            return show_database_stats()

        if args.cleanup_only:
            return cleanup_stuck_scans()

        if args.validate:
            return validate_configuration()

        # Create client and collector
        client = ShodanClient(
            api_key=config.shodan.api_key,
            max_retries=config.shodan.max_retries,
            request_delay=config.shodan.request_delay
        )

        collector = ShodanCollector(client)

        # Run based on arguments
        if args.once:
            logger.info("Running single scan")
            stats = collector.scan_once(group_filter=args.group)

            if stats.success_rate < 50:
                logger.warning(f"Low success rate: {stats.success_rate:.1f}%")
                return 1
            return 0

        else:
            logger.info("Starting continuous scan loop")
            collector.run(group_filter=args.group)
            return 0

    except ConfigError as e:
        logger.error(f"Configuration error: {e}")
        print("\nTip: Make sure environment variables are set:")
        print("  - SHODAN_API_KEY (required)")
        print("  - TARGETS_* (e.g., TARGETS_WEB='1.2.3.4,5.6.7.8')")
        print("  - DB_HOST, DB_NAME, DB_USER, DB_PASS")
        return 2

    except KeyboardInterrupt:
        logger.info("Collector interrupted by user")
        return 0

    except Exception as e:
        logger.exception("Collector crashed unexpectedly")
        return 1


if __name__ == "__main__":
    sys.exit(main())

