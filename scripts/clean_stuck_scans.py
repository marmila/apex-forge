#!/usr/bin/env python3
"""
Maintenance script for Shodan Security Monitor.
Cleans up stuck scans, orphaned data, and performs database maintenance.
"""
import argparse
import logging
import sys
from datetime import datetime, timedelta

from shodan_monitor.config import get_config
from shodan_monitor.db import (
    cleanup_stuck_scans,
    get_stuck_scans,
    get_database_stats,
    vacuum_analyze,
    close_all_connections
)

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[logging.StreamHandler()]
    )


def find_orphaned_services():
    """Find services without targets or scan runs."""
    from shodan_monitor.db import get_connection

    conn = get_connection()
    try:
        cur = conn.cursor()

        # Services without targets
        cur.execute("""
            SELECT COUNT(*) as count
            FROM services s
            LEFT JOIN targets t ON s.target_id = t.id
            WHERE t.id IS NULL
        """)
        orphaned_from_targets = cur.fetchone()['count']

        # Services without scan runs
        cur.execute("""
            SELECT COUNT(*) as count
            FROM services s
            LEFT JOIN scan_runs sr ON s.scan_run_id = sr.id
            WHERE sr.id IS NULL
        """)
        orphaned_from_scans = cur.fetchone()['count']

        # Targets without services
        cur.execute("""
            SELECT COUNT(*) as count
            FROM targets t
            LEFT JOIN services s ON t.id = s.target_id
            WHERE s.id IS NULL
        """)
        targets_without_services = cur.fetchone()['count']

        return {
            'orphaned_from_targets': orphaned_from_targets,
            'orphaned_from_scans': orphaned_from_scans,
            'targets_without_services': targets_without_services
        }

    finally:
        cur.close()
        conn.close()


def cleanup_old_data(days_old: int = 90):
    """
    Clean up old scan data to save space.
    WARNING: This removes historical data!
    """
    from shodan_monitor.db import get_connection

    if days_old < 30:
        logger.warning(f"Cleaning up data less than {days_old} days old is not recommended")
        return 0

    conn = get_connection()
    try:
        cur = conn.cursor()

        # Count scans to be deleted
        cur.execute("""
            SELECT COUNT(*) as count
            FROM scan_runs
            WHERE finished_at < NOW() - INTERVAL '%s days'
            AND status IN ('completed', 'failed', 'timeout')
        """, (days_old,))
        count = cur.fetchone()['count']

        if count == 0:
            logger.info(f"No scans older than {days_old} days found")
            return 0

        logger.info(f"Found {count} scans older than {days_old} days")

        # Ask for confirmation
        response = input(f"Delete {count} scans older than {days_old} days? (yes/no): ")
        if response.lower() != 'yes':
            logger.info("Cleanup cancelled")
            return 0

        # Delete old scans (cascade will delete associated services)
        cur.execute("""
            DELETE FROM scan_runs
            WHERE finished_at < NOW() - INTERVAL '%s days'
            AND status IN ('completed', 'failed', 'timeout')
        """, (days_old,))

        deleted = cur.rowcount
        conn.commit()

        logger.info(f"Deleted {deleted} old scans")
        return deleted

    finally:
        cur.close()
        conn.close()


def check_database_health():
    """Check database health and report issues."""
    from shodan_monitor.db import get_connection

    conn = get_connection()
    try:
        cur = conn.cursor()

        issues = []

        # Check for scans running too long
        config = get_config()
        stuck_scans = get_stuck_scans(config.collector.scan_timeout_minutes)
        if stuck_scans:
            issues.append(f"{len(stuck_scans)} scans stuck in running state")

        # Check for data consistency
        orphaned = find_orphaned_services()
        if orphaned['orphaned_from_targets'] > 0:
            issues.append(f"{orphaned['orphaned_from_targets']} services without targets")
        if orphaned['orphaned_from_scans'] > 0:
            issues.append(f"{orphaned['orphaned_from_scans']} services without scan runs")

        # Check table sizes
        cur.execute("""
            SELECT
                table_name,
                pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) as total_size,
                pg_size_pretty(pg_relation_size(quote_ident(table_name))) as table_size,
                pg_size_pretty(pg_total_relation_size(quote_ident(table_name)) -
                              pg_relation_size(quote_ident(table_name))) as index_size
            FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_type = 'BASE TABLE'
            ORDER BY pg_total_relation_size(quote_ident(table_name)) DESC
        """)

        table_sizes = cur.fetchall()

        return {
            'issues': issues,
            'table_sizes': table_sizes,
            'orphaned_data': orphaned
        }

    finally:
        cur.close()
        conn.close()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Shodan Security Monitor - Maintenance Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--cleanup-stuck",
        action="store_true",
        help="Clean up stuck scans"
    )

    parser.add_argument(
        "--health-check",
        action="store_true",
        help="Run database health check"
    )

    parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Run VACUUM ANALYZE for database maintenance"
    )

    parser.add_argument(
        "--cleanup-old",
        type=int,
        metavar="DAYS",
        help="Clean up data older than X days (WARNING: irreversible)"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )

    args = parser.parse_args()

    setup_logging(args.verbose)

    if not any([args.cleanup_stuck, args.health_check, args.vacuum, args.cleanup_old]):
        parser.print_help()
        return 1

    try:
        # Load configuration
        config = get_config()
        logger.info("Starting maintenance operations")

        if args.health_check:
            logger.info("Running database health check...")
            health = check_database_health()

            print("\n" + "=" * 60)
            print("DATABASE HEALTH REPORT")
            print("=" * 60)

            if health['issues']:
                print("\n❌ ISSUES FOUND:")
                for issue in health['issues']:
                    print(f"  - {issue}")
            else:
                print("\n✅ No issues found")

            print("\n📊 TABLE SIZES:")
            for table in health['table_sizes']:
                print(f"  {table['table_name']:20} {table['total_size']:10} "
                      f"(table: {table['table_size']}, index: {table['index_size']})")

            orphaned = health['orphaned_data']
            print(f"\n🗑️  ORPHANED DATA:")
            print(f"  Services without targets: {orphaned['orphaned_from_targets']}")
            print(f"  Services without scans: {orphaned['orphaned_from_scans']}")
            print(f"  Targets without services: {orphaned['targets_without_services']}")

            print("=" * 60)

        if args.cleanup_stuck:
            if args.dry_run:
                logger.info("DRY RUN: Would cleanup stuck scans")
                stuck = get_stuck_scans(config.collector.scan_timeout_minutes)
                if stuck:
                    print(f"\nFound {len(stuck)} stuck scans:")
                    for scan in stuck:
                        print(f"  {scan['id'][:8]}... running for {scan['running_for']}")
                else:
                    print("\nNo stuck scans found")
            else:
                logger.info("Cleaning up stuck scans...")
                count = cleanup_stuck_scans(config.collector.scan_timeout_minutes)
                print(f"\nCleaned up {count} stuck scans")

        if args.vacuum:
            if args.dry_run:
                logger.info("DRY RUN: Would run VACUUM ANALYZE")
            else:
                logger.info("Running VACUUM ANALYZE...")
                vacuum_analyze()
                print("\nVACUUM ANALYZE completed")

        if args.cleanup_old:
            if args.dry_run:
                logger.info(f"DRY RUN: Would cleanup data older than {args.cleanup_old} days")
                # Count what would be deleted
                from shodan_monitor.db import get_connection
                conn = get_connection()
                try:
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT COUNT(*) as count
                        FROM scan_runs
                        WHERE finished_at < NOW() - INTERVAL '%s days'
                        AND status IN ('completed', 'failed', 'timeout')
                    """, (args.cleanup_old,))
                    count = cur.fetchone()['count']
                    print(f"\nWould delete {count} scans older than {args.cleanup_old} days")
                finally:
                    cur.close()
                    conn.close()
            else:
                logger.info(f"Cleaning up data older than {args.cleanup_old} days...")
                deleted = cleanup_old_data(args.cleanup_old)
                if deleted > 0:
                    print(f"\nDeleted {deleted} old scans")

        # Show final stats
        if not args.dry_run and (args.cleanup_stuck or args.vacuum or args.cleanup_old):
            print("\n" + "=" * 60)
            print("FINAL DATABASE STATISTICS")
            print("=" * 60)

            stats = get_database_stats()
            print(f"Total scan runs:    {stats['total_scans']}")
            print(f"Total targets:      {stats['total_targets']}")
            print(f"Total services:     {stats['total_services']}")
            print(f"High-risk services: {stats['high_risk_services']}")

            print("\nScan status:")
            for status, count in stats['scan_status'].items():
                print(f"  {status:12} {count}")

        logger.info("Maintenance operations completed")

    except Exception as e:
        logger.error(f"Maintenance failed: {e}")
        return 1
    finally:
        # Ensure all connections are closed
        close_all_connections()

    return 0


if __name__ == "__main__":
    sys.exit(main())