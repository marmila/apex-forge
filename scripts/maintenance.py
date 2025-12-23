import argparse
import logging
import sys
from datetime import datetime, timezone, timedelta
from shodan_monitor.db import get_pg_cursor, get_mongo_collection, close_connections

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("shodan.maintenance")

def prune_mongo_data(days: int):
    """Remove raw banners from MongoDB older than X days using timezone-aware dates."""
    collection = get_mongo_collection()
    # Use timezone.utc for aware objects
    threshold = datetime.now(timezone.utc) - timedelta(days=days)

    logger.info(f"Pruning MongoDB banners older than {days} days (threshold: {threshold})")
    # MongoDB stores dates in UTC by default
    result = collection.delete_many({"sis_metadata.collected_at": {"$lt": threshold}})
    logger.info(f"Successfully deleted {result.deleted_count} old banners from MongoDB.")

def optimize_postgres():
    """Run VACUUM ANALYZE on PostgreSQL to maintain query performance."""
    logger.info("Running VACUUM ANALYZE on PostgreSQL...")
    try:
        with get_pg_cursor(autocommit=True) as cur:
            cur.execute("VACUUM ANALYZE intel_stats")
            cur.execute("VACUUM ANALYZE intel_history")
        logger.info("PostgreSQL optimization completed.")
    except Exception as e:
        logger.error(f"PostgreSQL maintenance failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Shodan Intelligence Sentinel Maintenance Tool")
    parser.add_argument("--prune-days", type=int, help="Remove MongoDB documents older than X days")
    parser.add_argument("--optimize", action="store_true", help="Optimize PostgreSQL tables")

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    try:
        if args.prune_days:
            prune_mongo_data(args.prune_days)

        if args.optimize:
            optimize_postgres()

    except Exception as e:
        logger.error(f"Maintenance task failed: {e}")
    finally:
        close_connections()

if __name__ == "__main__":
    main()