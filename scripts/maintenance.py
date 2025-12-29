import argparse
import logging
import sys
import os
from datetime import datetime, timezone, timedelta

from apex_forge.db import get_pg_cursor, get_mongo_collection, close_connections
from apex_forge.utils import setup_structured_logging

# Setup structured JSON logging
setup_structured_logging(level=os.getenv("LOG_LEVEL", "INFO"))

logger = logging.getLogger("apexforge.maintenance")

def prune_mongo_data(days: int):
    """Remove raw banners from MongoDB older than X days using timezone-aware dates."""
    collection = get_mongo_collection()
    threshold = datetime.now(timezone.utc) - timedelta(days=days)

    logger.info(f"Pruning MongoDB banners older than {days} days (threshold: {threshold.isoformat()})")
    result = collection.delete_many({"sis_metadata.collected_at": {"$lt": threshold}})
    logger.info(f"Deleted {result.deleted_count} old banners from MongoDB")

def optimize_postgres():
    """Run VACUUM ANALYZE on PostgreSQL to maintain query performance."""
    logger.info("Starting VACUUM ANALYZE on PostgreSQL tables...")
    try:
        with get_pg_cursor(autocommit=True) as cur:
            cur.execute("VACUUM ANALYZE intel_stats")
            cur.execute("VACUUM ANALYZE intel_history")
        logger.info("PostgreSQL VACUUM ANALYZE completed successfully")
    except Exception as e:
        logger.error(f"PostgreSQL maintenance failed: {e}", exc_info=True)

def main():
    parser = argparse.ArgumentParser(description="ApexForge Maintenance Tool")
    parser.add_argument("--prune-days", type=int, help="Remove MongoDB documents older than X days")
    parser.add_argument("--optimize", action="store_true", help="Run VACUUM ANALYZE on PostgreSQL tables")

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    try:
        if args.prune_days:
            prune_mongo_data(args.prune_days)

        if args.optimize:
            optimize_postgres()

        logger.info("ApexForge maintenance tasks completed")

    except Exception as e:
        logger.error(f"ApexForge maintenance task failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        close_connections()

if __name__ == "__main__":
    main()