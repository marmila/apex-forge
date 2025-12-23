import os
import logging
from contextlib import contextmanager
from typing import Generator, List, Optional, Dict, Any
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import DictCursor, Json
from psycopg2.pool import SimpleConnectionPool
from pymongo import MongoClient
from pymongo.collection import Collection

from shodan_monitor.config import get_config

logger = logging.getLogger("shodan.db")

# Global connection managers
_pg_pool = None
_mongo_client = None

def get_pg_pool():
    """Initialize or return the existing PostgreSQL connection pool."""
    global _pg_pool
    if _pg_pool is None:
        config = get_config().db
        try:
            _pg_pool = SimpleConnectionPool(
                config.min_connections,
                config.max_connections,
                host=config.host,
                database=config.name,
                user=config.user,
                password=config.password,
                port=config.port,
                cursor_factory=DictCursor
            )
            logger.info("PostgreSQL connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL pool: {e}")
            raise
    return _pg_pool

def get_mongo_collection() -> Collection:
    """Initialize or return the MongoDB collection for raw intelligence."""
    global _mongo_client
    config = get_config().mongo
    if _mongo_client is None:
        try:
            _mongo_client = MongoClient(config.uri)
            logger.info("MongoDB client initialized")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    return _mongo_client[config.db_name][config.collection]

@contextmanager
def get_pg_cursor(autocommit: bool = False) -> Generator:
    """Context manager for PostgreSQL cursors with automatic pool management."""
    pool = get_pg_pool()
    conn = pool.getconn()
    conn.autocommit = autocommit
    try:
        with conn.cursor() as cur:
            yield cur
            if not autocommit:
                conn.commit()
    except Exception as e:
        if not autocommit:
            conn.rollback()
        logger.error(f"PostgreSQL database error: {e}")
        raise
    finally:
        pool.putconn(conn)

# --- Intelligence Storage Functions ---

def save_raw_banner(banner: Dict[str, Any], profile_name: str):
    """
    Store the complete Shodan JSON banner into MongoDB.
    Uses timezone-aware UTC datetime for the collection timestamp.
    """
    try:
        collection = get_mongo_collection()
        banner['sis_metadata'] = {
            'profile_name': profile_name,
            'collected_at': datetime.now(timezone.utc),
            'processed': False
        }
        collection.insert_one(banner)
    except Exception as e:
        logger.error(f"Failed to save raw banner to MongoDB: {e}")

def update_intel_stats(profile_name: str, count: int, countries: Dict[str, int]):
    """
    Upsert aggregated profile statistics into PostgreSQL.
    Maintains a real-time snapshot of exposure per country.
    """
    query = """
        INSERT INTO intel_stats (profile_name, total_count, country_dist, last_updated)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (profile_name)
        DO UPDATE SET
            total_count = EXCLUDED.total_count,
            country_dist = EXCLUDED.country_dist,
            last_updated = EXCLUDED.last_updated;
    """
    try:
        with get_pg_cursor() as cur:
            cur.execute(query, (
                profile_name,
                count,
                Json(countries),
                datetime.now(timezone.utc)
            ))
    except Exception as e:
        logger.error(f"Failed to update intel stats for {profile_name}: {e}")

def log_intel_history(profile_name: str, count: int):
    """Record a time-series data point for threat velocity analysis."""
    query = """
        INSERT INTO intel_history (profile_name, count)
        VALUES (%s, %s)
    """
    try:
        with get_pg_cursor() as cur:
            cur.execute(query, (profile_name, count))
    except Exception as e:
        logger.error(f"Failed to log intel history for {profile_name}: {e}")

# --- Initialization and Maintenance ---

def init_databases():
    """Initialize the PostgreSQL schema for the Threat Intelligence focus."""
    commands = [
        """
        CREATE TABLE IF NOT EXISTS intel_stats (
            profile_name VARCHAR(100) PRIMARY KEY,
            total_count INTEGER DEFAULT 0,
            country_dist JSONB DEFAULT '{}',
            last_updated TIMESTAMP WITH TIME ZONE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS intel_history (
            id SERIAL PRIMARY KEY,
            profile_name VARCHAR(100),
            count INTEGER,
            observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
    ]
    try:
        with get_pg_cursor(autocommit=True) as cur:
            for cmd in commands:
                cur.execute(cmd)
        logger.info("Threat Intelligence database schemas initialized")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def get_database_stats() -> Dict[str, Any]:
    """Fetch high-level overview of the collected intelligence."""
    stats = {}
    try:
        with get_pg_cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM intel_stats")
            stats['active_profiles'] = cur.fetchone()[0]

            cur.execute("SELECT SUM(total_count) FROM intel_stats")
            stats['total_exposed_assets'] = cur.fetchone()[0] or 0
    except Exception as e:
        logger.error(f"Failed to retrieve database stats: {e}")
    return stats

def close_connections():
    """Close all database connections (call during graceful shutdown)."""
    global _pg_pool, _mongo_client
    if _pg_pool:
        _pg_pool.closeall()
        logger.info("PostgreSQL connection pool closed")
    if _mongo_client:
        _mongo_client.close()
        logger.info("MongoDB connection closed")









