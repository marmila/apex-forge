import os
import logging
import hashlib
from contextlib import contextmanager
from typing import Generator, Dict, Any, Optional
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import DictCursor, Json
from psycopg2.pool import SimpleConnectionPool
from pymongo import MongoClient
from pymongo.collection import Collection

from apex_forge.config import get_config
from apex_forge.utils import sanitize_for_mongo

logger = logging.getLogger("apexforge.db")

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

def get_last_checkpoint(profile_name: str) -> Optional[datetime]:
    """Retrieve the last successful collection timestamp for a profile."""
    try:
        with get_pg_cursor() as cur:
            cur.execute(
                "SELECT last_updated FROM intel_stats WHERE profile_name = %s",
                (profile_name,)
            )
            row = cur.fetchone()
            return row['last_updated'] if row else None
    except Exception as e:
        logger.error(f"Failed to fetch checkpoint for {profile_name}: {e}")
        return None

def save_raw_banner(banner: Dict[str, Any], profile_name: str):
    """Store complete banner in MongoDB with deterministic _id and risk metadata."""
    try:
        collection = get_mongo_collection()

        sanitized_data = sanitize_for_mongo(banner)

        ip = banner.get('ip_str', '0.0.0.0')
        port = banner.get('port', 0)
        ts = banner.get('timestamp', '')
        unique_string = f"{ip}:{port}:{ts}"
        banner_id = hashlib.sha256(unique_string.encode()).hexdigest()

        sanitized_data['_id'] = banner_id
        sanitized_data['sis_metadata'] = sanitized_data.get('sis_metadata', {})
        sanitized_data['sis_metadata'].update({
            'profile_name': profile_name,
            'collected_at': datetime.now(timezone.utc)
        })

        collection.replace_one({'_id': banner_id}, sanitized_data, upsert=True)

    except Exception as e:
        logger.error(f"Failed to save raw banner to MongoDB: {e}")

def update_intel_stats(profile_name: str, new_count: int, countries: Dict[str, int],
                       high_critical_new: int = 0, total_risk_sum: float = 0.0):
    """
    Update aggregated stats including risk metrics.
    Maintains running average risk score and high/critical asset count.
    """
    try:
        with get_pg_cursor() as cur:
            # Fetch current state
            cur.execute("""
                SELECT total_count, high_critical_count, avg_risk_score
                FROM intel_stats WHERE profile_name = %s
            """, (profile_name,))
            row = cur.fetchone()

            if row:
                curr_total, curr_critical, curr_avg = row
                new_total = curr_total + new_count
                new_critical = curr_critical + high_critical_new

                # Running average risk score
                if new_count > 0 and total_risk_sum > 0:
                    new_avg = (curr_avg * curr_total + total_risk_sum) / new_total
                else:
                    new_avg = curr_avg
            else:
                new_total = new_count
                new_critical = high_critical_new
                new_avg = total_risk_sum / new_count if new_count > 0 else 0.0

            # Upsert
            cur.execute("""
                INSERT INTO intel_stats (
                    profile_name, total_count, country_dist, last_updated,
                    high_critical_count, avg_risk_score
                ) VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s, %s)
                ON CONFLICT (profile_name) DO UPDATE SET
                    total_count = EXCLUDED.total_count,
                    country_dist = EXCLUDED.country_dist,
                    last_updated = CURRENT_TIMESTAMP,
                    high_critical_count = EXCLUDED.high_critical_count,
                    avg_risk_score = EXCLUDED.avg_risk_score
            """, (profile_name, new_total, Json(countries), new_critical, round(new_avg, 2)))

    except Exception as e:
        logger.error(f"Failed to update intel_stats for {profile_name}: {e}")

def log_intel_history(profile_name: str, new_count: int, high_critical_new: int = 0):
    """Log daily collection with critical asset count for trend analysis."""
    try:
        with get_pg_cursor() as cur:
            cur.execute("""
                INSERT INTO intel_history (profile_name, count, high_critical_new, observed_at)
                VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            """, (profile_name, new_count, high_critical_new))
    except Exception as e:
        logger.error(f"Failed to log intel_history: {e}")

# --- Initialization and Maintenance ---

def init_databases():
    """Initialize schema with risk-enhanced tables and Grafana views."""
    commands = [
        # Enhanced intel_stats with risk columns
        """
        CREATE TABLE IF NOT EXISTS intel_stats (
            profile_name VARCHAR(100) PRIMARY KEY,
            total_count INTEGER DEFAULT 0,
            country_dist JSONB DEFAULT '{}',
            last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            high_critical_count INTEGER DEFAULT 0,
            avg_risk_score FLOAT DEFAULT 0.0
        );
        """,
        # Enhanced history with critical daily count
        """
        CREATE TABLE IF NOT EXISTS intel_history (
            id SERIAL PRIMARY KEY,
            profile_name VARCHAR(100),
            count INTEGER,
            high_critical_new INTEGER DEFAULT 0,
            observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """,
        # Existing + new risk-focused views
        """
        CREATE OR REPLACE VIEW vw_exposed_assets_by_country AS
        SELECT
            s.profile_name,
            t.country_code,
            (t.country_count)::integer AS asset_count,
            s.last_updated
        FROM intel_stats s,
            jsonb_each_text(s.country_dist) AS t(country_code, country_count)
        WHERE s.country_dist != '{}' AND t.country_count IS NOT NULL;
        """,
        """
        CREATE OR REPLACE VIEW vw_exposure_trend_by_profile AS
        SELECT
            profile_name,
            observed_at::date AS date,
            count AS new_assets_daily,
            high_critical_new AS new_critical_daily,
            SUM(count) OVER (PARTITION BY profile_name ORDER BY observed_at::date) AS total_assets_cumulative,
            SUM(high_critical_new) OVER (PARTITION BY profile_name ORDER BY observed_at::date) AS critical_assets_cumulative
        FROM intel_history
        GROUP BY profile_name, observed_at::date, count, high_critical_new
        ORDER BY profile_name, date;
        """,
        """
        CREATE OR REPLACE VIEW vw_risk_summary AS
        SELECT
            SUM(high_critical_count) AS total_high_critical_assets,
            AVG(avg_risk_score) AS global_avg_risk_score,
            COUNT(*) FILTER (WHERE high_critical_count > 0) AS profiles_with_critical_assets
        FROM intel_stats;
        """,
        """
        CREATE OR REPLACE VIEW vw_top_risk_profiles AS
        SELECT
            profile_name,
            high_critical_count,
            avg_risk_score,
            total_count,
            ROUND((high_critical_count::float / total_count) * 100, 2) AS critical_percentage
        FROM intel_stats
        WHERE total_count > 0
        ORDER BY high_critical_count DESC
        LIMIT 15;
        """,
        """
        CREATE OR REPLACE VIEW vw_current_summary AS
        SELECT
            COUNT(*) AS active_profiles,
            SUM(total_count) AS total_exposed_assets,
            SUM(high_critical_count) AS total_high_critical_assets,
            MAX(last_updated) AS last_collection_cycle
        FROM intel_stats;
        """
    ]
    try:
        with get_pg_cursor(autocommit=True) as cur:
            for cmd in commands:
                cur.execute(cmd)
        logger.info("ApexForge PostgreSQL schema and risk-enhanced views initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def get_database_stats() -> Dict[str, Any]:
    """Fetch high-level overview including risk metrics."""
    stats = {}
    try:
        with get_pg_cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM intel_stats")
            stats['active_profiles'] = cur.fetchone()[0]

            cur.execute("SELECT SUM(total_count) FROM intel_stats")
            stats['total_exposed_assets'] = cur.fetchone()[0] or 0

            cur.execute("SELECT total_high_critical_assets FROM vw_risk_summary")
            stats['total_high_critical_assets'] = cur.fetchone()[0] or 0

    except Exception as e:
        logger.error(f"Failed to retrieve database stats: {e}")
    return stats

def close_connections():
    """Close all database connections."""
    global _pg_pool, _mongo_client
    if _pg_pool:
        _pg_pool.closeall()
        logger.info("PostgreSQL connection pool closed")
    if _mongo_client:
        _mongo_client.close()
        logger.info("MongoDB connection closed")








