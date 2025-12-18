import os
import uuid
import logging
from contextlib import contextmanager
from typing import Generator, List, Optional

import psycopg2
from psycopg2.extras import DictCursor, Json

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logger = logging.getLogger("shodan.db")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")

# -------------------------------------------------------------------
# DB config
# -------------------------------------------------------------------
DB_HOST = os.getenv("DB_HOST", "shodan-postgres.shodan-monitor.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "shodan")
DB_USER = os.getenv("DB_USER", "shodan")
DB_PASS = os.getenv("DB_PASS", "shodan")

# -------------------------------------------------------------------
# Connection helpers
# -------------------------------------------------------------------
def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        cursor_factory=DictCursor,
    )

@contextmanager
def get_cursor() -> Generator:
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()

# -------------------------------------------------------------------
# Schema initialization
# -------------------------------------------------------------------
def init_db() -> None:
    logger.info("Initializing database schema")

    with get_cursor() as cur:
        # ---- scan runs
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id UUID PRIMARY KEY,
                started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                finished_at TIMESTAMPTZ,
                status TEXT NOT NULL DEFAULT 'running',
                targets_count INTEGER
            )
        """)

        # ---- targets
        cur.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(45) UNIQUE NOT NULL,
                first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                asn TEXT,
                org TEXT,
                country TEXT
            )
        """)

        # ---- services
        cur.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id SERIAL PRIMARY KEY,
                scan_run_id UUID REFERENCES scan_runs(id) ON DELETE CASCADE,
                target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                port INTEGER NOT NULL,
                transport TEXT DEFAULT 'tcp',
                product TEXT,
                version TEXT,
                cpe TEXT,
                vulns JSONB,
                risk_score INTEGER,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)

        # ---- indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_services_target_port ON services(target_id, port)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at)")

    logger.info("Database schema ready")

# -------------------------------------------------------------------
# Insert helpers
# -------------------------------------------------------------------
def insert_scan_run(cur, targets_count: Optional[int] = None) -> uuid.UUID:
    scan_id = uuid.uuid4()
    cur.execute(
        """
        INSERT INTO scan_runs (id, targets_count, status)
        VALUES (%s, %s, 'running')
        """,
        (str(scan_id), targets_count)
    )
    logger.info("Inserted scan_run id=%s", scan_id)
    return str(scan_id)

def insert_target(cur, scan_run_id: uuid.UUID, ip: str, asn=None, org=None, country=None, last_update=None) -> int:
    cur.execute(
        """
        INSERT INTO targets (ip, asn, org, country)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (ip) DO UPDATE SET last_seen = now()
        RETURNING id
        """,
        (ip, asn, org, country)
    )
    target_id = cur.fetchone()["id"]
    logger.debug("Inserted/updated target id=%s | ip=%s", target_id, ip)
    return target_id

def insert_service(
    cur,
    scan_run_id: uuid.UUID,
    target_id: int,
    port: int,
    transport: str,
    product: Optional[str],
    version: Optional[str],
    cpe: Optional[str],
    vulns: List[str],
    risk_score: int
) -> None:
    cur.execute(
        """
        INSERT INTO services
        (scan_run_id, target_id, port, transport, product, version, cpe, vulns, risk_score, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now())
        """,
        (
            scan_run_id,
            target_id,
            port,
            transport,
            product,
            version,
            cpe,
            Json(vulns),
            risk_score,
        )
    )
    logger.debug("Inserted service for target_id=%s port=%s", target_id, port)



