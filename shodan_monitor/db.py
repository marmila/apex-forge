import os
import uuid
import logging
from contextlib import contextmanager
from typing import Generator

import psycopg2
from psycopg2.extras import DictCursor


# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logger = logging.getLogger("shodan.db")


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
        # ---- scan sessions
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id UUID PRIMARY KEY,
                started_at TIMESTAMPTZ NOT NULL,
                finished_at TIMESTAMPTZ,
                targets_count INTEGER,
                status TEXT NOT NULL
            );
            """
        )

        # ---- targets
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(45) UNIQUE NOT NULL,
                first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                asn TEXT,
                org TEXT,
                country TEXT
            );
            """
        )

        # ---- services
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id SERIAL PRIMARY KEY,
                scan_id UUID REFERENCES scan_sessions(id) ON DELETE CASCADE,
                target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                product TEXT,
                version TEXT,
                transport TEXT,
                banner_hash TEXT,
                discovered_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """
        )

        # ---- vulnerabilities (future-proof, già pronta)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id SERIAL PRIMARY KEY,
                service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
                cve TEXT,
                cvss REAL,
                severity TEXT,
                summary TEXT
            );
            """
        )

        # ---- indexes
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_services_target_port
            ON services (target_id, port);
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_sessions_started
            ON scan_sessions (started_at);
            """
        )

    logger.info("Database schema ready")


# -------------------------------------------------------------------
# Scan session helpers
# -------------------------------------------------------------------
def start_scan(targets_count: int) -> uuid.UUID:
    scan_id = uuid.uuid4()
    logger.info("Starting scan session %s", scan_id)

    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_sessions (id, started_at, targets_count, status)
            VALUES (%s, now(), %s, %s)
            """,
            (scan_id, targets_count, "running"),
        )

    return scan_id


def finish_scan(scan_id: uuid.UUID, status: str = "ok") -> None:
    logger.info("Finishing scan session %s | status=%s", scan_id, status)

    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE scan_sessions
            SET finished_at = now(), status = %s
            WHERE id = %s
            """,
            (status, scan_id),
        )


# -------------------------------------------------------------------
# Target helpers
# -------------------------------------------------------------------
def get_or_create_target(ip: str, asn=None, org=None, country=None) -> int:
    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO targets (ip, asn, org, country)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (ip)
            DO UPDATE SET last_seen = now()
            RETURNING id
            """,
            (ip, asn, org, country),
        )
        target_id = cur.fetchone()["id"]

    return target_id


