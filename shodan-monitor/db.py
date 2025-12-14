import os
import psycopg2
from psycopg2.extras import Json

DB_HOST = os.getenv("DB_HOST", "shodan-postgres.shodan-monitor.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "shodan")
DB_USER = os.getenv("DB_USER", "shodan")
DB_PASS = os.getenv("DB_PASS", "shodan")

def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id SERIAL PRIMARY KEY,
            ip VARCHAR(45) NOT NULL,
            port INTEGER NOT NULL,
            product TEXT,
            vulns JSONB,
            risk_score INTEGER,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

