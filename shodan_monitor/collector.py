import time
import logging
from datetime import datetime
from typing import List, Dict, Any

from shodan_monitor.db import get_connection, init_db, start_scan, finish_scan, get_or_create_target
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.config import Config

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)


class ShodanCollector:
    """
    Periodically collects data from Shodan and stores it in PostgreSQL.
    """

    def __init__(self, client: ShodanClient):
        self.client = client
        logger.info("Initializing database schema")
        init_db()

    def run(self, targets: List[str]) -> None:
        interval = getattr(Config, "INTERVAL_SECONDS", 6 * 3600)
        request_delay = getattr(Config, "REQUEST_DELAY", 1)

        logger.info(
            "Collector started | targets=%s | interval=%ss | request_delay=%ss",
            targets,
            interval,
            request_delay,
        )

        while True:
            self._run_once(targets)
            logger.info(
                "Batch completed at %s. Sleeping %s seconds",
                datetime.utcnow().isoformat(),
                interval,
            )
            time.sleep(interval)

    def _run_once(self, targets: List[str]) -> None:
        """
        Executes a single scan batch over all targets.
        """
        logger.info("Starting new scan batch")
        conn = get_connection()
        cur = conn.cursor()

        scan_id = start_scan(len(targets))
        logger.info("Created scan session id=%s", scan_id)

        for ip in targets:
            ip = ip.strip()
            if not ip:
                continue

            logger.info("Scanning target %s", ip)

            try:
                result = self.client.scan_host(ip)
                services = result.get("data", [])

                logger.info("Target %s returned %d services", ip, len(services))

                # create or update target
                target_id = get_or_create_target(
                    ip=ip,
                    asn=result.get("asn"),
                    org=result.get("org"),
                    country=result.get("country_name"),
                )

                for svc in services:
                    port = svc.get("port")
                    transport = svc.get("transport", "tcp")
                    product = svc.get("product")
                    version = svc.get("version")
                    cpe = svc.get("cpe")
                    vulns = list(svc.get("vulns", []))
                    risk_score = len(vulns)

                    logger.debug(
                        "Service detected | ip=%s port=%s product=%s vulns=%d",
                        ip,
                        port,
                        product,
                        len(vulns),
                    )

                    cur.execute(
                        """
                        INSERT INTO services (
                            scan_id, target_id, port, transport, product, version, banner_hash, discovered_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, now())
                        """,
                        (scan_id, target_id, port, transport, product, version, cpe),
                    )

                conn.commit()
                logger.info("Committed %d services for target %s", len(services), ip)
                time.sleep(request_delay)

            except Exception:
                conn.rollback()
                logger.exception("Error scanning target %s", ip)

        finish_scan(scan_id)
        cur.close()
        conn.close()
        logger.info("Scan batch finished")







