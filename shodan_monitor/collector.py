import time
import logging
from datetime import datetime
from psycopg2.extras import Json

from shodan_monitor.db import get_connection, init_db
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.config import Config

# logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


class ShodanCollector:
    def __init__(self, client: ShodanClient):
        self.client = client
        logger.info("Initializing database")
        init_db()

    def run(self, targets: list[str]) -> None:
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

    def _run_once(self, targets: list[str]) -> None:
        logger.info("Starting scan batch")
        conn = get_connection()
        cur = conn.cursor()

        for ip in targets:
            ip = ip.strip()
            if not ip:
                continue

            logger.info("Scanning target %s", ip)

            try:
                result = self.client.host(ip)
                services = result.get("data", [])

                logger.info(
                    "Target %s returned %d services",
                    ip,
                    len(services),
                )

                for item in services:
                    port = item.get("port")
                    product = item.get("product", "unknown")
                    vulns = item.get("vulns", [])

                    risk_score = len(vulns) + 1

                    logger.debug(
                        "Inserting result | ip=%s port=%s product=%s vulns=%d",
                        ip,
                        port,
                        product,
                        len(vulns),
                    )

                    cur.execute(
                        """
                        INSERT INTO scan_results
                        (ip, port, product, vulns, risk_score, timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            ip,
                            port,
                            product,
                            Json(vulns),
                            risk_score,
                            datetime.utcnow(),
                        ),
                    )

                conn.commit()
                logger.info("Committed results for %s", ip)
                time.sleep(Config.REQUEST_DELAY)

            except Exception as e:
                conn.rollback()
                logger.exception("Error scanning %s", ip)

        cur.close()
        conn.close()
        logger.info("Scan batch finished")



