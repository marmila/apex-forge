import time
import logging
from datetime import datetime

from shodan_monitor.db import (
    get_connection,
    init_db,
    insert_scan_run,
    insert_target,
    insert_service,
)
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.config import Config

# logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)


class ShodanCollector:
    """
    Periodically collects data from Shodan and stores it in PostgreSQL.
    """

    def __init__(self, client: ShodanClient):
        self.client = client
        logger.info("Initializing database schema")
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
        """
        Executes a single scan batch over all targets.
        """
        logger.info("Starting new scan batch")

        conn = get_connection()
        cur = conn.cursor()

        # create a new scan_run entry
        scan_run_id = insert_scan_run(cur)
        logger.info("Created scan_run id=%s", scan_run_id)

        for ip in targets:
            ip = ip.strip()
            if not ip:
                continue

            logger.info("Scanning target %s", ip)

            try:
                result = self.client.scan_host(ip)
                services = result.get("data", [])

                logger.info(
                    "Target %s returned %d services",
                    ip,
                    len(services),
                )

                # insert target metadata
                target_id = insert_target(
                    cur=cur,
                    scan_run_id=scan_run_id,
                    ip=ip,
                    org=result.get("org"),
                    isp=result.get("isp"),
                    country=result.get("country_name"),
                    asn=result.get("asn"),
                    last_update=result.get("last_update"),
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

                    insert_service(
                        cur=cur,
                        target_id=target_id,
                        port=port,
                        transport=transport,
                        product=product,
                        version=version,
                        cpe=cpe,
                        vulns=vulns,
                        risk_score=risk_score,
                    )

                conn.commit()
                logger.info(
                    "Committed %d services for target %s",
                    len(services),
                    ip,
                )

                time.sleep(request_delay)

            except Exception:
                conn.rollback()
                logger.exception("Error scanning target %s", ip)

        cur.close()
        conn.close()
        logger.info("Scan batch finished")




