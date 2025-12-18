# shodan-sec-monitor

## Project Overview

`shodan-sec-monitor` is a Python-based collector that periodically gathers passive internet exposure data from Shodan. The project is designed to provide with structured visibility on external-facing services and potential vulnerabilities, without performing any active scanning.
This project collects data in a **structured PostgreSQL database**, enabling further analysis, dashboards, and correlation with other observability tools.

---

## Data Model

The database is structured to capture both high-level scan runs and detailed service information:

- **scan_runs**: metadata for each collector batch (timestamp, duration, etc.)
- **targets**: each IP scanned, along with organization, ASN, country, and last update info
- **services**: each service discovered on a target (port, transport, product, version, CPE, vulnerabilities, risk score)

The tables are related as follows:

scan_runs 1---* targets 1---* services


This allows correlating service-level findings with the batch in which they were collected.

---

## Collected Data

For each target, the collector stores:

- **Target metadata**:
  - IP address
  - Organization
  - ISP
  - Country
  - ASN
  - Last update timestamp from Shodan

- **Service data**:
  - Port and transport protocol
  - Product and version (if available)
  - CPE identifier
  - Known vulnerabilities (CVE IDs)
  - Computed risk score (`1 + number of vulnerabilities`)

This data allows building **dashboards**, tracking external service exposure, and assessing relative risk.

---

## Target Strategy

Currently, targets are specified via environment variables. This allows flexible adjustment without changing code.

- Initially, only a few public resolvers (like Google and Cloudflare) were used as targets for testing.
- The collector is designed to scale to a **larger set of external targets**.
- Targets should be carefully selected to avoid scanning systems not owned by your organization (the collector only uses Shodan's passive API).

---

## Limitations

- **Shodan dependency**: The collector relies entirely on Shodan’s public API; missing data on Shodan will not be collected.
- **Passive data**: No active scanning is performed. This is **strictly passive**, safe, and compliant with external networks.
- **Rate limiting**: The collector respects configurable delays between API calls.
- **Future improvements**: Integration with MongoDB or other observability pipelines for faster aggregation or historical analysis.

---

## Future Work

- Implement **dashboards** and reporting tools for collected data.
- Expand **target lists** and make them dynamic.
- Improve database schema to support more detailed service metadata.
- Implement structured logging across all components.
- Optionally, add **MongoDB** backend for analytics or faster ingestion of large volumes.

---

## Environment Variables

Required:

```
SHODAN_API_KEY  # Shodan API key
TARGETS         # Comma-separated list of IPs or hostnames
DB_HOST         # PostgreSQL host
DB_NAME         # PostgreSQL database name
DB_USER         # PostgreSQL user
DB_PASS         # PostgreSQL password

Optional:

INTERVAL_SECONDS  # Seconds between scan batches (default 21600)
REQUEST_DELAY     # Seconds delay between API requests (default 1.0)

## Notes

All components are containerized, with PYTHONPATH=/app configured for Python imports.
The collector is stateless between runs, all state is persisted in PostgreSQL.
Suitable for Kubernetes deployment with configurable PVC and environment variables.
The collector design allows multiple instances to be deployed safely with separate scan batches.

## Disclaimer

This tool does not perform any active scanning. It only collects publicly available information from Shodan.
Ensure that all usage complies with organizational policies and Shodan’s API terms of service.