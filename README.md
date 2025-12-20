## Shodan Security Monitor
Project Overview
shodan-sec-monitor is a Python-based collector that periodically gathers passive internet exposure data from Shodan. The project is designed to provide structured visibility on external-facing services and potential vulnerabilities, without performing any active scanning.

This project collects data in a structured PostgreSQL database, enabling further analysis, dashboards, and correlation with other observability tools.

## What's New in This Refactor
I've completely refactored the project to be production-ready with the following improvements:

1. Enhanced Database Layer (shodan_monitor/db.py)
- Connection pooling for better performance in k3s

- Complete scan lifecycle management - scans now properly track status (running → completed/failed/timeout)

- Automatic cleanup of stuck scans

- Better error handling and transaction management

- Monitoring functions to check database health

2. Robust Shodan API Client (shodan_monitor/shodan_client.py)
- Exponential backoff and retry logic for rate limiting

- Structured error handling with classified error types

- Request throttling to respect Shodan API limits

- Data validation and IP format checking

- Better logging for debugging API issues

3. K3s-Optimized Configuration (shodan_monitor/config.py)
- Group-based target management: TARGETS_WEB, TARGETS_DATABASE, etc.

- Environment variable validation with helpful error messages

- Automatic IP validation and deduplication

- Security-aware logging - doesn't expose all IPs in production logs

- Designed for Kustomize - all configuration via environment variables

4. Improved Collector (shodan_monitor/collector.py)
- Graceful shutdown handling with signal management

- Progress tracking with detailed statistics

- Error isolation - one target failure doesn't stop entire scan

- Batch processing for efficient database operations

- Comprehensive logging for monitoring and debugging

5. New Utilities (shodan_monitor/utils.py)
- Timer context manager for performance monitoring

- IP validation functions

- Duration formatting utilities

- Graceful shutdown context manager

6. Enhanced CLI (scripts/run_collector.py)
- Multiple operational modes:

- Continuous scanning (production)

- Single scan mode (for cron jobs)

- Statistics display

- Configuration validation

- Cleanup of stuck scans

- Command-line arguments for flexibility

- Better error messages and help text

7. Maintenance Tools (scripts/cleanup_stuck_scans.py)
- Database health checks

- Stuck scan cleanup

- Orphaned data detection

- Database maintenance (VACUUM ANALYZE)

- Dry-run mode for safety

8. Advanced Features (Optional)
- Risk scoring engine (shodan_monitor/risk_scorer.py) - intelligent risk assessment beyond simple vulnerability counting

- Data models (shodan_monitor/models.py) - Pydantic models for data validation

- Multi-platform Docker - supports ARMv7, ARM64, AMD64


## Environment Variables
```
SHODAN_API_KEY  # Shodan API key
DB_HOST         # PostgreSQL host
DB_NAME         # PostgreSQL database name
DB_USER         # PostgreSQL user
DB_PASS         # PostgreSQL password
TARGETS=1.2.3.4,5.6.7.8
TARGETS_WEB=1.2.3.4,5.6.7.8
TARGETS_DATABASE=10.0.0.1,10.0.0.2
TARGETS_TEST=8.8.8.8,1.1.1.1
INTERVAL_SECONDS=21600      # 6 hours (default)
REQUEST_DELAY=1.5           # Seconds between API calls
SHODAN_MAX_RETRIES=3        # API retry attempts
SCAN_TIMEOUT_MINUTES=30     # Mark scans as timeout after this
ENABLE_CLEANUP=true         # Auto-cleanup stuck scans
LOG_LEVEL=INFO             # DEBUG, INFO, WARNING, ERROR
```
