## Shodan Security Monitor
A tool that passively monitors your external attack surface using Shodan's API. No active scanning - just collects existing public data and stores it in PostgreSQL for analysis.

## What It Does
Passively collects Shodan data about your IPs
Stores everything in PostgreSQL (targets, services, vulnerabilities)
Calculates risk scores intelligently
Runs continuously or on schedule



## Quick Start
1. Deploy with Docker
```
docker run -d \
  -e SHODAN_API_KEY="your_key" \
  -e TARGETS_WEB="1.2.3.4,5.6.7.8" \
  -e DB_HOST="postgres" \
  -e DB_NAME="shodan" \
  -e DB_USER="shodan" \
  -e DB_PASS="shodan" \
  shodan-sec-monitor
  ```
2. Or Deploy to k3s
```
# kustomization.yaml
configMapGenerator:
- name: shodan-config
  literals:
  - TARGETS_WEB="1.2.3.4,5.6.7.8"
  - INTERVAL_SECONDS="21600"

secretGenerator:
- name: shodan-secrets
  literals:
  - SHODAN_API_KEY="your_key"
  - DB_PASS="shodan"
  ```
## What Gets Stored
Table	What it holds
scan_runs	Scan history, status, timing
targets	IPs, org, country, ASN
services	Ports, products, versions, vulnerabilities
## Minimal Config

# Required
```
SHODAN_API_KEY=your_key_here
DB_HOST=postgres-host
DB_NAME=shodan
DB_USER=shodan
DB_PASS=shodan
TARGETS_WEB=1.2.3.4,5.6.7.8  # Your IPs here
```

# Optional (defaults shown)
```
INTERVAL_SECONDS=21600  # 6 hours
REQUEST_DELAY=1.0       # Seconds between API calls
LOG_LEVEL=INFO
```
## Usage

# Validate your setup
```python scripts/run_collector.py --validate```

# Run once (for cron jobs)
``` python scripts/run_collector.py --once```

# Run continuously
```python scripts/run_collector.py```

# Show stats
```python scripts/run_collector.py --stats```

# Cleanup stuck scans
```python scripts/clean_stuck_scans.py --cleanup-stuck```
# Useful SQL Queries
```
-- High-risk services
SELECT t.ip, s.port, s.product, s.risk_score
FROM services s
JOIN targets t ON s.target_id = t.id
WHERE s.risk_score > 70
ORDER BY s.risk_score DESC;
```
```
-- Scan performance
SELECT status, COUNT(*), AVG(finished_at - started_at)
FROM scan_runs
GROUP BY status;
```
```
-- Latest vulnerabilities
SELECT t.ip, s.port, s.vulns
FROM services s
JOIN targets t ON s.target_id = t.id
WHERE jsonb_array_length(s.vulns) > 0;
```
## Project Structure
```
shodan-sec-monitor/
├── Dockerfile          # Multi-arch build
├── build.sh           # Build script
├── scripts/           # CLI tools
└── shodan_monitor/    # Python package
    ├── collector.py   # Main logic
    ├── db.py          # Database ops
    ├── config.py      # Config loader
    └── shodan_client.py # API calls
```
## Multi-Plat

# Build for ARM and AMD64
```./build.sh```

# Or manually
```docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t your-registry/shodan-sec-monitor:latest \
  --push .
```
## Important Notes
Passive only - uses Shodan API, no active scanning
Rate limited - respects Shodan's API limits
IP validation - checks all targets before scanning

# Test config
```python scripts/run_collector.py --validate```

# See logs
```kubectl logs -f deployment/shodan-collector```

# Check database
```python scripts/run_collector.py --stats```

# License
MIT License. Use responsibly - only scan IPs you own.