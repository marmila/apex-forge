# Shodan Security Monitor

Python application to fetch Shodan scan data for target IPs, compute risk scores, and store results in PostgreSQL.

## Structure
- `app/db.py` → PostgreSQL connection & table creation
- `scripts/shodan_collector.py` → main Shodan collector
- `Dockerfile` → multi-arch Docker image
- `requirements.txt` → Python dependencies

## Usage
Build multi-arch image:

`docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/username/shodan-sec-monitor:latest --push` .
