# shodan-sec-monitor

Shodan Security Monitor is a Python-based batch collector designed to periodically scan target IPs using the Shodan API and store the results in a PostgreSQL database. These results can then be visualized via dashboards like Grafana.

This project is intended as a modular, extensible collector for future enhancements.

## Features

- Batch collection of Shodan data for specified IP targets.
- Stores results in a PostgreSQL database.
- Modular Python structure with separation between database logic and Shodan scanning.
- Ready for future extensions (e.g., additional data collectors, alerts, or integrations).
- Designed for containerized deployment with Kubernetes.

## Requirements

- Python 3.11+
- PostgreSQL 12+
- Shodan API key

## Installation

Build the Docker image:

`docker build -t ghcr.io/marmila/shodan-sec-monitor:latest .`

## Run locally (for testing):


`export SHODAN_API_KEY="your_api_key"
export TARGETS="8.8.8.8,1.1.1.1"`

` docker run --rm \
  -e SHODAN_API_KEY \
  -e TARGETS \
  ghcr.io/marmila/shodan-sec-monitor:latest
Environment Variables
SHODAN_API_KEY – Your Shodan API key.`

- `TARGETS` – Comma-separated list of IPs to scan.
- `DB_HOST` – PostgreSQL hostname.
- `DB_NAME` – Database name.
- `DB_USER` – Database user.
- `DB_PASS` – Database password.


## Deployment Notes
Designed to run as a Kubernetes CronJob or Deployment for scheduled collection.
PostgreSQL must be accessible from the container.
Ensure ConfigMaps and Secrets are properly mounted for credentials and target lists.

## License
MIT License
