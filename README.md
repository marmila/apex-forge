# Shodan Intelligence Sentinel (SIS)

Shodan Intelligence Sentinel is a modular threat intelligence engine designed for global exposure tracking and vulnerability analytics. Unlike traditional asset monitors, SIS pivots towards proactive threat hunting by leveraging the Shodan Search API to analyze large-scale attack surfaces, command-and-control (C2) infrastructures, and industrial control systems (ICS).

The project implements a polyglot persistence strategy, utilizing PostgreSQL for structured time-series analytics and MongoDB for raw data retention, providing a robust foundation for historical forensic analysis.

## Core Intelligence Modules

* **Exposed Data Analytics**: Tracking of unauthenticated database instances including MongoDB, Elasticsearch, and Redis.
* **C2 Infrastructure Hunting**: Identification of Command & Control frameworks through SSL/TLS fingerprints and banner hashing (e.g., Cobalt Strike, Metasploit, PoshC2).
* **Industrial Guard**: Global monitoring of ICS/SCADA protocols such as Modbus, Siemens S7, and BACnet.
* **CMS Exposure Trends**: Real-time analysis of patch-rates and vulnerabilities across major CMS platforms like WordPress and Drupal.

## Architecture and Data Strategy

The system is designed to handle high-volume data ingestion from the Shodan Search API (Freelancer Plan) with a focus on data integrity and observability.

1. **Extraction**: Asynchronous collection using the Shodan Search Cursor to handle large result sets without pagination overhead.
2. **Polyglot Storage**:
    * **PostgreSQL**: Stores normalized metadata, country distribution, and risk-score trends. Optimized for Grafana visualization.
    * **MongoDB**: Retains full, unstructured JSON banners for retroactive threat hunting and forensic verification.
3. **Observability**: Native integration with Prometheus for security metrics and Alertmanager for real-time notification on threat spikes.

## Tech Stack

* **Language**: Python 3.10+
* **Databases**: PostgreSQL 14+, MongoDB 6.0+
* **Infrastructure**: Designed for Docker and K3s
* **Monitoring**: Prometheus, Grafana, Alertmanager

## Configuration

SIS uses a YAML-based profile system to define intelligence targets.

```
# Example Intelligence Profile
- name: cobalt_strike_tracker
  query: "hash:-2007783223"
  severity: high
  frequency: 6h

- name: exposed_industrial_modbus
  query: "port:502"
  severity: critical
  frequency: 12h
```
## Required Environment Variables

```SHODAN_API_KEY```: Shodan Freelancer/Corporate API Key.

```DB_TYPE```: Set to 'polyglot' for dual-database mode.

```POSTGRES_URL```: Connection string for PostgreSQL analytics.

```MONGO_URL```: Connection string for MongoDB raw storage.

## Deployment
### Kubernetes (k3s)
The collector is optimized for k3s deployments, utilizing ConfigMaps for profile management and Secrets for API credentials. It supports graceful shutdown via SIGTERM to ensure database connection pooling is handled correctly.

```kubectl apply -f k8s/sentinel-deployment.yaml```
+
## Security and Ethics
This tool is strictly for defensive security research and threat intelligence gathering. It operates passively by querying Shodan's indexed data. Users must comply with Shodan's Terms of Service and ensure all intelligence activities remain within legal boundaries.

## License
MIT License.
