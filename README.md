# ApexForge

**ApexForge** is an open-source **Continuous Threat Exposure Management (CTEM)** platform designed for proactive discovery, enrichment, risk scoring, and monitoring of internet-facing assets and vulnerabilities.

Built on Shodan as the primary intelligence source — with built-in support for InternetDB enrichment and future extensions (CVEDB, VirusTotal, Censys) — ApexForge delivers:

- **Polyglot persistence**: MongoDB for raw banner storage, PostgreSQL for structured analytics and trends
- **ML-enhanced risk scoring** and anomaly detection (PyTorch + scikit-learn)
- **Full observability**: Prometheus metrics, structured JSON logs (Kibana), Grafana dashboards, Alertmanager alerts
- **Production-grade security**: HashiCorp Vault + External Secrets for API keys and DB credentials
- **Edge-optimized**: Multi-platform Docker images.


## Core Threat Hunting Modules

- Unauthenticated databases (MongoDB, Redis, Elasticsearch)
- C2 infrastructure (Cobalt Strike beacons, JARM fingerprints)
- Industrial control systems (Modbus, S7, BACnet)
- Vulnerable web applications (WordPress, phpMyAdmin)
- Emerging risks: exposed AI/ML services (Flask, TensorBoard on port 5000–9000)

## Architecture

1. **Collection** — Incremental Shodan searches using cursor API
2. **Enrichment** — InternetDB (free), future: CVE details, VirusTotal
3. **Storage**
   - MongoDB → raw banners (forensic analysis)
   - PostgreSQL → aggregated stats, country distribution, time-series trends
4. **Analysis** — ML-based risk scoring and anomaly detection
5. **Observability** — Prometheus, Grafana, Loki/Tempo, Kibana (ELK stack)
6. **Alerting** — Alertmanager notifications on exposure spikes

## Tech Stack

- Python 3.11
- PostgreSQL 15 + MongoDB
- Docker (multi-arch: amd64/arm64)
- k3s + Longhorn + Vault + External Secrets + Flux CD
- Prometheus, Grafana, Alertmanager, Kibana
- PyTorch, scikit-learn (ML risk engine)

## Configuration

Threat profiles defined in `profiles.yaml`:

```
intelligence_profiles:
  - name: unauthenticated_mongodb
    query: "product:mongodb port:27017 -authentication"
    severity: critical
    tags: [database, leak]

  - name: cobalt_strike_c2
    query: "hash:-2007783223"
    severity: high
    tags: [c2, malware]

  - name: exposed_ai_services
    query: "port:5000..9000 (flask OR tensorboard OR jupyter)"
    severity: high
```


## Build and push multi-platform image
./build.sh

## Update deployment image tag and apply

```kubectl apply -f k8s/deployment.yaml```

## Security & Ethics
This tool performs passive intelligence gathering using publicly indexed data from Shodan.
It is intended strictly for defensive security research, threat hunting, and exposure monitoring.
Users must comply with:

- Shodan Terms of Service
- All applicable laws and regulations

No active scanning or exploitation is performed.

## License
MIT License
