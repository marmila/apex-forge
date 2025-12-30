# ApexForge

**ApexForge** is an open-source **Continuous Threat Exposure Management (CTEM)** platform designed for proactive discovery, enrichment, risk scoring, and monitoring of internet-facing assets and vulnerabilities.

Built on Shodan as the primary intelligence source with built-in support for InternetDB enrichment and extensions for CVEDB and VirusTotal, ApexForge delivers:

- **Polyglot persistence**: MongoDB for raw banner storage, PostgreSQL for structured analytics and trends
- **Advanced risk scoring** with extensible architecture for future ML integration (PyTorch + scikit-learn ready)
- **Full observability**: Prometheus metrics, structured JSON logs (Kibana), Grafana dashboards, Alertmanager alerts
- **Production-grade security**: HashiCorp Vault + External Secrets for API keys and DB credentials
- **Edge-optimized**: Multi-platform Docker images for amd64 and arm64

## Core Threat Hunting Modules

- Unauthenticated databases (MongoDB, Redis, Elasticsearch)
- C2 infrastructure (Cobalt Strike beacons, JARM fingerprints)
- Industrial control systems (Modbus, Siemens S7, BACnet)
- Vulnerable web applications (WordPress, phpMyAdmin)
- To add: Emerging risks: exposed AI/ML services (Flask, TensorBoard, Jupyter on ports 5000–9000)

## Architecture

1. **Collection** — Incremental Shodan searches using cursor API
2. **Enrichment** — InternetDB (free), CVE details from CVEDB, VirusTotal hash reputation
3. **Storage**
   - MongoDB → raw enriched banners (forensic analysis)
   - PostgreSQL → aggregated stats, country distribution, risk trends
4. **Analysis** — Heuristic risk scoring with extensible ML architecture
5. **Observability** — Prometheus, Grafana, Loki/Tempo, Kibana (ELK stack)
6. **Alerting** — Alertmanager notifications on exposure spikes and critical assets

## Tech Stack

- Python 3.11
- PostgreSQL 15 + MongoDB
- Docker (multi-arch: amd64/arm64)
- k3s + Longhorn + Vault + External Secrets + Flux CD
- Prometheus, Grafana, Alertmanager, Kibana
- PyTorch, scikit-learn (ML-ready)
- FastAPI (internal query API)

## Configuration

Threat profiles are defined in `profiles.yaml`:

```
intelligence_profiles:
  - name: unauthenticated_mongodb
    query: "product:mongodb port:27017 -authentication"
    severity: critical
    tags: [database, leak]
    enrich_with_internetdb: true

  - name: cobalt_strike_c2
    query: "hash:-2007783223"
    severity: high
    tags: [c2, malware]
    enrich_with_internetdb: true

  - name: exposed_ai_services
    query: "port:5000..9000 (flask OR tensorboard OR jupyter)"
    severity: high
    enrich_with_internetdb: true
```

## Testing
Full test suite with pytest: `pytest -q`
All tests pass — covering risk scoring, enrichment, and DB operations.

## Deployment
Build and push multi-platform image

`./build.sh`

## Deploy on k3s

`kubectl apply -f k8s/deployment.yaml`

The collector uses existing secrets:

- shodan-secret → `SHODAN_API_KEY`
- virustotal-api-key → `VIRUSTOTAL_API_KEY`
- shodan-db-credentials → `PostgreSQL`
- shodan-mongo-credentials → `MongoDB`

## Security & Ethics
This tool performs passive intelligence gathering using publicly indexed data from Shodan.
It is intended strictly for:

- Defensive security research
- Threat hunting
- Exposure monitoring

Users must comply with:

- Shodan Terms of Service
- All applicable laws and regulations

No active scanning or exploitation is performed.

## License

MIT License
