import pytest
from unittest.mock import patch
from apex_forge.enrichment import Enricher

@pytest.fixture
def enricher():
    return Enricher(vt_api_key="fake_key")

def test_virustotal_enrichment_success(enricher):
    banner = {"hashes": ["abc123"]}

    mock_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 2},
                "reputation": -10
            }
        }
    }

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = mock_response

        result = enricher.enrich_with_virustotal(banner)
        assert result["detections"] == 7
        assert result["reputation"] == -10

def test_cvedb_enrichment(enricher):
    banner = {"vulns": {"CVE-2024-0001": {"cvss": 9.8}}}

    mock_cve = {"summary": "Critical remote code execution", "cvss": 9.8}

    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = mock_cve

        result = enricher.enrich_with_cvedb(banner)
        enriched = result["cve_enriched"]["CVE-2024-0001"]
        assert enriched["summary"] == "Critical remote code execution"
        assert enriched["cvss"] == 9.8