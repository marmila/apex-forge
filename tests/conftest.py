import pytest

@pytest.fixture
def sample_banner():
    """Basic Shodan banner for testing"""
    return {
        "ip_str": "1.2.3.4",
        "port": 502,
        "timestamp": "2025-12-30T12:00:00.000000",
        "location": {"country_code": "US"},
        "tags": ["ics", "honeypot"],
        "vulns": ["CVE-2024-0001"],
        "hashes": ["abc123def456"]  # for VT mock
    }