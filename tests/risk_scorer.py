from apex_forge.risk_scorer import RiskScorer

def test_critical_port_detection():
    scorer = RiskScorer()
    banner = {"port": 502}  # Modbus
    analysis = scorer.analyze_banner(banner)
    assert analysis["critical_port"] is True
    assert analysis["level"] in ("MEDIUM", "HIGH", "CRITICAL")  # Gets port weight

def test_vuln_detection():
    scorer = RiskScorer()
    banner = {"vulns": ["CVE-2024-1234"]}
    analysis = scorer.analyze_banner(banner)
    assert analysis["has_vulns"] is True
    assert analysis["score"] >= 50  # VULNS weight

def test_honeypot_deduction():
    scorer = RiskScorer()
    banner = {"port": 22, "tags": ["honeypot"]}
    analysis = scorer.analyze_banner(banner)
    assert analysis["score"] < 50  # Reduced due to honeypot

def test_ics_tag_bonus():
    scorer = RiskScorer()
    banner = {"port": 80, "tags": ["ics", "scada"]}
    analysis = scorer.analyze_banner(banner)
    assert analysis["score"] > 0  # Gets tag bonus
    assert "ics" in analysis["tags_triggered"]