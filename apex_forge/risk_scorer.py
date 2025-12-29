import logging
from typing import Dict, Any

# Updated logger name for consistency across ApexForge
logger = logging.getLogger("apexforge.risk")

class RiskScorer:
    """
    Risk scoring engine for ApexForge.
    Evaluates Shodan banners based on vulnerabilities, open ports, tags, and metadata.
    """

    # Weights for risk calculation
    WEIGHT_VULNS = 50
    WEIGHT_CRITICAL_PORTS = 30
    WEIGHT_TAGS = 20

    # Expanded critical ports – includes classic + ICS/SCADA + emerging AI/ML services
    CRITICAL_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5900: "VNC",
        27017: "MongoDB",
        # ICS/SCADA
        502: "Modbus",
        102: "Siemens S7",
        47808: "BACnet",
        # Emerging / AI-related (often exposed)
        5000: "Flask / Docker Registry / UPnP",
        8080: "HTTP Alternate (common proxy/dev)",
        9200: "Elasticsearch",
        6379: "Redis"
    }

    def __init__(self):
        pass

    def calculate_score(self, banner: Dict[str, Any]) -> float:
        """
        Calculate a risk score from 0 to 100 based on banner attributes.
        """
        score = 0.0

        # 1. Vulnerability Factor
        vulns = banner.get('vulns', [])
        if vulns:
            score += self.WEIGHT_VULNS
            logger.debug(f"Vulnerabilities found: {len(vulns)}")

        # 2. Critical Port Factor
        port = banner.get('port')
        if port in self.CRITICAL_PORTS:
            score += self.WEIGHT_CRITICAL_PORTS
            logger.debug(f"Critical port detected: {port} ({self.CRITICAL_PORTS[port]})")

        # 3. Tags and Metadata Factor – broader detection
        tags = banner.get('tags', [])
        tag_bonus = 0.0
        if any(t in tags for t in ['database', 'cloud', 'iot', 'ics', 'scada']):
            tag_bonus += self.WEIGHT_TAGS * 0.7
        if 'auth-bypass' in tags or 'anonymous' in tags:
            tag_bonus += self.WEIGHT_TAGS * 0.5

        score += tag_bonus

        # Reduce score for known honeypots
        if 'honeypot' in tags:
            score -= 40
            logger.debug("Honeypot tag detected – reducing score")

        # Normalize to 0–100
        return max(0.0, min(100.0, score))

    def get_risk_level(self, score: float) -> str:
        """Categorize the risk score into human-readable levels."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "INFO"

    def analyze_banner(self, banner: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform full risk analysis on a banner.
        Returns a summary used in storage and metrics.
        """
        score = self.calculate_score(banner)
        level = self.get_risk_level(score)

        return {
            "score": round(score, 2),  # Nicer precision
            "level": level,
            "critical_port": banner.get('port') in self.CRITICAL_PORTS,
            "has_vulns": len(banner.get('vulns', [])) > 0,
            "tags_triggered": [t for t in banner.get('tags', []) if t in ['database', 'cloud', 'iot', 'ics', 'scada', 'auth-bypass', 'anonymous', 'honeypot']]
        }