import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class RiskScorer:
    """
    Engine to evaluate risk scores for Shodan banners.
    Analyzes vulnerabilities, open ports, and service metadata.
    """

    # Weights for risk calculation
    WEIGHT_VULNS = 50
    WEIGHT_CRITICAL_PORTS = 30
    WEIGHT_TAGS = 20

    CRITICAL_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5900: "VNC",
        27017: "MongoDB"
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
            # If vulnerabilities are present, increase score significantly
            score += self.WEIGHT_VULNS
            logger.debug(f"Vulnerabilities found: {len(vulns)}")

        # 2. Critical Port Factor
        port = banner.get('port')
        if port in self.CRITICAL_PORTS:
            score += self.WEIGHT_CRITICAL_PORTS
            logger.debug(f"Critical port detected: {port} ({self.CRITICAL_PORTS[port]})")

        # 3. Tags and Metadata Factor
        tags = banner.get('tags', [])
        if 'database' in tags or 'cloud' in tags:
            score += self.WEIGHT_TAGS * 0.5

        if 'honeypot' in tags:
            # Reduce score for honeypots as they are intentional decoys
            score -= 40

        # Normalize score between 0 and 100
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
        Perform a full risk analysis on a banner.
        Returns a summary of risk findings.
        """
        score = self.calculate_score(banner)
        return {
            "score": score,
            "level": self.get_risk_level(score),
            "critical_port": banner.get('port') in self.CRITICAL_PORTS,
            "has_vulns": len(banner.get('vulns', [])) > 0
        }