"""
Intelligent risk scoring for Shodan services.
Moves beyond simple vulnerability counting to analyze service characteristics.
"""
import re
from typing import List, Dict, Any, Optional


class RiskScorer:
    """
    Calculates risk scores (0-100) based on multiple factors:
    - Number and severity of vulnerabilities
    - Service type and port
    - Default vs non-default ports
    - Service version age
    - Configuration weaknesses
    """

    # Risk weights for different service types
    SERVICE_RISK_WEIGHTS = {
        # High-risk services
        'ssh': 30, 'telnet': 40, 'ftp': 35, 'rdp': 35, 'vnc': 35,
        'mysql': 25, 'postgresql': 25, 'redis': 30, 'mongodb': 30,
        'elasticsearch': 30, 'kibana': 30, 'jenkins': 35,

        # Medium-risk services
        'http': 15, 'https': 10, 'smtp': 20, 'dns': 15, 'snmp': 25,
        'ldap': 20, 'kerberos': 20, 'ntp': 10,

        # Low-risk services (default)
        '_default': 10
    }

    # Default ports for common services
    DEFAULT_PORTS = {
        'ssh': 22, 'telnet': 23, 'ftp': 21, 'smtp': 25, 'dns': 53,
        'http': 80, 'https': 443, 'mysql': 3306, 'postgresql': 5432,
        'rdp': 3389, 'vnc': 5900, 'redis': 6379, 'mongodb': 27017,
        'elasticsearch': 9200, 'kibana': 5601, 'jenkins': 8080
    }

    # Critical vulnerability patterns
    CRITICAL_VULN_PATTERNS = [
        r'CVE-\d{4}-(0\d{3}|1\d{3}|2[0-4]\d{2}|25[0-5]\d{2})',  # Early CVE years
        r'remote.*code.*execution',
        r'privilege.*escalation',
        r'authentication.*bypass',
        r'buffer.*overflow',
        r'sql.*injection',
        r'cross.*site.*scripting',
        r'path.*traversal'
    ]

    # Weak configuration indicators in banners
    WEAK_CONFIG_PATTERNS = [
        (r'anonymous.*login', 25),
        (r'default.*password', 30),
        (r'root.*password', 25),
        (r'admin.*admin', 20),
        (r'guest.*guest', 20),
        (r'test.*test', 15),
        (r'weak.*cipher', 20),
        (r'ssl.*v[23]', 25),
        (r'tls.*1\.0', 15),
        (r'null.*cipher', 30)
    ]

    # Outdated version patterns
    OUTDATED_VERSION_PATTERNS = [
        (r'apache.*2\.2\.', 20),
        (r'nginx.*1\.(0|2|4|6|8|10|12|14)', 15),
        (r'openssh.*(5|6|7\.0|7\.1|7\.2|7\.3)', 25),
        (r'openssl.*1\.0\.', 30),
        (r'php.*5\.', 20),
        (r'wordpress.*4\.', 15),
        (r'tomcat.*[0-7]\.', 15),
        (r'iis.*(6|7|8)\.', 15)
    ]

    def __init__(self, custom_rules: Optional[Dict] = None):
        """
        Initialize risk scorer with optional custom rules.

        Args:
            custom_rules: Dict with custom scoring rules, e.g.:
                {
                    'service_weights': {'custom_service': 40},
                    'critical_ports': [8443, 9443],
                    'ignore_patterns': [r'test.*server']
                }
        """
        self.custom_rules = custom_rules or {}

    def calculate_risk_score(
        self,
        service_info: Dict[str, Any],
        vulnerabilities: List[str]
    ) -> int:
        """
        Calculate comprehensive risk score (0-100).

        Args:
            service_info: Dictionary with keys:
                - port: int
                - product: str (optional)
                - version: str (optional)
                - banner: str (optional)
                - transport: str (default: 'tcp')
            vulnerabilities: List of vulnerability IDs/CVEs

        Returns:
            Risk score between 0 and 100
        """
        score = 0

        # 1. Base score from vulnerabilities
        vuln_score = self._score_vulnerabilities(vulnerabilities)
        score += vuln_score

        # 2. Service type risk
        service_type_score = self._score_service_type(service_info)
        score += service_type_score

        # 3. Configuration weakness
        config_score = self._score_configuration(service_info)
        score += config_score

        # 4. Version age risk
        version_score = self._score_version_age(service_info)
        score += version_score

        # 5. Apply custom rules if any
        if self.custom_rules:
            score = self._apply_custom_rules(score, service_info)

        # Cap at 100
        return min(100, max(0, score))

    def _score_vulnerabilities(self, vulnerabilities: List[str]) -> int:
        """Score based on vulnerabilities."""
        if not vulnerabilities:
            return 0

        base_score = len(vulnerabilities) * 10  # 10 points per vulnerability

        # Bonus for critical vulnerabilities
        critical_count = 0
        for vuln in vulnerabilities:
            vuln_lower = vuln.lower()
            for pattern in self.CRITICAL_VULN_PATTERNS:
                if re.search(pattern, vuln_lower, re.IGNORECASE):
                    critical_count += 1
                    break

        # Add extra points for critical vulnerabilities
        base_score += critical_count * 15

        return min(50, base_score)  # Cap vulnerability score at 50

    def _score_service_type(self, service_info: Dict) -> int:
        """Score based on service type and port."""
        product = (service_info.get('product') or '').lower()
        port = service_info.get('port', 0)

        # Try to identify service from product name
        for service_name, weight in self.SERVICE_RISK_WEIGHTS.items():
            if service_name in product:
                score = weight

                # Bonus for running on default port (more likely to be attacked)
                if service_name in self.DEFAULT_PORTS:
                    if port == self.DEFAULT_PORTS[service_name]:
                        score += 10

                return score

        # Default score for unknown services
        default_score = self.SERVICE_RISK_WEIGHTS.get('_default', 10)

        # Check if port is in well-known range
        if 0 < port <= 1024:  # Well-known ports
            default_score += 5

        return default_score

    def _score_configuration(self, service_info: Dict) -> int:
        """Score based on configuration weaknesses."""
        banner = (service_info.get('banner') or '').lower()
        product = (service_info.get('product') or '').lower()

        score = 0

        # Check banner for weak configuration patterns
        for pattern, points in self.WEAK_CONFIG_PATTERNS:
            if re.search(pattern, banner, re.IGNORECASE):
                score += points

        # Check for anonymous/unauth services
        unauth_services = ['ftp', 'telnet', 'vnc', 'redis', 'mongodb', 'elasticsearch']
        for service in unauth_services:
            if service in product and 'auth' not in banner:
                score += 20
                break

        return min(30, score)  # Cap config score at 30

    def _score_version_age(self, service_info: Dict) -> int:
        """Score based on outdated versions."""
        product = (service_info.get('product') or '').lower()
        version = (service_info.get('version') or '').lower()

        if not product or not version:
            return 0

        full_info = f"{product} {version}"

        score = 0
        for pattern, points in self.OUTDATED_VERSION_PATTERNS:
            if re.search(pattern, full_info, re.IGNORECASE):
                score += points

        return min(20, score)  # Cap version score at 20

    def _apply_custom_rules(self, score: int, service_info: Dict) -> int:
        """Apply custom scoring rules."""
        # Custom service weights
        custom_weights = self.custom_rules.get('service_weights', {})
        product = (service_info.get('product') or '').lower()

        for service_name, weight in custom_weights.items():
            if service_name in product:
                score += weight - self.SERVICE_RISK_WEIGHTS.get('_default', 10)

        # Custom critical ports
        critical_ports = self.custom_rules.get('critical_ports', [])
        port = service_info.get('port', 0)

        if port in critical_ports:
            score += 15

        # Ignore patterns
        ignore_patterns = self.custom_rules.get('ignore_patterns', [])
        banner = (service_info.get('banner') or '').lower()

        for pattern in ignore_patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                score = max(0, score - 10)  # Reduce score for ignored patterns

        return score

    def get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"

    def generate_risk_report(
        self,
        service_info: Dict,
        vulnerabilities: List[str]
    ) -> Dict[str, Any]:
        """
        Generate detailed risk analysis report.

        Returns:
            Dict with risk analysis details
        """
        score = self.calculate_risk_score(service_info, vulnerabilities)
        risk_level = self.get_risk_level(score)

        # Analyze factors
        vuln_score = self._score_vulnerabilities(vulnerabilities)
        service_score = self._score_service_type(service_info)
        config_score = self._score_configuration(service_info)
        version_score = self._score_version_age(service_info)

        # Count critical vulnerabilities
        critical_vulns = 0
        for vuln in vulnerabilities:
            vuln_lower = vuln.lower()
            for pattern in self.CRITICAL_VULN_PATTERNS:
                if re.search(pattern, vuln_lower, re.IGNORECASE):
                    critical_vulns += 1
                    break

        return {
            'total_score': score,
            'risk_level': risk_level,
            'breakdown': {
                'vulnerabilities': vuln_score,
                'service_type': service_score,
                'configuration': config_score,
                'version_age': version_score
            },
            'vulnerability_analysis': {
                'total': len(vulnerabilities),
                'critical': critical_vulns,
                'list': vulnerabilities[:10]  # First 10 only
            },
            'recommendations': self._generate_recommendations(service_info, score)
        }

    def _generate_recommendations(
        self,
        service_info: Dict,
        score: int
    ) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        product = (service_info.get('product') or '').lower()
        port = service_info.get('port', 0)

        if score >= 70:
            recommendations.append("Immediate remediation required - high risk exposure")

        # Service-specific recommendations
        if 'ssh' in product and port == 22:
            recommendations.extend([
                "Change SSH from default port 22",
                "Implement key-based authentication",
                "Disable root login"
            ])

        if 'ftp' in product and 'sftp' not in product:
            recommendations.append("Replace FTP with SFTP or FTPS")

        if 'telnet' in product:
            recommendations.append("Replace Telnet with SSH")

        if 'http' in product and 'https' not in product:
            recommendations.append("Enable HTTPS with valid certificate")

        if not recommendations and score > 30:
            recommendations.append("Review configuration and apply security updates")

        return recommendations