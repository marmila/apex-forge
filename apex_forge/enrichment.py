import logging
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger("apexforge.enrichment")

# VirusTotal (requires API key – will be loaded from config/env)
VT_API_URL = "https://www.virustotal.com/api/v3"

class Enricher:
    def __init__(self, vt_api_key: Optional[str] = None):
        self.vt_api_key = vt_api_key
        self.session = requests.Session()
        if self.vt_api_key:
            self.session.headers.update({"x-apikey": self.vt_api_key})

    def enrich_with_virustotal(self, banner: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enrich banner with VirusTotal data if hash or file info exists."""
        if not self.vt_api_key:
            logger.debug("VirusTotal API key not set – skipping VT enrichment")
            return None

        # Look for common hash fields in Shodan banners
        hashes = banner.get("hashes", [])
        if not hashes:
            return None

        # Use first hash (usually JA3 or file hash)
        file_hash = hashes[0] if hashes else None
        if not file_hash:
            return None

        url = f"{VT_API_URL}/files/{file_hash}"
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                vt_data = response.json()
                # Extract meaningful fields
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "detections": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total_engines": stats.get("harmless", 0) + stats.get("malicious", 0) + stats.get("suspicious", 0) + stats.get("undetected", 0),
                    "reputation": vt_data.get("data", {}).get("attributes", {}).get("reputation", 0),
                    "vt_link": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            elif response.status_code == 404:
                logger.debug(f"Hash {file_hash} not found in VirusTotal")
                return {"detections": 0, "note": "not_found"}
        except Exception as e:
            logger.debug(f"VirusTotal request failed for {file_hash}: {e}")
            return None

    def enrich_with_cvedb(self, banner: Dict[str, Any]) -> Dict[str, Any]:
        """Expand CVE entries with summary/description from Shodan CVEDB."""
        vulns = banner.get("vulns", {})
        if not vulns:
            return {}

        enriched_vulns = {}
        for cve_id, vuln_data in vulns.items():
            cve_url = f"https://cvedb.shodan.io/cve/{cve_id}"
            try:
                response = requests.get(cve_url, timeout=5)
                if response.status_code == 200:
                    cve_info = response.json()
                    enriched_vulns[cve_id] = {
                        "cvss": vuln_data.get("cvss", cve_info.get("cvss")),
                        "summary": cve_info.get("summary", "No summary available"),
                        "verified": vuln_data.get("verified", False),
                        "references": cve_info.get("references", [])[:3]  # Top 3
                    }
                else:
                    enriched_vulns[cve_id] = vuln_data  # Fallback
            except Exception as e:
                logger.debug(f"CVEDB fetch failed for {cve_id}: {e}")
                enriched_vulns[cve_id] = vuln_data

        return {"cve_enriched": enriched_vulns} if enriched_vulns else {}