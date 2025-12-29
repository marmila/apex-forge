"""
ApexForge - Continuous Threat Exposure Management platform
"""

__version__ = "3.0.0"
__author__ = "Marco Milano"
__description__ = "Proactive exposure discovery, ML risk scoring, and threat hunting with Shodan + enrichments"

from apex_forge.shodan_client import ShodanClient
from apex_forge.risk_scorer import RiskScorer
from apex_forge.db import get_pg_pool, get_mongo_collection

__all__ = ["ShodanClient", "RiskScorer", "get_pg_pool", "get_mongo_collection"]