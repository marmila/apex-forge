from pydantic import BaseModel, Field, validator
from typing import List, Optional
from datetime import datetime

class IntelProfile(BaseModel):
    """
    Validates the structure of a Threat Intelligence profile
    defined in profiles.yaml.
    """
    name: str
    query: str
    severity: str = "medium"
    tags: List[str] = []
    enrich_with_internetdb: bool = True

    @validator('severity')
    def severity_must_be_valid(cls, v):
        valid_levels = ['info', 'low', 'medium', 'high', 'critical']
        if v.lower() not in valid_levels:
            raise ValueError(f"Severity must be one of {valid_levels}")
        return v.lower()

class IntelStatsSummary(BaseModel):
    """
    Represents the structured data for PostgreSQL analytics.
    """
    profile_name: str
    total_count: int
    country_dist: dict
    last_updated: datetime

class RiskAnalysis(BaseModel):
    """
    Represents the output of the RiskScorer.
    """
    score: float
    level: str
    has_vulns: bool
    critical_port: bool