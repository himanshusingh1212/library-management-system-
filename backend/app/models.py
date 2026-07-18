"""Core data models shared by every scanner, the AI engine, and the report generator."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    NETWORK = "network"
    KEY_VAULT = "key_vault"
    STORAGE = "storage"
    IDENTITY = "identity"


class MitreMapping(BaseModel):
    tactic_id: str = Field(..., description="ATT&CK tactic ID, e.g. TA0001")
    tactic_name: str = Field(..., description="e.g. Initial Access")
    technique_id: str = Field(..., description="ATT&CK technique ID, e.g. T1190")
    technique_name: str = Field(..., description="e.g. Exploit Public-Facing Application")


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: Category
    rule_id: str = Field(..., description="Stable identifier for the check that produced this finding")
    title: str
    description: str
    severity: Severity
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    resource_id: str
    resource_name: str
    resource_type: str
    recommendation: str
    mitre: MitreMapping
    evidence: dict = Field(default_factory=dict, description="Raw config values that triggered the finding")
    detected_at: datetime = Field(default_factory=datetime.utcnow)


class ScanError(BaseModel):
    scanner: str
    message: str
    is_coverage_gap: bool = True


class ScannerSummary(BaseModel):
    scanner: str
    resources_scanned: int
    findings_count: int
    errors: list[ScanError] = Field(default_factory=list)


class AIAnalysis(BaseModel):
    executive_summary: str
    top_risks: list[str]
    remediation_plan: list[str]
    business_impact: str


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subscription_id: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    findings: list[Finding] = Field(default_factory=list)
    scanner_summaries: list[ScannerSummary] = Field(default_factory=list)
    ai_analysis: Optional[AIAnalysis] = None
    severity_counts: dict[str, int] = Field(default_factory=dict)

    def compute_severity_counts(self) -> None:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        self.severity_counts = counts
