"""FastAPI application: wires scanners, MITRE mapping, AI analysis, and PDF reports together."""

import logging

from azure.identity import DefaultAzureCredential
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from app.ai_analysis import generate_ai_analysis
from app.config import Settings, get_settings
from app.models import ScanResult, ScannerSummary
from app.report import generate_pdf_report
from app.scanners import (
    scan_conditional_access,
    scan_key_vaults,
    scan_network_security_groups,
    scan_storage_accounts,
)
from app.store import ScanStore
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SecureOps AI",
    description="Automated Azure security posture scanning with MITRE ATT&CK mapping and AI-generated reporting.",
    version="0.1.0",
)

settings = get_settings()
store = ScanStore(settings.scan_store_path)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_allowed_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCANNERS = [
    scan_network_security_groups,
    scan_key_vaults,
    scan_storage_accounts,
    scan_conditional_access,
]


class ScanRequest(BaseModel):
    subscription_id: str
    include_network: bool = True
    include_key_vault: bool = True
    include_storage: bool = True
    include_identity: bool = True
    skip_ai_analysis: bool = False


def _selected_scanners(req: ScanRequest):
    selected = []
    if req.include_network:
        selected.append(scan_network_security_groups)
    if req.include_key_vault:
        selected.append(scan_key_vaults)
    if req.include_storage:
        selected.append(scan_storage_accounts)
    if req.include_identity:
        selected.append(scan_conditional_access)
    return selected


def _run_scan(req: ScanRequest, settings: Settings) -> ScanResult:
    credential = DefaultAzureCredential()
    result = ScanResult(subscription_id=req.subscription_id)

    for scanner_fn in _selected_scanners(req):
        try:
            findings, summary = scanner_fn(credential, req.subscription_id, settings)
        except Exception as exc:  # a scanner failing must never crash the whole run
            logger.exception("Scanner %s raised unexpectedly", scanner_fn.__name__)
            summary = ScannerSummary(
                scanner=scanner_fn.__name__,
                resources_scanned=0,
                findings_count=0,
                errors=[],
            )
            findings = []
        result.findings.extend(findings)
        result.scanner_summaries.append(summary)

    result.compute_severity_counts()

    if not req.skip_ai_analysis and settings.anthropic_api_key:
        try:
            result.ai_analysis = generate_ai_analysis(result.findings, settings)
        except Exception:
            logger.exception("AI analysis failed; continuing without it")

    result.completed_at = datetime.utcnow()
    return result


@app.post("/api/scan", response_model=ScanResult)
def create_scan(req: ScanRequest) -> ScanResult:
    if not req.subscription_id:
        raise HTTPException(status_code=400, detail="subscription_id is required")
    result = _run_scan(req, settings)
    store.save(result)
    return result


@app.get("/api/scan/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str) -> ScanResult:
    result = store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/api/scan/{scan_id}/report")
def get_scan_report(scan_id: str) -> Response:
    result = store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf_bytes = generate_pdf_report(result)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="secureops-ai-report-{scan_id}.pdf"'},
    )


@app.get("/api/scans")
def list_scans() -> list[str]:
    return store.list_ids()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}
