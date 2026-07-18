"""Turns structured scanner findings into a stakeholder-readable narrative via Claude."""

import json
import logging

import anthropic

from app.config import Settings
from app.models import AIAnalysis, Finding

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a cloud security analyst producing an audit report for a small \
organization's leadership and SOC team. You will be given a JSON array of \
Azure security findings (network, secrets/Key Vault, storage, and identity \
misconfigurations), each with a severity, CVSS score, and MITRE ATT&CK \
mapping.

Respond with ONLY a single JSON object — no prose before or after it, no \
markdown code fences — matching exactly this shape:

{
  "executive_summary": "2-4 sentence plain-English summary of the overall security posture, written for a non-technical stakeholder.",
  "top_risks": ["3-6 short strings, each naming the single most dangerous risk from these findings and why it matters"],
  "remediation_plan": ["4-8 short strings, ordered by priority, each a concrete actionable fix step"],
  "business_impact": "2-4 sentences translating the technical risk into what could actually go wrong for the business (data breach, downtime, compliance exposure, cost) if left unfixed."
}

Be specific and reference the actual findings given — do not write generic \
boilerplate. Do not invent findings that were not provided.
"""


def _findings_to_prompt_payload(findings: list[Finding]) -> list[dict]:
    return [
        {
            "category": f.category.value,
            "title": f.title,
            "severity": f.severity.value,
            "cvss_score": f.cvss_score,
            "resource_name": f.resource_name,
            "mitre_technique": f"{f.mitre.technique_id} - {f.mitre.technique_name}",
            "recommendation": f.recommendation,
        }
        for f in findings
    ]


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def generate_ai_analysis(findings: list[Finding], settings: Settings) -> AIAnalysis:
    if not settings.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not configured")

    if not findings:
        return AIAnalysis(
            executive_summary="No misconfigurations were detected across the scanned categories in this run.",
            top_risks=[],
            remediation_plan=[],
            business_impact="No immediate action required based on this scan. Continue periodic scanning to catch drift.",
        )

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    payload = _findings_to_prompt_payload(findings)

    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(payload, indent=2)}],
    )

    raw_text = "".join(block.text for block in response.content if block.type == "text")
    cleaned = _strip_code_fences(raw_text)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.error("Claude did not return valid JSON: %s", raw_text)
        raise ValueError(f"AI analysis response was not valid JSON: {exc}") from exc

    return AIAnalysis.model_validate(parsed)
