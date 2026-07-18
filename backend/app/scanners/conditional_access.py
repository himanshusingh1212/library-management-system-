"""Conditional Access scanner: queries Microsoft Graph directly (Entra ID lives outside ARM)."""

import requests
from azure.core.credentials import TokenCredential

from app.config import Settings
from app.mitre import get_mitre_mapping
from app.models import Category, Finding, ScanError, ScannerSummary, Severity

SCANNER_NAME = "conditional_access"

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_POLICIES_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

LEGACY_AUTH_CLIENT_APP_TYPES = {"exchangeActiveSync", "other"}


def _get_graph_token(credential: TokenCredential) -> str:
    token = credential.get_token(GRAPH_SCOPE)
    return token.token


def scan_conditional_access(
    credential: TokenCredential, subscription_id: str, settings: Settings
) -> tuple[list[Finding], ScannerSummary]:
    findings: list[Finding] = []
    errors: list[ScanError] = []

    try:
        access_token = _get_graph_token(credential)
    except Exception as exc:
        errors.append(
            ScanError(
                scanner=SCANNER_NAME,
                message=f"Failed to acquire a Microsoft Graph token (check Policy.Read.All grant/consent): {exc}",
            )
        )
        return findings, ScannerSummary(scanner=SCANNER_NAME, resources_scanned=0, findings_count=0, errors=errors)

    try:
        response = requests.get(
            GRAPH_POLICIES_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30,
        )
        response.raise_for_status()
        policies = response.json().get("value", [])
    except requests.RequestException as exc:
        errors.append(ScanError(scanner=SCANNER_NAME, message=f"Failed to call Microsoft Graph: {exc}"))
        return findings, ScannerSummary(scanner=SCANNER_NAME, resources_scanned=0, findings_count=0, errors=errors)

    scanned = len(policies)
    enabled_policies = [p for p in policies if p.get("state") == "enabled"]
    report_only_policies = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]

    if not policies:
        findings.append(
            Finding(
                category=Category.IDENTITY,
                rule_id="ca-no-policies",
                title="No Conditional Access policies exist in this tenant",
                description=(
                    "There are zero Conditional Access policies configured. Sign-in to every "
                    "application is governed only by basic authentication, with no risk-based, "
                    "device-based, or MFA controls in place."
                ),
                severity=Severity.CRITICAL,
                cvss_score=9.4,
                resource_id=f"tenant/{settings.azure_tenant_id or 'unknown'}",
                resource_name="Entra ID tenant",
                resource_type="Microsoft.Graph/conditionalAccessPolicies",
                recommendation="Create baseline Conditional Access policies requiring MFA for all users and blocking legacy authentication.",
                mitre=get_mitre_mapping("ca-no-policies"),
                evidence={"policy_count": 0},
            )
        )
        return findings, ScannerSummary(
            scanner=SCANNER_NAME, resources_scanned=scanned, findings_count=len(findings), errors=errors
        )

    mfa_enforced = any(
        "mfa" in [c.lower() for c in (p.get("grantControls") or {}).get("builtInControls", [])]
        for p in enabled_policies
    )
    if not mfa_enforced:
        findings.append(
            Finding(
                category=Category.IDENTITY,
                rule_id="ca-no-mfa-enforced",
                title="MFA is not enforced by any enabled Conditional Access policy",
                description=(
                    "No enabled Conditional Access policy requires multi-factor authentication. "
                    "Compromised passwords (phishing, credential stuffing, password spray) are "
                    "sufficient on their own to gain access to the tenant."
                ),
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                resource_id=f"tenant/{settings.azure_tenant_id or 'unknown'}",
                resource_name="Entra ID tenant",
                resource_type="Microsoft.Graph/conditionalAccessPolicies",
                recommendation="Enable a Conditional Access policy that requires MFA for all users on all cloud apps.",
                mitre=get_mitre_mapping("ca-no-mfa-enforced"),
                evidence={"enabled_policy_count": len(enabled_policies)},
            )
        )

    legacy_auth_blocked = any(
        "exchangeActiveSync" in (p.get("conditions", {}).get("clientAppTypes") or [])
        or "other" in (p.get("conditions", {}).get("clientAppTypes") or [])
        for p in enabled_policies
        if (p.get("grantControls") or {}).get("operator") == "block"
        or "block" in [c.lower() for c in (p.get("grantControls") or {}).get("builtInControls", [])]
    )
    if not legacy_auth_blocked:
        findings.append(
            Finding(
                category=Category.IDENTITY,
                rule_id="ca-legacy-auth-allowed",
                title="Legacy authentication protocols are not blocked",
                description=(
                    "No enabled policy blocks legacy authentication (e.g. IMAP, POP, older Office "
                    "clients). Legacy protocols don't support MFA and are a favored path for "
                    "password-spray attacks."
                ),
                severity=Severity.HIGH,
                cvss_score=8.1,
                resource_id=f"tenant/{settings.azure_tenant_id or 'unknown'}",
                resource_name="Entra ID tenant",
                resource_type="Microsoft.Graph/conditionalAccessPolicies",
                recommendation="Create a Conditional Access policy that blocks sign-in for legacy authentication client app types.",
                mitre=get_mitre_mapping("ca-legacy-auth-allowed"),
                evidence={"enabled_policy_count": len(enabled_policies)},
            )
        )

    if report_only_policies:
        names = ", ".join(p.get("displayName", "unnamed") for p in report_only_policies)
        findings.append(
            Finding(
                category=Category.IDENTITY,
                rule_id="ca-policy-report-only",
                title=f"{len(report_only_policies)} Conditional Access polic{'y is' if len(report_only_policies) == 1 else 'ies are'} stuck in report-only mode",
                description=(
                    f"The following policies are configured but not enforced (report-only): {names}. "
                    "They provide visibility but zero actual protection until turned on."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.0,
                resource_id=f"tenant/{settings.azure_tenant_id or 'unknown'}",
                resource_name="Entra ID tenant",
                resource_type="Microsoft.Graph/conditionalAccessPolicies",
                recommendation="Review report-only policies' sign-in logs for false positives, then switch them to 'On'.",
                mitre=get_mitre_mapping("ca-policy-report-only"),
                evidence={"report_only_policy_names": [p.get("displayName") for p in report_only_policies]},
            )
        )

    return findings, ScannerSummary(
        scanner=SCANNER_NAME, resources_scanned=scanned, findings_count=len(findings), errors=errors
    )
