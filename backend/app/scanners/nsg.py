"""Network scanner: flags NSG inbound rules that expose sensitive ports to the internet."""

import logging

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.network import NetworkManagementClient

from app.config import Settings
from app.mitre import get_mitre_mapping
from app.models import Category, Finding, ScanError, ScannerSummary, Severity

logger = logging.getLogger(__name__)

SCANNER_NAME = "network_security_groups"

PUBLIC_SOURCES = {"internet", "*", "0.0.0.0/0", "any"}
MANAGEMENT_PORTS = {"22", "3389"}


def _is_public_source(address_prefix: str | None, address_prefixes: list[str] | None) -> bool:
    candidates = []
    if address_prefix:
        candidates.append(address_prefix)
    if address_prefixes:
        candidates.extend(address_prefixes)
    return any(c.lower() in PUBLIC_SOURCES for c in candidates)


def _ports_from_rule(rule) -> list[str]:
    if rule.destination_port_range:
        return [rule.destination_port_range]
    return rule.destination_port_ranges or []


def _classify_ports(ports: list[str], sensitive_ports: set[str]) -> tuple[str, str] | None:
    """Returns (rule_id, title-suffix) for the worst finding this rule set triggers, or None."""
    for port in ports:
        if port == "*":
            return "nsg-public-any-port", "any port"
    hit_mgmt = {p for p in ports if p in MANAGEMENT_PORTS}
    if hit_mgmt:
        return "nsg-public-management-port", f"management port(s) {', '.join(sorted(hit_mgmt))}"
    hit_db = {p for p in ports if p in sensitive_ports and p not in MANAGEMENT_PORTS}
    if hit_db:
        return "nsg-public-database-port", f"database port(s) {', '.join(sorted(hit_db))}"
    return None


def scan_network_security_groups(
    credential: TokenCredential, subscription_id: str, settings: Settings
) -> tuple[list[Finding], ScannerSummary]:
    findings: list[Finding] = []
    errors: list[ScanError] = []
    scanned = 0
    sensitive_ports = set(settings.sensitive_ports)

    try:
        client = NetworkManagementClient(credential, subscription_id)
        nsgs = list(client.network_security_groups.list_all())
    except HttpResponseError as exc:
        errors.append(ScanError(scanner=SCANNER_NAME, message=f"Failed to list NSGs: {exc.message}"))
        return findings, ScannerSummary(
            scanner=SCANNER_NAME, resources_scanned=0, findings_count=0, errors=errors
        )
    except Exception as exc:  # pragma: no cover - defensive, scanner failure must not crash the run
        errors.append(ScanError(scanner=SCANNER_NAME, message=f"Unexpected error listing NSGs: {exc}"))
        return findings, ScannerSummary(
            scanner=SCANNER_NAME, resources_scanned=0, findings_count=0, errors=errors
        )

    for nsg in nsgs:
        scanned += 1
        for rule in nsg.security_rules or []:
            if rule.direction != "Inbound" or rule.access != "Allow":
                continue
            if not _is_public_source(rule.source_address_prefix, rule.source_address_prefixes):
                continue

            ports = _ports_from_rule(rule)
            classification = _classify_ports(ports, sensitive_ports)
            if not classification:
                continue
            rule_id, port_desc = classification

            severity = Severity.CRITICAL if rule_id == "nsg-public-any-port" else Severity.HIGH
            cvss = 9.8 if severity == Severity.CRITICAL else 8.6

            findings.append(
                Finding(
                    category=Category.NETWORK,
                    rule_id=rule_id,
                    title=f"NSG '{nsg.name}' allows public inbound access to {port_desc}",
                    description=(
                        f"Security rule '{rule.name}' on NSG '{nsg.name}' permits inbound traffic "
                        f"from the public internet ({rule.source_address_prefix or rule.source_address_prefixes}) "
                        f"to {port_desc}. This exposes the resource directly to internet-wide scanning "
                        f"and brute-force/exploit attempts."
                    ),
                    severity=severity,
                    cvss_score=cvss,
                    resource_id=nsg.id or "",
                    resource_name=nsg.name or "",
                    resource_type="Microsoft.Network/networkSecurityGroups",
                    recommendation=(
                        "Restrict the source address prefix to known IP ranges (e.g. a VPN or "
                        "bastion subnet), or remove the rule entirely and use Azure Bastion / "
                        "Just-In-Time VM access for administrative connectivity."
                    ),
                    mitre=get_mitre_mapping(rule_id),
                    evidence={
                        "rule_name": rule.name,
                        "source": rule.source_address_prefix or rule.source_address_prefixes,
                        "ports": ports,
                        "priority": rule.priority,
                    },
                )
            )

    return findings, ScannerSummary(
        scanner=SCANNER_NAME, resources_scanned=scanned, findings_count=len(findings), errors=errors
    )
