"""Storage scanner: public blob access, HTTPS enforcement, TLS version, network firewall."""

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.storage import StorageManagementClient

from app.config import Settings
from app.mitre import get_mitre_mapping
from app.models import Category, Finding, ScanError, ScannerSummary, Severity

SCANNER_NAME = "storage_accounts"

WEAK_TLS_VERSIONS = {"TLS1_0", "TLS1_1"}


def scan_storage_accounts(
    credential: TokenCredential, subscription_id: str, settings: Settings
) -> tuple[list[Finding], ScannerSummary]:
    findings: list[Finding] = []
    errors: list[ScanError] = []
    scanned = 0

    try:
        client = StorageManagementClient(credential, subscription_id)
        accounts = list(client.storage_accounts.list())
    except HttpResponseError as exc:
        errors.append(ScanError(scanner=SCANNER_NAME, message=f"Failed to list storage accounts: {exc.message}"))
        return findings, ScannerSummary(scanner=SCANNER_NAME, resources_scanned=0, findings_count=0, errors=errors)
    except Exception as exc:  # pragma: no cover
        errors.append(ScanError(scanner=SCANNER_NAME, message=f"Unexpected error listing storage accounts: {exc}"))
        return findings, ScannerSummary(scanner=SCANNER_NAME, resources_scanned=0, findings_count=0, errors=errors)

    for account in accounts:
        scanned += 1

        if account.allow_blob_public_access:
            findings.append(
                Finding(
                    category=Category.STORAGE,
                    rule_id="storage-public-blob-access",
                    title=f"Storage account '{account.name}' allows public blob access",
                    description=(
                        "Public blob access is enabled at the account level, meaning any container "
                        "or blob explicitly marked public is reachable anonymously over the internet. "
                        "This is one of the most common causes of real-world Azure data breaches."
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    resource_id=account.id or "",
                    resource_name=account.name or "",
                    resource_type="Microsoft.Storage/storageAccounts",
                    recommendation="Set `allowBlobPublicAccess: false` at the account level and use SAS tokens or private endpoints for controlled access.",
                    mitre=get_mitre_mapping("storage-public-blob-access"),
                    evidence={"allow_blob_public_access": account.allow_blob_public_access},
                )
            )

        if not account.enable_https_traffic_only:
            findings.append(
                Finding(
                    category=Category.STORAGE,
                    rule_id="storage-https-not-enforced",
                    title=f"Storage account '{account.name}' does not enforce HTTPS-only traffic",
                    description=(
                        "Plain HTTP is permitted, allowing data (including SAS tokens and account "
                        "keys sent as query parameters) to be intercepted in transit."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    resource_id=account.id or "",
                    resource_name=account.name or "",
                    resource_type="Microsoft.Storage/storageAccounts",
                    recommendation="Set `supportsHttpsTrafficOnly: true`.",
                    mitre=get_mitre_mapping("storage-https-not-enforced"),
                    evidence={"enable_https_traffic_only": account.enable_https_traffic_only},
                )
            )

        min_tls = str(account.minimum_tls_version) if account.minimum_tls_version else None
        if min_tls and any(weak in min_tls for weak in WEAK_TLS_VERSIONS):
            findings.append(
                Finding(
                    category=Category.STORAGE,
                    rule_id="storage-weak-tls",
                    title=f"Storage account '{account.name}' permits a weak minimum TLS version ({min_tls})",
                    description=(
                        "TLS 1.0/1.1 have known cryptographic weaknesses and are deprecated. "
                        "Allowing them widens the window for downgrade and interception attacks."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.9,
                    resource_id=account.id or "",
                    resource_name=account.name or "",
                    resource_type="Microsoft.Storage/storageAccounts",
                    recommendation="Set `minimumTlsVersion: TLS1_2`.",
                    mitre=get_mitre_mapping("storage-weak-tls"),
                    evidence={"minimum_tls_version": min_tls},
                )
            )

        network_rule_set = account.network_rule_set
        default_action = getattr(network_rule_set, "default_action", None) if network_rule_set else None
        if default_action is None or str(default_action).lower() == "allow":
            findings.append(
                Finding(
                    category=Category.STORAGE,
                    rule_id="storage-no-network-firewall",
                    title=f"Storage account '{account.name}' has no network firewall restricting access",
                    description=(
                        "The account's network rule set default action is 'Allow' (or unset), so it "
                        "accepts requests from any public IP rather than being scoped to approved "
                        "VNets/IP ranges."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=6.1,
                    resource_id=account.id or "",
                    resource_name=account.name or "",
                    resource_type="Microsoft.Storage/storageAccounts",
                    recommendation="Set the network rule set default action to 'Deny' and allowlist only required VNets/IP ranges, or use private endpoints.",
                    mitre=get_mitre_mapping("storage-no-network-firewall"),
                    evidence={"default_action": str(default_action)},
                )
            )

    return findings, ScannerSummary(
        scanner=SCANNER_NAME, resources_scanned=scanned, findings_count=len(findings), errors=errors
    )
