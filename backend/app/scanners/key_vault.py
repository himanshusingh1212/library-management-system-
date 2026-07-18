"""Key Vault scanner: purge protection, soft delete, and default network access."""

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.keyvault import KeyVaultManagementClient

from app.config import Settings
from app.mitre import get_mitre_mapping
from app.models import Category, Finding, ScanError, ScannerSummary, Severity

SCANNER_NAME = "key_vaults"


def scan_key_vaults(
    credential: TokenCredential, subscription_id: str, settings: Settings
) -> tuple[list[Finding], ScannerSummary]:
    findings: list[Finding] = []
    errors: list[ScanError] = []
    scanned = 0

    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = list(client.vaults.list_by_subscription())
    except HttpResponseError as exc:
        errors.append(ScanError(scanner=SCANNER_NAME, message=f"Failed to list Key Vaults: {exc.message}"))
        return findings, ScannerSummary(scanner=SCANNER_NAME, resources_scanned=0, findings_count=0, errors=errors)
    except Exception as exc:  # pragma: no cover
        errors.append(ScanError(scanner=SCANNER_NAME, message=f"Unexpected error listing Key Vaults: {exc}"))
        return findings, ScannerSummary(scanner=SCANNER_NAME, resources_scanned=0, findings_count=0, errors=errors)

    for vault in vaults:
        scanned += 1
        try:
            props = client.vaults.get(vault.id.split("/")[4], vault.name).properties
        except Exception as exc:
            errors.append(
                ScanError(
                    scanner=SCANNER_NAME,
                    message=f"Could not read properties for vault '{vault.name}': {exc}",
                )
            )
            continue

        if not props.enable_purge_protection:
            findings.append(
                Finding(
                    category=Category.KEY_VAULT,
                    rule_id="kv-purge-protection-disabled",
                    title=f"Key Vault '{vault.name}' does not have purge protection enabled",
                    description=(
                        "Without purge protection, a compromised account with delete permissions "
                        "can permanently and irrecoverably delete secrets, keys, and certificates "
                        "before the retention period would otherwise allow recovery."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    resource_id=vault.id or "",
                    resource_name=vault.name or "",
                    resource_type="Microsoft.KeyVault/vaults",
                    recommendation="Enable purge protection (`enablePurgeProtection: true`). This cannot be reverted once enabled.",
                    mitre=get_mitre_mapping("kv-purge-protection-disabled"),
                    evidence={"enable_purge_protection": props.enable_purge_protection},
                )
            )

        if not props.enable_soft_delete:
            findings.append(
                Finding(
                    category=Category.KEY_VAULT,
                    rule_id="kv-soft-delete-disabled",
                    title=f"Key Vault '{vault.name}' does not have soft delete enabled",
                    description=(
                        "Soft delete is the baseline recovery mechanism for accidental or malicious "
                        "deletion of vault objects. Modern vaults have this on by default; an explicit "
                        "disable is a red flag."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=6.5,
                    resource_id=vault.id or "",
                    resource_name=vault.name or "",
                    resource_type="Microsoft.KeyVault/vaults",
                    recommendation="Enable soft delete (`enableSoftDelete: true`).",
                    mitre=get_mitre_mapping("kv-soft-delete-disabled"),
                    evidence={"enable_soft_delete": props.enable_soft_delete},
                )
            )

        network_acls = props.network_acls
        default_action = getattr(network_acls, "default_action", None) if network_acls else None
        if default_action is None or str(default_action).lower() == "allow":
            findings.append(
                Finding(
                    category=Category.KEY_VAULT,
                    rule_id="kv-public-network-access",
                    title=f"Key Vault '{vault.name}' is reachable from any network by default",
                    description=(
                        "The vault's network ACL default action is 'Allow' (or unset), meaning it "
                        "accepts requests from any public IP address rather than being restricted to "
                        "approved VNets/IP ranges or a private endpoint."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    resource_id=vault.id or "",
                    resource_name=vault.name or "",
                    resource_type="Microsoft.KeyVault/vaults",
                    recommendation=(
                        "Set the network ACL default action to 'Deny' and allow only required VNets/"
                        "IP ranges, or migrate to a private endpoint."
                    ),
                    mitre=get_mitre_mapping("kv-public-network-access"),
                    evidence={"default_action": str(default_action)},
                )
            )

    return findings, ScannerSummary(
        scanner=SCANNER_NAME, resources_scanned=scanned, findings_count=len(findings), errors=errors
    )
