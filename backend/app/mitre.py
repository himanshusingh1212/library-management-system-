"""Lookup table mapping a scanner rule_id to its MITRE ATT&CK tactic + technique.

Every scanner finding carries a rule_id; this module is the single place that
knows how a misconfiguration category translates into attacker tradecraft.
"""

from app.models import MitreMapping

RULE_TO_MITRE: dict[str, MitreMapping] = {
    "nsg-public-management-port": MitreMapping(
        tactic_id="TA0001",
        tactic_name="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
    ),
    "nsg-public-database-port": MitreMapping(
        tactic_id="TA0001",
        tactic_name="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
    ),
    "nsg-public-any-port": MitreMapping(
        tactic_id="TA0001",
        tactic_name="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
    ),
    "kv-purge-protection-disabled": MitreMapping(
        tactic_id="TA0040",
        tactic_name="Impact",
        technique_id="T1485",
        technique_name="Data Destruction",
    ),
    "kv-soft-delete-disabled": MitreMapping(
        tactic_id="TA0040",
        tactic_name="Impact",
        technique_id="T1485",
        technique_name="Data Destruction",
    ),
    "kv-public-network-access": MitreMapping(
        tactic_id="TA0001",
        tactic_name="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
    ),
    "storage-public-blob-access": MitreMapping(
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        technique_id="T1530",
        technique_name="Data from Cloud Storage",
    ),
    "storage-https-not-enforced": MitreMapping(
        tactic_id="TA0006",
        tactic_name="Credential Access",
        technique_id="T1557",
        technique_name="Adversary-in-the-Middle",
    ),
    "storage-weak-tls": MitreMapping(
        tactic_id="TA0006",
        tactic_name="Credential Access",
        technique_id="T1557",
        technique_name="Adversary-in-the-Middle",
    ),
    "storage-no-network-firewall": MitreMapping(
        tactic_id="TA0001",
        tactic_name="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
    ),
    "ca-no-mfa-enforced": MitreMapping(
        tactic_id="TA0006",
        tactic_name="Credential Access",
        technique_id="T1078",
        technique_name="Valid Accounts",
    ),
    "ca-no-policies": MitreMapping(
        tactic_id="TA0006",
        tactic_name="Credential Access",
        technique_id="T1078",
        technique_name="Valid Accounts",
    ),
    "ca-legacy-auth-allowed": MitreMapping(
        tactic_id="TA0006",
        tactic_name="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
    ),
    "ca-policy-report-only": MitreMapping(
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        technique_id="T1562",
        technique_name="Impair Defenses",
    ),
}


def get_mitre_mapping(rule_id: str) -> MitreMapping:
    try:
        return RULE_TO_MITRE[rule_id]
    except KeyError as exc:
        raise ValueError(f"No MITRE ATT&CK mapping registered for rule_id={rule_id!r}") from exc


# All 14 ATT&CK Enterprise tactics, used to render a full coverage grid in the
# dashboard even for tactics with zero findings.
ALL_TACTICS: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]
