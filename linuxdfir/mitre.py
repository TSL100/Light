"""Static MITRE ATT&CK reference data (offline, no external requests)."""

TACTIC_ORDER = [
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

TECHNIQUES = {
    "T1110": {"name": "Brute Force", "tactics": ["TA0006"]},
    "T1110.001": {"name": "Password Guessing", "tactics": ["TA0006"]},
    "T1110.003": {"name": "Password Spraying", "tactics": ["TA0006"]},
    "T1078": {"name": "Valid Accounts", "tactics": ["TA0003", "TA0004", "TA0005", "TA0001"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["TA0002"]},
    "T1105": {"name": "Ingress Tool Transfer", "tactics": ["TA0011"]},
    "T1053": {"name": "Scheduled Task/Job", "tactics": ["TA0003", "TA0004"]},
    "T1053.003": {"name": "Cron", "tactics": ["TA0003", "TA0004"]},
    "T1543": {"name": "Create or Modify System Process", "tactics": ["TA0003", "TA0004"]},
    "T1543.002": {"name": "Systemd Service", "tactics": ["TA0003", "TA0004"]},
    "T1136": {"name": "Create Account", "tactics": ["TA0003"]},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactics": ["TA0004", "TA0005"]},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactics": ["TA0004", "TA0005"]},
    "T1098": {"name": "Account Manipulation", "tactics": ["TA0003"]},
    "T1098.004": {"name": "SSH Authorized Keys", "tactics": ["TA0003"]},
    "T1021": {"name": "Remote Services", "tactics": ["TA0008"]},
    "T1021.004": {"name": "SSH", "tactics": ["TA0008"]},
    "T1070": {"name": "Indicator Removal", "tactics": ["TA0005"]},
    "T1070.002": {"name": "Clear Linux or Mac System Logs", "tactics": ["TA0005"]},
    "T1070.003": {"name": "Clear Command History", "tactics": ["TA0005"]},
    "T1070.006": {"name": "Timestomp", "tactics": ["TA0005"]},
    "T1562": {"name": "Impair Defenses", "tactics": ["TA0005"]},
    "T1562.001": {"name": "Disable or Modify Tools", "tactics": ["TA0005"]},
    "T1562.006": {"name": "Indicator Blocking", "tactics": ["TA0005"]},
    "T1574": {"name": "Hijack Execution Flow", "tactics": ["TA0003", "TA0004", "TA0005"]},
    "T1574.006": {"name": "Dynamic Linker Hijacking", "tactics": ["TA0003", "TA0004", "TA0005"]},
    "T1505": {"name": "Server Software Component", "tactics": ["TA0003"]},
    "T1505.003": {"name": "Web Shell", "tactics": ["TA0003"]},
    "T1546": {"name": "Event Triggered Execution", "tactics": ["TA0003", "TA0004"]},
    "T1546.004": {"name": "Unix Shell Configuration Modification", "tactics": ["TA0003", "TA0004"]},
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, {}).get("name", "Unknown technique")


def tactics_for(technique_id: str) -> list[str]:
    return list(TECHNIQUES.get(technique_id, {}).get("tactics", []))


def tactic_name(tactic_id: str) -> str:
    for known_id, name in TACTIC_ORDER:
        if known_id == tactic_id:
            return name
    return tactic_id
