import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from faker import Faker

fake = Faker()

RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)

USERS = [
    "jsmith",
    "adoe",
    "mgarcia",
    "tnguyen",
    "rpatel",
    "admin.user",
    "svc-backup",
    "svc-ci-cd",
]

EVENT_NAMES = [
    "ConsoleLogin",
    "AssumeRole",
    "ListBuckets",
    "GetObject",
    "PutObject",
    "CreateAccessKey",
    "DeleteTrail",
    "AuthorizeSecurityGroupIngress",
    "RunInstances",
    "StopLogging",
]

SENSITIVE_EVENTS = {
    "CreateAccessKey",
    "DeleteTrail",
    "AuthorizeSecurityGroupIngress",
    "StopLogging",
    "AssumeRole",
}

GUARDDUTY_TYPES = [
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
    "Recon:IAMUser/UserPermissions",
    "Discovery:S3/BucketEnumeration",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "Impact:EC2/MaliciousIPCaller",
]

MITRE_MAP = {
    "ConsoleLogin": "T1078 - Valid Accounts",
    "AssumeRole": "T1078 - Valid Accounts",
    "ListBuckets": "T1619 - Cloud Storage Object Discovery",
    "GetObject": "T1530 - Data from Cloud Storage",
    "PutObject": "T1105 - Ingress Tool Transfer",
    "CreateAccessKey": "T1098 - Account Manipulation",
    "DeleteTrail": "T1562.008 - Disable Cloud Logs",
    "AuthorizeSecurityGroupIngress": "T1578 - Modify Cloud Compute Infrastructure",
    "StopLogging": "T1562.008 - Disable Cloud Logs",
}

def random_ip():
    if random.random() < 0.15:
        return random.choice(
            [
                "45.155.205.233",
                "185.220.101.42",
                "91.219.236.15",
                "193.32.160.12",
            ]
        )

    return fake.ipv4_public()

def generate_cloudtrail_events(num_events: int = 500):
    now = datetime.now(timezone.utc)
    events = []

    for i in range(num_events):
        event_name = random.choice(EVENT_NAMES)
        user = random.choice(USERS)
        source_ip = random_ip()
        event_time = now - timedelta(minutes=random.randint(1, 60 * 24 * 14))

        event = {
            "event_id": f"evt-{i + 1:05d}",
            "event_time": event_time.isoformat(),
            "event_source": "aws.amazonaws.com",
            "event_name": event_name,
            "aws_region": random.choice(["us-east-1", "us-east-2", "us-west-2"]),
            "source_ip_address": source_ip,
            "user_name": user,
            "user_type": "IAMUser" if not user.startswith("svc-") else "ServiceAccount",
            "account_id": "123456789012",
            "resource_name": random.choice(
                [
                    "prod-app-bucket",
                    "customer-data-bucket",
                    "admin-role",
                    "web-prod-instance",
                    "cloudtrail-main",
                    "security-group-prod",
                ]
            ),
            "error_code": random.choice([None, None, None, "AccessDenied"]),
            "mitre_technique": MITRE_MAP.get(event_name, "Unknown"),
            "is_sensitive_event": event_name in SENSITIVE_EVENTS,
        }

        events.append(event)
        
    return events

def generate_seeded_attack_scenarios(start_index: int = 10000):
    """
    Generate  deterministic attack chains so the AI/agent has clear patterns to investigate.

    Returns:
        attack_events: CloudTrail-style events visible to the AI.
        evaluation_labels: Hidden labels used later for evaluation only.
    """
    now = datetime.now(timezone.utc)

    attack_events = []
    evaluation_labels = []

    def add_attack_event(
        event_name,
        event_time,
        source_ip,
        user_name,
        user_type,
        region,
        region_name,
        scenario_name,
        attack_stage,
        expected_reasoning,
        error_code=None,
    ):
      event_id = f"evt-{start_index + len(attack_events):05d}"

      attack_events.append(
        {
            "event_id": event_id,
            "event_time": event_time.isoformat(),
            "event_source": "aws.amazonaws.com",
            "event_name": event_name,
            "aws_region": region,
            "source_ip_address": source_ip,
            "user_name": user_name,
            "user_type": user_type,
            "account_id": "123456789012"
            "resource_name": resource_name,
            "error_code": error_code,
            "mitre_technique": MITRE_MAP.get(event_name, "Unknown"),
            "is_sensitive_event": event_name in SENSITIVE_EVENTS,
        }
      )

      evaluation_labels.append(
        {
            "event_id": event_id,
            "scenario_name": scenario_name,
            "attack_stage": attack_stage,
            "expected_detection": True,
            "expected_reasoning": expected_reasoning,
        }
      )

    # Scenario 1: Credential compromise
    # Pattern:
    # New/suspicious IP -> ConsoleLogin -> ListBuckets -> GetObject -> CreateAccessKey -> AssumeRole
    compromised_user = "jsmith"
    attacker_ip = "45.155.205.233"

    add_attack_event(
        event_name="ConsoleLogin",
        event_time=now - timedelta(hours=2, minutes=30)
    )

    credential_compromise_steps = [
        ("ConsoleLogin", "Successful login from known malicious IP"),
        ("ListBuckets", "Reconnaissance of available S3 buckets"),
        ("GetObject", "Access to sensitive customer data"),
        ("CreateAccessKey", "Persistence attempt through new access key"),
        ("AssumeRole", "Privilege escalation attempt into admin role"),
    ]

    for offset, (event_name, description) in enumerate(credential_compromise_steps):
        scenarios.append(
            {
                "event_id": f"evt-{start_index + len(scenarios):05d}",
                "event_time": (now - timedelta(hours=2, minutes=30 - offset * 5)).isoformat(),
                "event_source": "aws.amazonaws.com",
                "event_name": event_name,
                "aws_region": "us-east-1",
                "source_ip_address": attacker_ip,
                "user_name": compromised_user,
                "user_type": "IAMUser",
                "account_id": "123456789012"
                "resource_name": "customer-data-bucket" if event_name in ["ListBuckets", "GetObject"] else "admin-role",
                "error_code": None,
                "mitre_technique": MITRE_MAP.get(event_name, "Unknown"),
                "is_sensitive_event": event_name in SENSITIVE_EVENTS,
                "scenario_description": description,
            }
        )

    # Scenario 2: CloudTrail tampering
    tampering_user = "admin.user"
    tampering_ip = "91.219.236.15"

    cloudtrail_tampering_steps = [
        ("AssumeRole", "Admin role assumed from suspicious IP"),
        ("StopLogging", "CloudTrail logging stopped"),
        ("DeleteTrail", "CloudTrail trail deletion attempted"),
    ]

    for offset, (event_name, description) in enumerate(cloudtrail_tampering_steps):
        scenarios.append(
            {
                "event_id": f"evt-{start_index + len(scenarios):05d}",
                "event_time": (now - timedelta(hours=1, minutes=20 - offset *5)).isoformat(),
                "event_source": "aws.amazonaws.com",
                "event_name": event_name,
                "aws_region": "us-east-1",
                "source_ip_address": tampering_ip,
                "user_name": tampering_user,
                "user_type": "IAMUser",
                "account_id": "123456789012",
                "resource_name": "cloudtrail-main",
                "error_code": None,
                "mitre_technique": MITRE_MAP.get(event_name, "Unknown"),
                "is_sensitive_event": event_name in SENSITIVE_EVENTS,
                "scenario_name": "cloudtrail_tampering",
                "scenario_description": description,
            }
        )

    # Scenario 3: Suspicious infrastrucutre modification
    infra_user = "svc-ci-cd"
    infra_ip = "193.32.160.12"

    infrastrucutre_abuse_steps = [
        ("AssumeRole", "Service account assumed deployment role"),
        ("AuthorizeSecurityGroupIngress", "Security group opened to external traffic"),
        ("RunInstances", "New EC2 instance launched after network exposure"),
    ]

    for offset, (event_name, description) in enumerate(infrastructure_abuse_steps):
        scenarios.append(
            {
                "event_id": f"evt-(start_index + len(scenarios):05d)",
                "event_time": (now -timedelta(minutes=45 - offset * 5)).isoformat(),
                "event_source": "aws.amazonaws.com",
                "event_name": event_name,
                "aws_region": "us-west-2"
                "source_ip_address": infra_ip,
                "user_name": infra_user,
                "user_type": "ServiceAccount",
                "account_id": "123456789012",
                "resource_name": "security-group-prod" if event_name == "AuthorizeSecurityGroupIngress" else "web-prod-instance",
                "error_code": None,
                "mitre_technique": MITRE_MAP.get(event_name, "Unknown"),
                "is_sensitive_event": event_name in SENSITIVE_EVENTS,
                "scenario_name": "suspicious_infrastructure_change",
                "scenario_description": description, 
            }
        )

    return scenarios

def generate_guardduty_findings(cloudtrail_events, num_findings: int = 40):
    suspicious_events = [
        event
        for event in cloudtrail_events
        if event["is_sensitive_event"] or event["source_ip_address"].startswith(("45.", "185.", "91.", "193."))
    ]

    findings = []

    for i, event in enumerate(random.sample(suspicious_events, min(num_findings, len(suspicious_events)))):
        severity = random.choice([4.0, 5.0, 6.5, 7.2, 8.5])

        finding = {
            "finding_id": f"gd-{i + 1:04d}",
            "related_event_id": event["event_id"],
            "finding_type": random.choice(GUARDDUTY_TYPES),
            "severity": severity,
            "title": f"Suspicious activity involoving {event['user_name']}",
            "description": f"GuardDuty detected suspicious {event['event_name']} activity from {event['source_ip_address']}.",
            "user_name": event["user_name"],
            "source_ip_address": event["source_ip_address"],
            "resource_name": event["resource_name"],
            "created_at": event["event_time"],
            "account_id": event["account_id"],
            "region": event["aws_region"],
        }

        findings.append(finding)

    return findings

def generate_iam_users():
    rows = []

    for user in USERS:
        rows.append(
            {
                "user_name": user,
                "department": random.choice(["Engineering", "Security", "Finance", "IT", "DevOps"]),
                "mfa_enabled": random.choice([True, True, True, False]),
                "privilege_level": "high" if user in ["admin.user", "svc-ci-cd"] else random.choice(["low", "medium"]),
                "active_access_keys": random.randint(0, 2),
                "last_password_change_days": random.randint(1, 180),
            }
        )
    
    return pd.DataFrame(rows)

def generate_threat_intel():
    rows = [
        {
            "ip_address": "45.155.205.233",
            "threat_type": "Known botnet infrastructure",
            "confidence": "high",
        },
        {
            "ip_address": "185.220.101.42",
            "threat_type": "Tor exit node",
            "confidence": "medium",
        },
        {
            "ip_address": "91.219.236.15",
            "threat_type": "Credential stuffing source",
            "confidence": "high",
        },
        {
            "ip_address": "193.32.160.12",
            "threat_type": "Suspicious scanner",
            "confidence": "medium",
        },
    ]

    return pd.DataFrame(rows)

def main():
    cloudtrail_events = generate_cloudtrail_events()
    seeded_attack_events = generate_seeded_attack_scenarios()
    cloudtrail_events.extend(seeded_attack_events)
    guardduty_findings = generate_guardduty_findings(cloudtrail_events)
    iam_users = generate_iam_users()
    threat_intel = generate_threat_intel()

    with open(RAW_DIR / "cloudtrail_events.json", "w") as f:
        json.dump(cloudtrail_events, f, indent=2)

    with open(RAW_DIR / "guardduty_findings.json", "w") as f:
        json.dump(guardduty_findings, f, indent=2)

    iam_users.to_csv(RAW_DIR / "iam_users.csv", index=False)
    threat_intel.to_csv(RAW_DIR / "threat_intel.csv", index=False)

    print("Synthetic security data generated:")
    print(f"- {RAW_DIR / 'cloudtrail_events.json'}")
    print(f"- {RAW_DIR / 'guardduty_findings.json'}")
    print(f"- {RAW_DIR / 'iam_users.csv'}")
    print(f"- {RAW_DIR / 'threat_intel.csv'}")

if __name__ == "__main__":
    main()