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

def main():
    cloudtrail_events = generate_cloudtrail_events()
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