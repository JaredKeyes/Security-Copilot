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

GUARDDUTY_TYPES = [
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
    "Recon:IAMUser/UserPermissions",
    "Discovery:S3/BucketEnumeration",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "Impact:EC2/MaliciousIPCaller",
]

EVENT_SOURCE_MAP = {
    "ConsoleLogin": "signin.amazonaws.com",
    "AssumeRole": "sts.amazonaws.com",
    "ListBuckets": "s3.amazonaws.com",
    "GetObject": "s3.amazonaws.com",
    "PutObject": "s3.amazonaws.com",
    "CreateAccessKey": "iam.amazonaws.com",
    "DeleteTrail": "cloudtrail.amazonaws.com",
    "StopLogging": "cloudtrail.amazonaws.com",
    "AuthorizeSecurityGroupIngress": "ec2.amazonaws.com",
    "RunInstances": "ec2.amazonaws.com",
}

def random_ip():
    if random.random() < 0.02:
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
            "event_source": EVENT_SOURCE_MAP.get(event_name, "unknown.amazonaws.com"),
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
        resource_name,
        scenario_id,
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
            "event_source": EVENT_SOURCE_MAP.get(event_name, "unknown.amazonaws.com"),
            "event_name": event_name,
            "aws_region": region,
            "source_ip_address": source_ip,
            "user_name": user_name,
            "user_type": user_type,
            "account_id": "123456789012",
            "resource_name": resource_name,
            "error_code": error_code,
        }
      )

      evaluation_labels.append(
        {
            "event_id": event_id,
            "scenario_id": scenario_id,
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
        event_time=now - timedelta(hours=2, minutes=30),
        source_ip=attacker_ip,
        user_name=compromised_user,
        user_type="IAMUser",
        region="us-east-1",
        resource_name="aws-console",
        scenario_id="scn-001",
        scenario_name="credential_compromise",
        attack_stage="initial_access",
        expected_reasoning="Successful console login from a known malicious IP.",
    )

    add_attack_event(
        event_name="ListBuckets",
        event_time=now - timedelta(hours=2, minutes=30),
        source_ip=attacker_ip,
        user_name=compromised_user,
        user_type="IAMUser",
        region="us-east-1",
        resource_name="s3",
        scenario_id="scn-001",
        scenario_name="credential_compromise",
        attack_stage="discovery",
        expected_reasoning="s3 bucket discovery shortly after suspicious login.",
    )

    add_attack_event(
        event_name="GetObject",
        event_time=now - timedelta(hours=2, minutes=15),
        source_ip=attacker_ip,
        user_name=compromised_user,
        user_type="IAMUser",
        region="us-east-1",
        resource_name="customer-data-bucket",
        scenario_id="scn-001",
        scenario_name="credential_compromise",
        attack_stage="collection",
        expected_reasoning="Access to sensitive customer data after bucket discovery.",
    )

    add_attack_event(
        event_name="CreateAccessKey",
        event_time=now - timedelta(hours=2, minutes=15),
        source_ip=attacker_ip,
        user_name=compromised_user,
        user_type="IAMUser",
        region="us-east-1",
        resource_name=compromised_user,
        scenario_id="scn-001",
        scenario_name="credential_compromise",
        attack_stage="persistence",
        expected_reasoning="Access key creation after suspicious activity may indicate persistence.",
    )

    add_attack_event(
        event_name="AssumeRole",
        event_time=now - timedelta(hours=2, minutes=10),
        source_ip=attacker_ip,
        user_name=compromised_user,
        user_type="IAMUser",
        region="us-east-1",
        resource_name="admin-role",
        scenario_id="scn-001",
        scenario_name="credential_compromise",
        attack_stage="privilege_escalation",
        expected_reasoning="Attempt to assume an admin role after suspicious login and persistence behavior.",
    )

    # Scenario 2: CloudTrail tampering
    # Pattern
    # Suspicious IP -> AssumeRole -> StopLogging -> DeleteTrail
    tampering_user = "admin.user"
    tampering_ip = "91.219.236.15"

    add_attack_event(
        event_name="AssumeRole",
        event_time=now - timedelta(hours=1, minutes=20),
        source_ip=tampering_ip,
        user_name=tampering_user,
        user_type="IAMUser",
        region="us-east-1",
        resource_name="admin-role",
        scenario_id="scn-002",
        scenario_name="cloudtrail_tampering",
        attack_stage="privilege_escalation",
        expected_reasoning="Admin role assumed from a suspicious IP.",
    )

    add_attack_event(
        event_name="StopLogging",
        event_time=now - timedelta(hours=1, minutes=15),
        source_ip=tampering_ip,
        user_name=tampering_user,
        user_type="IAMUser",
        region="us-east-1",
        resource_name="cloudtrail-main",
        scenario_id="scn-002",
        scenario_name="cloudtrail_tampering",
        attack_stage="defense_evasion",
        expected_reasoning="CloudTrail logging stopped after suspicious admin role activity.",
    )

    add_attack_event(
        event_name="DeleteTrail",
        event_time=now - timedelta(hours=1, minutes=10),
        source_ip=tampering_ip,
        user_name=tampering_user,
        user_type="IAMUser",
        region="us-east-1",
        resource_name="cloudtrail-main",
        scenario_id="scn-002",
        scenario_name="cloudtrail_tampering",
        attack_stage="defense_evasion",
        expected_reasoning="CloudTrail trail deletion attempted after logging was stopped.",
    )

    # Scenario 3: Suspicious infrastructure modification
    # Pattern:
    # Service account -> AssumeRole -> Open security group -> Launch instance
    infra_user = "svc-ci-cd"
    infra_ip = "193.32.160.12"

    add_attack_event(
        event_name="AssumeRole",
        event_time=now - timedelta(minutes=45),
        source_ip=infra_ip,
        user_name=infra_user,
        user_type="ServiceAccount",
        region="us-west-2",
        resource_name="deployment-role",
        scenario_id="scn-003",
        scenario_name="suspicious_infrastructure_change",
        attack_stage="privilege_escalation",
        expected_reasoning="Service account assumed a deployment role from a susicious IP.",
    )

    add_attack_event(
        event_name="AuthorizeSecurityGroupIngress",
        event_time=now - timedelta(minutes=40),
        source_ip=infra_ip,
        user_name=infra_user,
        user_type="ServiceAccount",
        region="us-west-2",
        resource_name="security-group-prod",
        scenario_id="scn-003",
        scenario_name="suspicious_infrastructure_change",
        attack_stage="network_exposure",
        expected_reasoning="Security group ingress was modified after suspicious service account activity.",
    )

    add_attack_event(
        event_name="RunInstances",
        event_time=now - timedelta(minutes=35),
        source_ip=infra_ip,
        user_name=infra_user,
        user_type="ServiceAccount",
        region="us-west-2",
        resource_name="web-prod-instance",
        scenario_id="scn-003"
        scenario_name="suspicious_infrastructure_change",
        attack_stage="execution",
        expected_reasoning="New compute instance launched after network exposure.",
    )

    return attack_events, evaluation_labels

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

def generate_seeded_guardduty_findings(attack_events):
    findings = []

    key_events = [
        event for event in attack_events
        if event["event_name"] in [
            "CreateAccessKey",
            "DeleteTrail",
            "AuthorizeSecurityGroupIngress",
        ]
    ]

    finding_map = {
        "CreateAccessKey": {
            "finding_type": "UnauthorizedAccess:IAMUser/"
        }
    }
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
    attack_events, evaluation_labels = generate_seeded_attack_scenarios()

    cloudtrail_events.extend(attack_events)

    guardduty_findings = generate_guardduty_findings(cloudtrail_events)
    iam_users = generate_iam_users()
    threat_intel = generate_threat_intel()

    with open(RAW_DIR / "cloudtrail_events.json", "w") as f:
        json.dump(cloudtrail_events, f, indent=2)

    with open(RAW_DIR / "guardduty_findings.json", "w") as f:
        json.dump(guardduty_findings, f, indent=2)

    with open(RAW_DIR / "evaluation_labels.json", "w") as f:
        json.dump(evaluation_labels, f, indent=2)

    iam_users.to_csv(RAW_DIR / "iam_users.csv", index=False)
    threat_intel.to_csv(RAW_DIR / "threat_intel.csv", index=False)

    print("Synthetic security data generated:")
    print(f"- {RAW_DIR / 'cloudtrail_events.json'}")
    print(f"- {RAW_DIR / 'guardduty_findings.json'}")
    print(f"- {RAW_DIR / 'iam_users.csv'}")
    print(f"- {RAW_DIR / 'threat_intel.csv'}")
    print(f"- {RAW_DIR / 'evaluation_labels.json'}")

if __name__ == "__main__":
    main()