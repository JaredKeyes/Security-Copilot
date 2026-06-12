EVALUATION_TEST_CASES = [
    {
        "finding_id": "gd-seeded-0001",
        "expected_scenario": "credential_compromise",
        "expected_pattern_keywords": [
            "credential compromise",
            "discovery",
            "data access",
            "persistence",
            "privilege escalation",
        ],
        "expected_event_names": [
            "ConsoleLogin",
            "ListBuckets",
            "GetObject",
            "CreateAccessKey",
            "AssumeRole",
        ],
        "expected_runbook": "aws_credential_compromise.md",
    },
    {
        "finding_id": "gd-seeded-0002",
        "expected_scenario": "cloudtrail_tamering",
        "expected_pattern_keywords": [
            "CloudTrail",
            "tampering",
            "defense evasion",
            "logging",
        ],
        "expected_event_names": [
            "AssumeRole",
            "StopLogging",
            "DeleteTrail",
        ],
        "expected_runbook": "cloudtrail_tampering.md",
    },
    {
        "finding_id": "gd-seeded-0003",
        "expected_scenario": "suspicious_infrastructure_change",
        "expected_pattern_keywords": [
            "service account",
            "infrastructure",
            "security group",
            "EC2",
        ],
        "expected_event_names": [
            "AssumeRole",
            "AuthorizeSecurityGroupIngress",
            "RunInstances",
        ],
        "expected_runbook": "suspicious_Security_group_change.md",
    },
]