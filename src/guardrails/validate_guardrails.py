from src.guardrails.security_guardrails import (
    apply_guardrails,
    detect_destructive_actions,
    detect_secret_patterns,
    mask_secrets,
    require_human_approval,
    check_citation_coverage,
    extract_report_entities,
)

def print_result(name: str, passed: bool):
    status = "PASS" if passed else "FAIL"
    print(f"{name}: {status}")

def test_secret_masking():
    text = """
    User created an access key: AKIA1234567890ABCDEF
    aws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890
    password=SuperSecret123
    Authorization: Bearer abc.def.ghi
    """

    masked = mask_secrets(text)
    remaining = detect_secret_patterns(masked)

    print("\n=== Secret Masking Test ===")
    print(masked)

    return len(remaining) == 0

def test_destructive_action_detection():
    text = "Delete the user immediately and terminate the EC2 instance."

    matches = detect_destructive_actions(text)

    print("\n=== Destructive Action Detection Test ===")
    print(matches)

    return len(matches) >= 2

def test_human_approval_failure():
    text = "Disable the access key and isolate the instance."

    result = require_human_approval(text)

    print("\n=== Human Approval Failure Test ===")
    print(result)

    return result["passed"] is False

def test_human_approval_pass():
    text = "Disable the access key after analyst confirmation and isolate the instance with approval."

    result = require_human_approval(text)

    print("\n=== Human Approval Pass Test ===")
    print(result)

    return result["passed"] is True

def test_full_guardrail_review_required():
    report = """
    This user is definitely compromised.
    Delete the user immediately.
    Access key: AKIA1234567890ABCDEF
    """

    context = {
        "runbook_context": [],
    }

    result = apply_guardrails(report, context)

    print("\n=== Full Guardrail Review Required Test ===")
    print(result)

    return result["passed"] is False and result["status"] == "REVIEW_REQUIRED"

def test_full_guardrail_pass():
    report = """
    This activity may indicate credential compromise based on the observer timeline.

    Recommended Next Steps:
    - Review and disable suspicious credentials after analyst confirmation.
    - Preserve CloudTrail and GuardDuty evidence.
    - Escalate to incident response if unauthorized access is confirmed.
    """

    context = {
        "runbook_context": [
            {
                "metadata": {
                    "file_name": "aws_credential_compromise.md",
                    "chunk_index": 0,
                }
            }
        ],
    }

    result = apply_guardrails(report, context)

    print("\n=== Full Guardrail Pass Test ===")
    print(result)

    return result["passed"] is True and result["status"] == "PASS"

def test_entity_extraction():
    report = "IP 10.0.0.5, finding gd-seeded-0042, users svc-ci-cd and admin.user."
    entities = extract_report_entities(report)
    print("\n=== Entity Extraction ===")
    print(entities)
    return (
        "10.0.0.5" in entities["ips"]
        and "gd-seeded-0042" in entities["finding_ids"]
        and "svc-ci-cd" in entities["user_names"]
        and "admin.user" in entities["user_names"]
    )

def test_citation_coverage_pass():
    report = "Finding gd-seeded-0001 involved source IP 198.51.100.7 and user jsmith."
    context = {
        "alert": {
            "finding_id": "gd-seeded-0001",
            "source_ip_address": "198.51.100.7",
            "user_name": "jsmith",
        }
    }
    result = check_citation_coverage(report, context)
    print("\n=== Citation Coverage Pass ===")
    print(result)
    return result["passed"] is True and result["coverage_ratio"] == 1.0

def test_citation_coverage_fabricated_ip():
    report = "The attacker pivoted from 203.0.113.99 against gd-seeded-0001."
    context = {"alert": {"finding_id": "gd-seeded-0001", "source_ip_address": "198.51.100.7"}}
    result = check_citation_coverage(report, context)
    print("\n=== Citation Coverage Fabricated IP ===")
    print(result)
    return (
        result["passed"] is False
        and "203.0.113.99" in result["missing_entities"]
        and result["coverage_ratio"] < 1.0
    )

def main():
    tests = [
        ("Secret masking", test_secret_masking),
        ("Destructive action detection", test_destructive_action_detection),
        ("Human approval failure", test_human_approval_failure),
        ("Human approval pass", test_human_approval_pass),
        ("Full guardrail review required", test_full_guardrail_review_required),
        ("Full guardrail pass", test_full_guardrail_pass),
        ("Entity extraction", test_entity_extraction),
        ("Citation coverage pass", test_citation_coverage_pass),
        ("Citation coverage fabricated IP", test_citation_coverage_fabricated_ip),
    ]

    passed = 0

    for name, test_func in tests:
        result = test_func()
        print_result(name, result)

        if result:
            passed += 1

    print("\n" + "=" * 100)
    print(f"Guardrail validation score: {passed}/{len(tests)}")

if __name__ == "__main__":
    main()