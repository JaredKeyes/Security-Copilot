import os

from src.guardrails.security_guardrails import check_citation_coverage, groundedness_score

FABRICATED_IP = "203.0.113.99"

GOOD_REPORT = (
    "Investigation Report for gd-seeded-0001. ConsoleLogin from 198.51.100.7, "
    "followed by ListBuckets and CreateAccessKey. Likely credential compromise."
)
GOOD_CONTEXT = {
    "alert": {"finding_id": "gd-seeded-0001", "source_ip_address": "198.51.100.7"},
}

def print_result(name, passed):
    print(f"{name}: {'PASS' if passed else 'FAIL'}")

def test_regression_catches_injected_fabrication():
    before = check_citation_coverage(GOOD_REPORT, GOOD_CONTEXT)
    before_score = groundedness_score(GOOD_REPORT, GOOD_CONTEXT)

    poisoned = GOOD_REPORT + f" Traffic also originated from {FABRICATED_IP}."
    after = check_citation_coverage(poisoned, GOOD_CONTEXT)
    after_score = groundedness_score(poisoned, GOOD_CONTEXT)

    print("\n=== Regression: inject fabricated IP ===")
    print(f"BEFORE: passed={before['passed']} groundedness={before_score}")
    print(f"After : passed={after['passed']} groundedness={after_score} "
            f"missing={after['missing_entities']}")

    return (
        before["passed"] is True
        and before_score == 1.0
        and after["passed"] is False
        and FABRICATED_IP in after["missing_entities"]
        and after_score < before_score
    )

def test_regression_on_served_artifact():
    if not os.environ.get("REPORTS_BUCKET"):
        print("SKIP: REPORTS_BUCKET not set")
        return True
    from src.evaluation.served_artifacts import load_served_artifact
    art = load_served_artifact("gd-seeded-0001")
    if art is None:
        print("SKIP: artifact not precomputed")
        return True
    clean = groundedness_score(art["report"], art["context"])
    poisoned = art["report"] + f" Also from {FABRICATED_IP}."
    return (
        check_citation_coverage(poisoned, art["context"])["passed"] is False
        and groundedness_score(poisoned, art["context"]) < clean
    )

def main():
    tests = [
        ("Regression catches injected fabrication", test_regression_catches_injected_fabrication),
        ("Regreesion on served artifact (S3-gated)", test_regression_on_served_artifact),
    ]
    passed = 0
    for name, fn in tests:
        ok = fn()
        print_result(name, ok)
        passed += 1 if ok else 0
    print("\n" + "=" * 100)
    print(f"Regression-demo validation score: {passed}/{len(tests)}")

if __name__ == "__main__":
    main()