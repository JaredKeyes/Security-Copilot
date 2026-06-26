import os

from src.evaluation.llm_judge import judge_passed, judge_report

def print_result(name, passed):
    print(f"{name}: {'PASS' if passed else 'FAIL'}")

def test_judge_passed_threshold():
    assert judge_passed({"faithfulness": 4, "correctness": 4, "completeness": 1}) is True
    assert judge_passed({"faithfulness": 3, "correctness": 5, "completeness": 5}) is False
    assert judge_passed({"faithfulness": 5, "correctness": 3, "completeness": 5}) is False
    return True

def test_judge_live():
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_SECRET_ARN")):
        print("SKIP: no Anthropic credentials in env")
        return True
    report = "Finding gd-seeded-0001 shows ConsoleLogin from 198.51.100.7 then ListBuckets; likely credential compromise."
    context = {"alerts": {"finding_id": "gd-seeded-0001", "source_ip_address": "198.51.100.7"}}
    label = {"scenario_name": "credential_compromise",
            "expected_reasoning": ["Successful console login from a known malicious IP."]}
    scores = judge_report(report, context, label)
    print("\n=== Live Judge ===")
    print(scores)
    for dim in ("faithfulness", "correctness", "completeness"):
        if not (1 <= scores[dim] <= 5):
            return False
    return "passed" in scores

def main():
    tests = [
        ("Judge pass threshold", test_judge_passed_threshold),
        ("Judge live (creds-gated)", test_judge_live),
    ]
    passed = 0
    for name, fn in tests:
        ok = fn()
        print_result(name, ok)
        passed += 1 if ok else 0
    print("\n" + "=" * 100)
    print(f"LLM-judge validation score: {passed}/{len(tests)}")

if __name__ == "__main__":
    main()