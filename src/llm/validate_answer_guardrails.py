from src.llm.answer_question import apply_answer_guardrails

def print_result(name, passed):
    print(f"{name}: {'PASS' if passed else 'FAIL'}")

def test_masks_secret_in_answer():
    context = {"alert": {"finding_id": "gd-seeded-0001"}}
    answer = "The leaked key was AKIA1234567890ABCDEF."
    out = apply_answer_guardrails(answer, context)
    print("\n=== Mask Secret In Answer ===")
    print(out)
    return "AKIA1234567890ABCDEF" not in out

def test_caveat_on_fabricated_ip():
    context = {"alert": {"finding_id": "gd-seeded-0001", "source_ip_address": "198.51.100.7"}}
    answer = "Traffic also came from 203.0.113.99."
    out = apply_answer_guardrails(answer, context)
    print("\n=== Caveat On Fabricated IP ===")
    print(out)
    return "REVIEW_REQUIRED" in out

def test_clean_answer_unchanged_meaning():
    context = {"alert": {"finding_id": "gd-seeded-0001", "source_ip_address": "198.51.100.7"}}
    answer = "The login came from 198.51.100.7"
    out = apply_answer_guardrails(answer, context)
    print("\n=== Clean Answer ===")
    print(out)
    return "REVIEW_REQUIRED" not in out and "198.51.100.7" in out

def main():
    tests = [
        ("Mask secret in answer", test_masks_secret_in_answer),
        ("Caveat on fabricated IP", test_caveat_on_fabricated_ip),
        ("Clean answer unchanged", test_clean_answer_unchanged_meaning),
    ]
    passed = 0
    for name, fn in tests:
        ok = fn()
        print_result(name, ok)
        passed += 1 if ok else 0
    print("\n" + "=" * 100)
    print(f"Answer-guardrail validation score: {passed}/{len(tests)}")

if __name__ == "__main__":
    main()