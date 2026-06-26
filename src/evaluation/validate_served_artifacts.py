import os

from src.evaluation.served_artifacts import load_served_artifact

def print_result(name, passed):
    print(f"{name}: {'PASS' if passed else 'FAIL'}")

def test_loads_seeded_artifact():
    if not os.environ.get("REPORTS_BUCKET"):
        print("SKIP: REPORTS_BUCKET not set (need AWS profile test)")
        return True
    art = load_served_artifact("gd-seeded-0001")
    print("\n=== Load Served Artifact ===")
    print({k: type(v).__name__ for k, v in (art or {}).items()})
    return art is not None and "report" in art and "context" in art

def test_missing_returns_none():
    if not os.environ.get("REPORTS_BUCKET"):
        print("SKIP: REPORTS_BUCKET not set")
        return True
    return load_served_artifact("gd-seeded-does-not-exist") is None

def main():
    tests = [
        ("Loads seeded artifact", test_loads_seeded_artifact),
        ("Missing returns None", test_missing_returns_none),
    ]
    passed = 0
    for name, fn in tests:
        ok = fn()
        print_result(name, ok)
        passed += 1 if ok else 0
    print("\n" + "=" * 100)
    print(f"Server-artifacts validation score: {passed}/{len(tests)}")

if __name__ == "__main__":
    main()