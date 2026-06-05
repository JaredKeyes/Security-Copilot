from src.retrieval.query_vector_index import retrieve_runbook_context

TEST_CASES = [
    {
        "query": "What should I do for suspected AWS credential compromise?",
        "expected_file": "aws_credential_compromise.md",
    },
    {
        "query": "How do I investigate CloudTrail StopLogging or DeleteTrail activity?",
        "expected_file": "cloudtrail_tampering.md",
    },
    {
        "query": "What should I check after AuthorizeSecurityGroupIngress opens a port?",
        "expected_file": "suspicious_security_group_change.md",
    },
    {
        "query": "How do I investigate suspicious S3 GetObject access?",
        "expected_file": "s3_data_exposure.md",
    },
    {
        "query": "How do I investigate suspicious svc-ci-cd activity?",
        "expected_file": "service_account_abuse.md",
    },
]

def main():
    passed = 0

    for case in TEST_CASES:
        query = case["query"]
        expected_file = case["expected_file"]

        results = retrieve_runbook_context(query, top_k=3)
        retrieved_files = [result["metadata"]["file_name"] for result in results]

        success = expected_file in retrieved_files

        if success:
            passed += 1

        print("\n" + "=" * 100)
        print(f"Query: {query}")
        print(f"Expected file: {expected_file}")
        print(f"Retrieved files: {retrieved_files}")
        print(f"Result: {'PASS' if success else 'FAIL'}")

    print("\n" + "=" * 100)
    print(f"Retrieval validation score: {passed}/{len(TEST_CASES)}")

if __name__ == "__main__":
    main()