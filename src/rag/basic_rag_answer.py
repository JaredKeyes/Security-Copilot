from src.retrieval.query_vector_index import retrieve_runbook_context

def format_context(results):
    context_blocks = []

    for i, result in enumerate(results, start=1):
        source = result["metadata"]["source"]
        chunk_index = result["metadata"]["chunk_index"]
        text = result["text"]

        context_blocks.append(
            f"[Source {i}: {source}, chunk {chunk_index}]\n{text}"
        )
    
    return "\n\n".join(context_blocks)

def generate_basic_rag_answer(query: str, top_k: int = 4) -> str:
    results = retrieve_runbook_context(query, top_k=top_k)

    if not results:
        return "No relevant runbook context was found."

    sources = []
    investigation_steps = []
    containment_steps = []
    evidence_items = []

    for result in results:
        text = result["text"]
        metadata = result["metadata"]

        source_label = f"{metadata['file_name']}::chunk-{metadata['chunk_index']}"
        sources.append(source_label)

        lower_text = text.lower()

        if "investigation steps" in lower_text:
            investigation_steps.append(text)

        if "containment steps" in lower_text:
            containment_steps.append(text)

        if "evidence to collect" in lower_text:
            evidence_items.append(text)

    answer = []

    answer.append(f"Question: {query}")
    answer.append("")
    answer.append("Relevant runbook context was retrieved from:")
    for source in sorted(set(sources)):
        answer.append(f"- {source}")

    answer.append("")
    answer.append("Initial response:")
    answer.append(
        "Based on the retrieved runbook context, the analyst should review the involved principal, "
        "source IP address, related CloudTrail events, GuardDuty finding details, IAM metadata, and any "
        "sensitive resource access before taking containment action."
    )

    answer.append("")
    answer.append("Retrieved context:")
    answer.append(format_context(results))

    return "\n".join(answer)

def main():
    questions = [
        "What should I do for suspected AWS credential compromise?",
        "How should I investigate CloudTrail logging being disabled?",
        "What should I check after a suspicious security group change?",
        "How do I investigate suspicious S3 data access?",
        "What should I do if a service account is abused?",
    ]

    for question in questions:
        print("\n" + "=" * 100)
        print(generate_basic_rag_answer(question))

if __name__ == "__main__":
    main()