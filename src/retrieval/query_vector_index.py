from pathlib import Path
from typing import List
from functools import lru_cache

import chromadb
from sentence_transformers import SentenceTransformer

VECTOR_STORE_DIR = Path("data/vector_store")
COLLECTION_NAME = "security_runbooks"

EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

@lru_cache(maxsize=1)
def get_embedding_model() -> SentenceTransformer:
    return SentenceTransformer(EMBEDDING_MODEL_NAME)

@lru_cache(maxsize=1)
def get_collection():
    client = chromadb.PersistentClient(path=str(VECTOR_STORE_DIR))
    return client.get_collection(name=COLLECTION_NAME)

def retrieve_runbook_context(query: str, top_k: int =4) -> List[dict]:
    model = get_embedding_model()
    collection = get_collection()

    query_embedding = model.encode([query]).tolist()[0]

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=top_k,
    )

    retrieved = []

    for doc, metadata, distance in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        retrieved.append(
            {
                "text": doc,
                "metadata": metadata,
                "distance": distance,
            }
        )
    
    return retrieved

def main():
    query = "What should I do for suspected AWS credential compromise?"

    results = retrieve_runbook_context(query)

    print("\nQuery:")
    print(query)

    print("\nRetrieved Context:")
    for i, result in enumerate(results, start=1):
        print("\n" + "-" * 100)
        print(f"Result {i}")
        print(f"Source: {result['metadata']['source']}")
        print(f"Chunk: {result['metadata']['chunk_index']}")
        print(f"Distance: {result['distance']}")
        print(result["text"])

if __name__ == "__main__":
    main()