from pathlib import Path
from typing import List

import chromadb
from fastembed import TextEmbedding

RUNBOOK_DIR = Path("data/raw/runbooks")
VECTOR_STORE_DIR = Path("data/vector_store")
COLLECTION_NAME = "security_runbooks"

EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

def load_markdown_documents(runbook_dir: Path) -> List[dict]:
    documents = []

    for path in sorted(runbook_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")

        documents.append(
            {
                "source": str(path),
                "file_name": path.name,
                "text": text,
            }
        )

    return documents

def chunk_text(text: str, chunk_size: int = 900, overlap: int = 150) -> List[str]:
    chunks = []

    start = 0

    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        start += chunk_size - overlap

    return chunks

def build_index():
    VECTOR_STORE_DIR.mkdir(parents=True, exist_ok=True)

    documents = load_markdown_documents(RUNBOOK_DIR)

    if not documents:
        raise FileNotFoundError(f"No markdown runbooks found in {RUNBOOK_DIR}")

    model = TextEmbedding(model_name=EMBEDDING_MODEL_NAME)

    client = chromadb.PersistentClient(path=str(VECTOR_STORE_DIR))

    existing_collections = [collection.name for collection in client.list_collections()]

    if COLLECTION_NAME in existing_collections:
        client.delete_collection(COLLECTION_NAME)

    collection = client.create_collection(name=COLLECTION_NAME)

    ids = []
    texts = []
    metadatas = []

    for doc in documents:
        chunks = chunk_text(doc["text"])

        for chunk_index, chunk in enumerate(chunks):
            chunk_id = f"{doc['file_name']}::chunk-{chunk_index}"

            ids.append(chunk_id)
            texts.append(chunk)
            metadatas.append(
                {
                    "source": doc["source"],
                    "file_name": doc["file_name"],
                    "chunk_index": chunk_index,
                }
            )

    embeddings = [e.tolist() for e in model.embed(texts)]

    collection.add(
        ids=ids,
        documents=texts,
        embeddings=embeddings,
        metadatas=metadatas,
    )

    print("Vector index built successfully.")
    print(f"Documents loaded: {len(documents)}")
    print(f"Chunks indexed: {len(texts)}")
    print(f"Vector store path: {VECTOR_STORE_DIR}")
    print(f"Collection name: {COLLECTION_NAME}")

if __name__ == "__main__":
    build_index()