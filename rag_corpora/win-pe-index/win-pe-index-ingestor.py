#!/usr/bin/env python3
"""
Simple PE Ingestor — Pure Ingestion Mode
========================================
Reads markdown files from a corpus directory and stores them directly in ChromaDB.
No chunking, no complex splitting — just straightforward ingestion.

Requirements:
    pip install chromadb openai

Usage:
    python simple_ingest.py --corpus ./pe-corpus --db ./pe-chromadb
    python simple_ingest.py --corpus ./pe-corpus --db ./pe-chromadb --embedding-url http://localhost:1234/v1
"""

import argparse
import os
from pathlib import Path

import chromadb
from openai import OpenAI


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_DB_PATH = "~/.simple_pe_ingest/chromadb"
DEFAULT_EMBEDDING_URL = "http://localhost:1234/v1"
COLLECTION_NAME = "pe_files"


def extract_metadata(text):
    """Extract YAML frontmatter and basic info from markdown."""
    meta = {}
    
    # Extract YAML frontmatter
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            fm_lines = text[3:end].strip().split("\n")
            for line in fm_lines:
                if ":" in line and not line.strip().startswith("#"):
                    key, _, value = line.partition(":")
                    meta[key.strip()] = value.strip()
    
    # Extract title from first heading
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("# "):
            meta["title"] = line[2:].strip()
            break
    
    return meta


def get_document_text(text, meta):
    """Get the main content of the document for embedding."""
    # Remove YAML frontmatter
    if text.startswith("---"):
        end = text.find("---", 3)
        body = text[end + 3:] if end != -1 else text
    else:
        body = text
    
    # Clean up markdown formatting for better embeddings
    lines = body.split("\n")
    cleaned_lines = []
    for line in lines:
        # Remove bold/italic markers but keep content
        clean_line = line.replace("**", "").replace("*", "")
        # Keep headings and important info
        if clean_line.strip():
            cleaned_lines.append(clean_line)
    
    return "\n".join(cleaned_lines).strip()


def embed_texts(texts, client, model):
    """Embed texts in batches."""
    all_embeddings = []
    bs = 32
    
    for i in range(0, len(texts), bs):
        batch = texts[i:i + bs]
        resp = client.embeddings.create(model=model, input=batch)
        for item in resp.data:
            all_embeddings.append(item.embedding)
    
    return all_embeddings


def ingest(corpus_dir, db_path, embedding_url, embedding_model):
    """Ingest all markdown files from the corpus directory."""
    print(f"Corpus: {corpus_dir}")
    print(f"DB:     {db_path}")
    print(f"Embed:  {embedding_url} ({embedding_model})")

    # Load all documents
    path = Path(corpus_dir)
    md_files = sorted(path.glob("*.md"))
    
    if not md_files:
        print("No markdown files found.")
        return
    
    print(f"\nFound {len(md_files)} markdown files\n")
    
    # Extract metadata and content from each file
    documents = []
    for f in md_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  WARN: Could not read {f}: {e}")
            continue
        
        if not text.strip():
            continue
        
        meta = extract_metadata(text)
        meta["source"] = "pe-index"
        meta["file"] = f.name
        meta["path"] = str(f.relative_to(path))
        
        # Use title or filename as name if not in metadata
        if "name" not in meta:
            meta["name"] = meta.get("title", f.stem)
        
        doc_text = get_document_text(text, meta)
        
        documents.append({
            "id": f.name,  # Simple ID based on filename
            "text": doc_text,
            "metadata": meta
        })
    
    print(f"\nExtracted {len(documents)} documents")

    if not documents:
        print("Nothing to ingest.")
        return
    
    # Set up ChromaDB
    client = OpenAI(base_url=embedding_url, api_key="lm-studio")
    db = chromadb.PersistentClient(path=db_path)
    
    # Create or get collection with cosine similarity
    col = db.get_or_create_collection(
        name=COLLECTION_NAME, 
        metadata={"hnsw:space": "cosine"}
    )

    # Check for existing documents to avoid duplicates
    existing_ids = set(col.get()["ids"]) if col.count() > 0 else set()
    new_docs = [doc for doc in documents if doc["id"] not in existing_ids]
    
    print(f"New: {len(new_docs)} (skipping {len(documents) - len(new_docs)} existing)")

    if not new_docs:
        print("All documents already ingested.")
        return
    
    # Embed and store in batches
    bs = 32
    for i in range(0, len(new_docs), bs):
        batch = new_docs[i:i + bs]
        
        texts = [doc["text"] for doc in batch]
        ids = [doc["id"] for doc in batch]
        metadatas = [doc["metadata"] for doc in batch]
        
        print(f"  Embedding {i // bs + 1}/{(len(new_docs) + bs - 1) // bs}...")
        
        embs = embed_texts(texts, client, embedding_model)
        
        col.add(
            ids=ids,
            documents=texts,
            embeddings=embs,
            metadatas=metadatas
        )
    
    print(f"\nDone. Collection: {col.count()} docs.")
    print(f"Database at: {os.path.abspath(db_path)}")


def show_stats(db_path):
    """Show statistics about the ingested collection."""
    db = chromadb.PersistentClient(path=db_path)
    col = db.get_or_create_collection(name=COLLECTION_NAME)
    
    count = col.count()
    print(f"Database: {os.path.abspath(db_path)}")
    print(f"Total documents: {count}")
    
    if count > 0:
        all_meta = col.get(include=["metadatas"])
        sources = {}
        for m in all_meta["metadatas"]:
            s = m.get("source", "?")
            sources[s] = sources.get(s, 0) + 1
        
        print("\nBy source:")
        for s, c in sorted(sources.items()):
            print(f"  {s}: {c}")


def main():
    parser = argparse.ArgumentParser(description="Simple PE Ingestor")
    parser.add_argument("--corpus", help="Path to corpus directory with .md files")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, 
                       help=f"ChromaDB path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--embedding-url", default=DEFAULT_EMBEDDING_URL,
                       help="LM Studio embedding endpoint")
    parser.add_argument("--embedding-model", default="text-embedding-nomic-embed-text-v1.5@f32",
                       help="Embedding model name")
    parser.add_argument("--stats", action="store_true", help="Show database stats")
    
    args = parser.parse_args()

    if args.stats:
        show_stats(args.db)
    elif args.corpus:
        ingest(args.corpus, args.db, args.embedding_url, args.embedding_model)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
