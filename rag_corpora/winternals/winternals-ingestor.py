#!/usr/bin/env python3
"""
Windows Internals RAG — Corpus Ingestor
========================================
Reads markdown files from a corpus directory, chunks them appropriately,
embeds via LM Studio (nomic-embed-text), and stores in a ChromaDB database.

Requirements:
    pip install chromadb openai

Usage:
    python ingest.py --corpus ./rag-corpus --db ./winternals.chromadb
    python ingest.py --corpus ./rag-corpus --db ./winternals.chromadb --embedding-url http://localhost:1234/v1
    python ingest.py --stats --db ./winternals.chromadb
    python ingest.py --reset --db ./winternals.chromadb
"""

import argparse
import os
import re
import hashlib
from pathlib import Path

import chromadb
from openai import OpenAI

# =============================================================================
# Config
# =============================================================================

DEFAULT_DB_PATH = os.path.expanduser("~/.winternals_rag/chromadb")
DEFAULT_EMBEDDING_URL = "http://localhost:1234/v1"
DEFAULT_EMBEDDING_MODEL = "text-embedding-nomic-embed-text-v1.5@f32"
COLLECTION_NAME = "winternals"
MAX_CHUNK_CHARS = 5500  # ~2048 tokens for nomic-embed-text v1.5
SPLIT_SOURCES = {"wdk-concepts"}

# =============================================================================
# Embedding
# =============================================================================

def embed_texts(texts, client, model):
    all_embeddings = []
    bs = 32
    for i in range(0, len(texts), bs):
        batch = texts[i:i + bs]
        resp = client.embeddings.create(model=model, input=batch)
        for item in resp.data:
            all_embeddings.append(item.embedding)
    return all_embeddings

# =============================================================================
# Chunking
# =============================================================================

def extract_yaml_frontmatter(text):
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            fm = text[3:end].strip()
            body = text[end + 3:].strip()
            meta = {}
            for line in fm.split("\n"):
                if ":" in line:
                    k, _, v = line.partition(":")
                    meta[k.strip()] = v.strip()
            return meta, body
    return {}, text

def split_on_headings(text, min_size=100):
    parts = re.split(r'(?=^## )', text, flags=re.MULTILINE)
    chunks = []
    for p in parts:
        p = p.strip()
        if len(p) >= min_size:
            chunks.append(p)
        elif chunks:
            chunks[-1] += "\n\n" + p
    return chunks if chunks else [text]

def split_oversized(text, meta, max_chars=MAX_CHUNK_CHARS):
    if len(text) <= max_chars:
        return [{"text": text, "metadata": meta}]
    if meta.get("source") == "vergilius":
        lines = text.split("\n")
        header, thead, fields, in_t = [], [], [], False
        for line in lines:
            if line.startswith("|") and "Offset" in line:
                in_t = True; thead.append(line); continue
            if in_t and line.startswith("|---"):
                thead.append(line); continue
            if in_t and line.startswith("|"):
                fields.append(line)
            elif not in_t:
                header.append(line)
        if not fields:
            return _split_text(text, meta, max_chars)
        ht = "\n".join(header)
        tt = "\n".join(thead)
        budget = max_chars - len(ht) - len(tt) - 100
        subs, cur, sz = [], [], 0
        for fl in fields:
            ls = len(fl) + 1
            if sz + ls > budget and cur:
                pn = len(subs) + 1
                ct = ht + "\n\n" + tt + "\n" + "\n".join(cur) + "\n"
                cm = dict(meta); cm["part"] = str(pn)
                cm["offset_range"] = f"{_exoff(cur[0])}-{_exoff(cur[-1])}"
                subs.append({"text": ct, "metadata": cm})
                cur, sz = [], 0
            cur.append(fl); sz += ls
        if cur:
            pn = len(subs) + 1
            ct = ht + "\n\n" + tt + "\n" + "\n".join(cur) + "\n"
            cm = dict(meta); cm["part"] = str(pn)
            cm["offset_range"] = f"{_exoff(cur[0])}-{_exoff(cur[-1])}"
            subs.append({"text": ct, "metadata": cm})
        return subs
    return _split_text(text, meta, max_chars)

def _exoff(row):
    cells = row.split("|")
    return cells[2].strip() if len(cells) >= 3 else "?"

def _split_text(text, meta, max_chars):
    paras = text.split("\n\n")
    results, cur, part = [], "", 0
    for p in paras:
        if len(cur) + len(p) > max_chars and cur:
            m = dict(meta); m["part"] = str(part)
            results.append({"text": cur.strip(), "metadata": m})
            cur, part = "", part + 1
        cur += p + "\n\n"
    if cur.strip():
        m = dict(meta); m["part"] = str(part)
        results.append({"text": cur.strip(), "metadata": m})
    return results

def extract_ntdoc_meta(text, meta):
    see, in_s = [], False
    for line in text.split("\n"):
        if line.strip().lower().startswith("# see also"): in_s = True; continue
        if in_s:
            if line.strip().startswith("#"): break
            see.extend(re.findall(r'`([^`]+)`', line))
    if see: meta["see_also"] = ", ".join(see[:10])
    name = meta.get("name", "")
    if name.lower().startswith(("nt", "zw", "rtl")): meta["kind"] = "function"
    elif name.startswith("_") or name.isupper(): meta["kind"] = "type"
    return meta

def chunk_id(source, filepath, section=""):
    return hashlib.md5(f"{source}::{filepath}::{section}".encode()).hexdigest()

# =============================================================================
# Loading
# =============================================================================

def load_source(source_dir, source_name):
    chunks, oversized = [], 0
    should_split = source_name in SPLIT_SOURCES
    md_files = sorted(source_dir.rglob("*.md"))
    print(f"  [{source_name}] {len(md_files)} files")

    for f in md_files:
        try: text = f.read_text(encoding="utf-8", errors="replace")
        except Exception as e: print(f"  WARN: {f}: {e}"); continue
        if not text.strip(): continue

        meta, body = extract_yaml_frontmatter(text)
        meta["source"] = source_name
        meta["file"] = f.name
        if "name" not in meta: meta["name"] = f.stem
        if source_name == "ntdoc": meta = extract_ntdoc_meta(body, meta)

        if should_split and len(body) > 1500:
            for idx, sec in enumerate(split_on_headings(body)):
                cm = dict(meta); cm["section"] = str(idx)
                fl = sec.split("\n")[0].strip()
                if fl.startswith("## "): cm["heading"] = fl[3:].strip()
                cid = chunk_id(source_name, str(f.relative_to(source_dir)), str(idx))
                scs = split_oversized(sec, cm)
                for si, sc in enumerate(scs):
                    ci = cid if len(scs) == 1 else chunk_id(source_name, str(f.relative_to(source_dir)), f"{idx}_{si}")
                    chunks.append({"id": ci, "text": sc["text"], "metadata": sc["metadata"]})
                if len(scs) > 1: oversized += 1
        else:
            ct = text if source_name == "vergilius" else body
            cid_val = chunk_id(source_name, str(f.relative_to(source_dir)))
            scs = split_oversized(ct, meta)
            if len(scs) == 1:
                chunks.append({"id": cid_val, "text": scs[0]["text"], "metadata": scs[0]["metadata"]})
            else:
                oversized += 1
                for si, sc in enumerate(scs):
                    ci = chunk_id(source_name, str(f.relative_to(source_dir)), f"part_{si}")
                    chunks.append({"id": ci, "text": sc["text"], "metadata": sc["metadata"]})

    if oversized: print(f"  [{source_name}] Split {oversized} oversized chunks")
    return chunks

def load_corpus(corpus_dir):
    path = Path(corpus_dir)
    all_chunks = []
    for sub in sorted(path.iterdir()):
        if sub.is_dir() and not sub.name.startswith("."):
            print(f"Loading {sub.name}...")
            chunks = load_source(sub, sub.name)
            all_chunks.extend(chunks)
            print(f"  -> {len(chunks)} chunks")
    return all_chunks

# =============================================================================
# Ingest
# =============================================================================

def ingest(corpus_dir, db_path, embedding_url, embedding_model):
    print(f"Corpus: {corpus_dir}")
    print(f"DB:     {db_path}")
    print(f"Embed:  {embedding_url} ({embedding_model})")

    chunks = load_corpus(corpus_dir)
    print(f"\nTotal chunks: {len(chunks)}")
    if not chunks: print("Nothing to ingest."); return

    client = OpenAI(base_url=embedding_url, api_key="lm-studio")
    db = chromadb.PersistentClient(path=db_path)
    col = db.get_or_create_collection(name=COLLECTION_NAME, metadata={"hnsw:space": "cosine"})

    existing = set(col.get()["ids"]) if col.count() > 0 else set()
    new = [c for c in chunks if c["id"] not in existing]
    if not new:
        print(f"All ingested. Collection: {col.count()} docs.")
        return

    print(f"New: {len(new)} (skipping {len(chunks) - len(new)} existing)")
    bs = 32
    for i in range(0, len(new), bs):
        batch = new[i:i + bs]
        print(f"  Embedding {i // bs + 1}/{(len(new) + bs - 1) // bs}...")
        embs = embed_texts([c["text"] for c in batch], client, embedding_model)
        col.add(ids=[c["id"] for c in batch], documents=[c["text"] for c in batch],
                embeddings=embs, metadatas=[c["metadata"] for c in batch])
    print(f"\nDone. Collection: {col.count()} docs.")
    print(f"Database at: {os.path.abspath(db_path)}")

def show_stats(db_path):
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
        print("By source:")
        for s, c in sorted(sources.items()):
            print(f"  {s}: {c}")

def reset_db(db_path):
    import shutil
    if os.path.exists(db_path):
        shutil.rmtree(db_path)
        print(f"Deleted: {db_path}")
    else:
        print("No database found.")

# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Windows Internals RAG Ingestor")
    parser.add_argument("--corpus", help="Path to corpus directory")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help=f"ChromaDB path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--embedding-url", default=DEFAULT_EMBEDDING_URL, help="LM Studio embedding endpoint")
    parser.add_argument("--embedding-model", default=DEFAULT_EMBEDDING_MODEL, help="Embedding model name")
    parser.add_argument("--stats", action="store_true", help="Show database stats")
    parser.add_argument("--reset", action="store_true", help="Delete the database")
    args = parser.parse_args()

    if args.reset:
        reset_db(args.db)
    elif args.stats:
        show_stats(args.db)
    elif args.corpus:
        ingest(args.corpus, args.db, args.embedding_url, args.embedding_model)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()