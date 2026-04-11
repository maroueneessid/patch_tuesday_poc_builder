#!/usr/bin/env python3
"""
Windows Internals RAG — MCP Server
====================================
An MCP server that exposes ChromaDB-backed Windows internals knowledge base
as tools for any MCP-compatible client (Claude Desktop, LM Studio, etc.)

Configuration via environment variables:
    WINTERNALS_DB        — path to ChromaDB database (required)
    WINTERNALS_EMBED_URL — LM Studio embedding endpoint (default: http://0.0.0.0:1234/v1)
    WINTERNALS_EMBED_MODEL — embedding model name (default: text-embedding-nomic-embed-text-v1.5@f32)

Requirements:
    pip install "mcp[cli]" chromadb openai

Usage:
    # Set env and run
    export WINTERNALS_DB=/path/to/winternals.chromadb
    python winternals_mcp.py

    # Or inline
    WINTERNALS_DB=./winternals.chromadb python winternals_mcp.py

    # Test with MCP inspector
    mcp dev winternals_mcp.py

LM Studio MCP config (add to your MCP settings):
    {
        "winternals": {
            "command": "python",
            "args": ["C:/path/to/winternals_mcp.py"],
            "env": {
                "WINTERNALS_DB": "C:/path/to/winternals.chromadb"
            }
        }
    }
"""

import os
import sys
import re
import argparse

from mcp.server.fastmcp import FastMCP
import chromadb
from openai import OpenAI

# =============================================================================
# Config from environment
# =============================================================================


EMBED_URL = os.environ.get("WINTERNALS_EMBED_URL", "http://0.0.0.0:1234/v1")
EMBED_MODEL = os.environ.get("WINTERNALS_EMBED_MODEL", "text-embedding-nomic-embed-text-v1.5@f32")
COLLECTION_NAME = "winternals"


# =============================================================================
# Initialize
# =============================================================================

mcp = FastMCP(
    name="winternals",
    instructions="""Windows Internals Knowledge Base & Analysis Engine.

### 1. Core Knowledge Sources
- Vergilius Project: Undocumented kernel struct/union/enum definitions (Windows 11 25H2, build 10.0.26200.6584).
- ntdoc: Native API (Nt/Zw) documentation derived from System Informer headers.
- WDK DDI/Concepts: Official Microsoft driver development and architecture documentation.

### 2. Strategic Tool Selection (Suggestive Prompting)
- For General Lookups: Prefer `search_exact` when you identify a symbol name (e.g., '_EPROCESS', 'PsGetCurrentProcess') to retrieve its full context.
- For Precision Analysis: `search_offset` is best suited when a query specifies a numeric or hex offset (e.g., 0x2e0, 188) within a known structure.
- For High-Level Context: Use `search_semantic` for conceptual questions or when specific symbol names are unknown.

### 3. Data Integrity & Merging Policy
- Continuous Definitions: Treat multiple chunks returned for the same symbol name (especially from Vergilius) as sequential parts of a single definition.
- Verification: Automatically synthesize these chunks into a unified view. Do not debate discrepancies between parts unless there is a physical overlap or gap in the 'offset_range' metadata.

### 4. Analysis Workflow (Zero-Shot Tooling)
- Execution-First Approach: In reverse engineering and patch diffing, prioritize data acquisition over preliminary reasoning.
- Minimize Pre-Thought: If a query contains a specific technical identifier or hex value, invoke the relevant search tool immediately. Perform your deep analysis and "thinking" only after the factual data has been retrieved from the knowledge base.
- Fact-Based Reasoning: Base your conclusions strictly on the offsets and field names provided in the search results.

### 5. Thinking Guardrails (Internal Monologue Constraints)
- Round 1 (Pre-Tool): Do not narrate your tool selection or validate hex formats in your thoughts. If the query contains a symbol and/or offset, your thought block should be a single-line checklist: "Target: [Symbol], Offset: [Value] -> Calling [Tool]."
- Round 2 (Post-Tool): Do not describe the fields you found or explain what they are in your thoughts. The tool output is the ground truth. Your thought block should only confirm: "Data retrieved. Formatting response."
- No Speculation: Do not think about "version differences" unless the tool returns multiple conflicting results for the same offset.


"""
)

def _get_collection():
    db = chromadb.PersistentClient(path=DB_PATH)
    return db.get_or_create_collection(name=COLLECTION_NAME, metadata={"hnsw:space": "cosine"})

def _get_embed_client():
    return OpenAI(base_url=EMBED_URL, api_key="lm-studio")

def _embed(text):
    client = _get_embed_client()
    resp = client.embeddings.create(model=EMBED_MODEL, input=[text])
    return resp.data[0].embedding

def _format_results(results, max_text=3000):
    """Format search results into readable text."""
    if not results:
        return "No results found."
    parts = []
    for r in results:
        src = r.get("source", "?")
        name = r.get("name", "?")
        orange = r.get("offset_range", "")
        dist = r.get("distance", 0)
        text = r.get("text", "")[:max_text]
        header = f"[{src}] {name}"
        if orange:
            header += f" (offsets: {orange})"
        if dist > 0:
            header += f" (similarity: {1-dist:.3f})"
        parts.append(f"--- {header} ---\n{text}")
    return "\n\n".join(parts)

def _raw_to_dicts(ids, docs, metas, distances=None):
    """Convert raw ChromaDB results to list of dicts."""
    results = []
    for i in range(len(ids)):
        r = {
            "source": metas[i].get("source", "?"),
            "name": metas[i].get("name", "?"),
            "text": docs[i],
            "offset_range": metas[i].get("offset_range", ""),
            "distance": distances[i] if distances else 0,
        }
        results.append(r)
    return results

# =============================================================================
# Tools
# =============================================================================

@mcp.tool()
def search_exact(name: str, source: str = "") -> str:
    """Search for a specific Windows kernel type, struct, or function by exact name.
    Returns ALL chunks matching this name, including all offset ranges for large structs.

    Args:
        name: Exact type/struct/function name (e.g. '_EPROCESS', '_MDL', 'NtCreateFile')
        source: Optional source filter: 'vergilius', 'ntdoc', 'wdk-ddi', 'wdk-concepts'
    """
    col = _get_collection()
    where = {"name": name}
    if source:
        where = {"$and": [{"name": name}, {"source": source}]}
    try:
        raw = col.get(where=where, include=["documents", "metadatas"])
        if not raw["ids"]:
            return f"No results found for name='{name}'" + (f" source='{source}'" if source else "")
        results = _raw_to_dicts(raw["ids"], raw["documents"], raw["metadatas"])
        count = len(results)
        return f"Found {count} chunk(s) for '{name}':\n\n" + _format_results(results)
    except Exception as e:
        return f"Search error: {e}"


@mcp.tool()
def search_offset(name: str, offset: str) -> str:
    """Search for a specific field at a given offset within a struct.
    Handles embedded sub-structs: if the target offset falls inside an embedded
    struct field, automatically resolves the sub-struct and sub-offset.

    Args:
        name: Struct name (e.g. '_EPROCESS', '_KTHREAD')
        offset: Hex offset to look up (e.g. '0x1D0', '0x4B8')
    """
    col = _get_collection()
    try:
        off_str = offset.strip().lower()
        if off_str.startswith("0x"):
            target = int(off_str, 16)
        else:
            target = int(off_str)
    except ValueError:
        return f"Invalid offset: {offset}"

    try:
        raw = col.get(where={"name": name}, include=["documents", "metadatas"])
        if not raw["ids"]:
            return f"No results for struct '{name}'"

        all_results = _raw_to_dicts(raw["ids"], raw["documents"], raw["metadatas"])

        # --- Phase 1: exact offset_range match ---
        matching = []
        parsed_ranges = []  # (lo, hi, result) for fallback
        for r in all_results:
            orange = r.get("offset_range", "")
            if not orange:
                continue
            parts = orange.split("-")
            if len(parts) != 2:
                continue
            try:
                lo_s, hi_s = parts[0].strip(), parts[1].strip()
                lo = int(lo_s, 16) if lo_s.startswith("0x") else int(lo_s)
                hi = int(hi_s, 16) if hi_s.startswith("0x") else int(hi_s)
                parsed_ranges.append((lo, hi, r))
                if lo <= target <= hi:
                    matching.append(r)
            except (ValueError, TypeError):
                continue

        # --- Phase 2: nearest-lower fallback ---
        # If target is beyond the hi of the best chunk, find the chunk whose hi is
        # closest to (but below) the target — this likely contains the embedded
        # parent field.
        if not matching and parsed_ranges:
            nearest = None
            nearest_hi = -1
            for lo, hi, r in parsed_ranges:
                if hi < target and hi > nearest_hi:
                    nearest = r
                    nearest_hi = hi
            # Also check: target might be just above the hi of a chunk
            # whose last field is an embedded struct that spans past hi
            if nearest:
                matching = [nearest]

        if not matching:
            return (f"No chunk with offset_range covering 0x{target:X} for '{name}'. "
                    f"Returning all {len(all_results)} chunks:\n\n"
                    + _format_results(all_results))

        # --- Phase 3: embedded struct auto-resolution ---
        embed_hint = _detect_embedded_field(matching[0].get("text", ""), target)
        sub_struct_result = None

        if embed_hint:
            sub_name = embed_hint["sub_struct"]
            sub_offset = embed_hint["sub_offset"]
            # Auto-chain: look up the sub-struct at the computed sub-offset
            try:
                sub_raw = col.get(where={"name": sub_name},
                                  include=["documents", "metadatas"])
                if sub_raw["ids"]:
                    sub_results = _raw_to_dicts(
                        sub_raw["ids"], sub_raw["documents"], sub_raw["metadatas"])
                    # Filter sub-struct chunks by sub-offset range
                    for sr in sub_results:
                        orange = sr.get("offset_range", "")
                        if not orange:
                            # Single-chunk struct (small enough to not be split)
                            sub_struct_result = sr
                            break
                        parts = orange.split("-")
                        if len(parts) == 2:
                            try:
                                lo = int(parts[0].strip(), 16)
                                hi = int(parts[1].strip(), 16)
                                if lo <= sub_offset <= hi:
                                    sub_struct_result = sr
                                    break
                            except (ValueError, TypeError):
                                pass
                    # If no range match, just take the first chunk
                    if not sub_struct_result and sub_results:
                        sub_struct_result = sub_results[0]
            except Exception:
                pass  # sub-lookup failed, still return the parent result

        # --- Format response ---
        output = (f"Found {len(matching)} chunk(s) for '{name}' "
                  f"covering offset 0x{target:X}:\n\n"
                  + _format_results(matching))

        if embed_hint:
            parent_field = embed_hint["parent_field"]
            parent_offset = embed_hint["parent_offset"]
            sub_name = embed_hint["sub_struct"]
            sub_offset = embed_hint["sub_offset"]
            output += (f"\n\n=== EMBEDDED STRUCT DETECTED ===\n"
                       f"Offset 0x{target:X} falls inside embedded field "
                       f"'{parent_field}' (type: {sub_name}) at 0x{parent_offset:X}.\n"
                       f"Sub-offset within {sub_name}: "
                       f"0x{target:X} - 0x{parent_offset:X} = 0x{sub_offset:X}\n"
                       f"Resolves to: {name}.{parent_field} + 0x{sub_offset:X}")

            if sub_struct_result:
                output += (f"\n\n=== AUTO-RESOLVED: {sub_name} at 0x{sub_offset:X} ===\n"
                           + _format_results([sub_struct_result]))
            else:
                output += (f"\n\nSub-struct '{sub_name}' not found in knowledge base. "
                           f"Try: search_exact('{sub_name}') or web search.")

        return output
    except Exception as e:
        return f"Search error: {e}"


def _detect_embedded_field(chunk_text: str, target_offset: int):
    """Scan a chunk's table rows to find if target_offset falls inside an embedded struct.

    Returns dict with parent_field, parent_offset, sub_struct, sub_offset if found.
    Returns None if target is a direct field or no embedded struct detected.
    """
    # Parse table rows: | Offset | Type | Field | ...
    # Match patterns like: | 0x98 | _KAPC_STATE | ApcState |
    #                  or: | 0x98 | struct _KAPC_STATE | ApcState |
    rows = []
    for line in chunk_text.split("\n"):
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")]
        # cells[0] is empty (before first |), so meaningful data starts at [1]
        if len(cells) < 4:
            continue
        offset_cell = cells[1]
        type_cell = cells[2]
        field_cell = cells[3]

        # Parse offset
        try:
            if offset_cell.startswith("0x") or offset_cell.startswith("0X"):
                off = int(offset_cell, 16)
            elif offset_cell.isdigit():
                off = int(offset_cell)
            else:
                continue
        except ValueError:
            continue

        rows.append((off, type_cell, field_cell))

    if not rows:
        return None

    # Find the last field whose offset is <= target
    candidate = None
    for off, type_name, field_name in sorted(rows, key=lambda r: r[0]):
        if off <= target_offset:
            candidate = (off, type_name, field_name)
        else:
            break

    if not candidate:
        return None

    parent_offset, type_name, field_name = candidate

    # Check if this is the exact offset (direct field, not embedded)
    if parent_offset == target_offset:
        return None

    # Check if the type looks like an embedded struct (no pointer indicator)
    # Pointers have * in the type: _KPROCESS*, PVOID, VOID*, etc.
    clean_type = type_name.replace("struct ", "").replace("union ", "").strip()
    if "*" in clean_type or clean_type.startswith("P") and clean_type[1:2].isupper():
        # Looks like a pointer type — not embedded
        # Exception: types like "PULONG" are pointers, but "PROCESS_..." is not
        # Simple heuristic: if it starts with P followed by uppercase and contains
        # no underscore after P, it's likely a pointer typedef (PVOID, PULONG, PCHAR)
        if re.match(r'^P[A-Z][A-Z_]*$', clean_type) and '_' not in clean_type[1:]:
            return None
        if '*' in clean_type:
            return None

    # Looks like an embedded struct — compute sub-offset
    # Extract the base struct name (strip array notation, qualifiers)
    sub_struct = re.match(r'[_A-Za-z][_A-Za-z0-9]*', clean_type)
    if not sub_struct:
        return None
    sub_struct_name = sub_struct.group(0)

    # Skip primitive types
    primitives = {
        "ULONG", "LONG", "USHORT", "SHORT", "UCHAR", "CHAR", "BOOLEAN",
        "ULONGLONG", "LONGLONG", "UINT", "INT", "BYTE", "WORD", "DWORD",
        "QWORD", "VOID", "SIZE_T", "ULONG_PTR", "LONG_PTR", "NTSTATUS",
        "HANDLE", "PVOID", "BOOLEAN", "KIRQL", "KPRIORITY",
    }
    if sub_struct_name.upper() in primitives or sub_struct_name in primitives:
        return None

    sub_offset = target_offset - parent_offset

    return {
        "parent_field": field_name,
        "parent_offset": parent_offset,
        "sub_struct": sub_struct_name,
        "sub_offset": sub_offset,
    }


@mcp.tool()
def search_semantic(query: str, source: str = "", top_k: int = 5) -> str:
    """Semantic similarity search across the Windows internals knowledge base.
    Use for conceptual questions, behavior lookups, or when you don't know the exact name.

    Args:
        query: Natural language search query (e.g. 'MDL bounds check vulnerability', 'process token security')
        source: Optional source filter: 'vergilius', 'ntdoc', 'wdk-ddi', 'wdk-concepts'
        top_k: Number of results (default 5, max 15)
    """
    col = _get_collection()
    top_k = min(max(top_k, 1), 15)

    try:
        qe = _embed(query)
        where = {"source": source} if source else None
        raw = col.query(query_embeddings=[qe], n_results=top_k, where=where,
                        include=["documents", "metadatas", "distances"])

        if not raw["ids"][0]:
            return f"No results for query: {query}"

        results = _raw_to_dicts(
            raw["ids"][0], raw["documents"][0], raw["metadatas"][0], raw["distances"][0])

        return f"Found {len(results)} result(s):\n\n" + _format_results(results)
    except Exception as e:
        return f"Search error: {e}"


@mcp.tool()
def list_sources() -> str:
    """List all knowledge base sources and their document counts."""
    col = _get_collection()
    count = col.count()
    if count == 0:
        return "Knowledge base is empty."

    all_meta = col.get(include=["metadatas"])
    sources = {}
    for m in all_meta["metadatas"]:
        s = m.get("source", "?")
        sources[s] = sources.get(s, 0) + 1

    lines = [f"Total documents: {count}", ""]
    for s, c in sorted(sources.items()):
        desc = {
            "vergilius": "Undocumented kernel structs/unions/enums (Windows 11 25H2)",
            "ntdoc": "Native API docs from System Informer phnt headers",
            "wdk-ddi": "WDK DDI function/struct reference",
            "wdk-concepts": "WDK conceptual driver development docs",
        }.get(s, "")
        lines.append(f"  {s}: {c} chunks — {desc}")
    return "\n".join(lines)


@mcp.tool()
def get_stats() -> str:
    """Get detailed statistics about the knowledge base including sample type names."""
    col = _get_collection()
    count = col.count()
    if count == 0:
        return "Knowledge base is empty."

    all_meta = col.get(include=["metadatas"])
    sources = {}
    names_by_source = {}
    for m in all_meta["metadatas"]:
        s = m.get("source", "?")
        n = m.get("name", "?")
        sources[s] = sources.get(s, 0) + 1
        if s not in names_by_source:
            names_by_source[s] = set()
        names_by_source[s].add(n)

    lines = [f"Total documents: {count}", ""]
    for s, c in sorted(sources.items()):
        names = sorted(names_by_source.get(s, set()))
        sample = names[:10]
        lines.append(f"{s}: {c} chunks, {len(names)} unique names")
        lines.append(f"  Sample: {', '.join(sample)}")
        if len(names) > 10:
            lines.append(f"  ... and {len(names) - 10} more")
        lines.append("")
    return "\n".join(lines)


# =============================================================================
# Run
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the Winternals MCP tool."
    )
    parser.add_argument(
        "--db",
        dest="db_path",
        required=True,
        help="Path to the Winternals ChromaDB file (e.g. /path/to/winternals.chromadb)",
    )
    # add any other options you need here
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    global DB_PATH
    DB_PATH = os.path.expanduser(args.db_path)
    mcp.run()