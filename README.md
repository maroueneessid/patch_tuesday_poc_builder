# AI Assistance in Windows nternals reverse engineering and patch diffing toolkit
---

## Overview

This project consists of three main components:

1. **Patch Diffing Workflow** — Automated tools for triaging CVEs from Microsoft Patch Tuesday, fetching pre/post-patch binaries, and using Ghidra + BinDiff to analyze binary differences.

2. **Windows Internals RAG** — A local RAG system providing build-accurate access to Windows kernel struct layouts, native API documentation, and WDK references via MCP servers.

3. **Win-PE-Index RAG** — A local RAG system indexing all PE files (DLLs, EXEs, SYS) from a standard Windows workstation with their names, descriptions, types, locations, and versions.

---

## Components

### Patch Diffing Workflow

| Tool | Purpose |
|------|--------|
| `mcp_server/patch_tuesday_triage_analysis/fetch_patch_tuesday_interesting_vulns.py` | Fetches high-exploitability CVEs from Microsoft MSRC CVRF API |
| `mcp_server/patch_tuesday_triage_analysis/fetch_cve_related_pre_post_patch_binaries.py` | Downloads patched and vulnerable Windows binaries for a given CVE |
| `bindiff_high_roi_to_csv.py` | Runs BinDiff headlessly and exports changed functions to CSV |
| `mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py` | MCP server exposing the full triage workflow + PE index search as tools |

### Ghidra Scripts

| Script | Purpose |
|--------|--------|
| `CppClassExtractor.py` | Recovers C++ class structure from MSVC-compiled binaries using decompiler output |
| `DatatypeMerger.py` | Replaces empty/undefined composite types with definitions from external GDT archives |
| `post_script_export_binexports.py` | Exports the current program to a `.BinExport` file for BinDiff |

### Windows Internals RAG

| Component | Purpose |
|-----------|--------|
| `mcp_server/winternals_rag/winternals_rag_mcp.py` | MCP server exposing search tools over the knowledge base |
| `rag_corpora/winternals/winternals-ingestor.py` | Corpus ingestion pipeline (chunking + embedding + ChromaDB) |

### Win-PE-Index RAG

| Component | Purpose |
|-----------|--------|
| `mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py` | Integrated PE index search tools (`search_pe_by_description`, `search_pe_by_name`) |
| `rag_corpora/win-pe-index/win-pe-index-ingestor.py` | Corpus ingestion pipeline for PE file metadata |

---

## Knowledge Base Sources

### Windows Internals RAG

Built from four sources:

| Source | Content |
|--------|--------|
| **vergilius** | Undocumented kernel struct/union/enum definitions (Windows 11 25H2, build 10.0.26200.x) |
| **ntdoc** | Native API (Nt/Zw/Rtl) documentation from System Informer phnt headers |
| **wdk-ddi** | WDK DDI function and struct reference |
| **wdk-concepts** | WDK conceptual driver development documentation |

### Win-PE-Index RAG

Indexes all PE files (~4700) from a standard Windows workstation:

| Field | Description |
|-------|-------------|
| **name** | Filename (e.g., `msfs.sys`, `tapisrv.dll`) |
| **description** | FileDescription from VS_VERSIONINFO block |
| **type** | PE type (DLL, EXE, SYS) |
| **location** | Path in System32 or drivers\ |
| **version** | ProductVersion string |

---

## Setup

### Prerequisites

- Ghidra 11.0.3+
- BinExport extension (install via File → Install Extensions)
- BinDiff
- Python with required packages (`pip install -r rag_corpora/requirements.txt` for RAG components)
- LM Studio running locally at `http://localhost:1234`

### Patch Diffing Setup

1. Clone the repository and navigate to the directory
2. Ensure Ghidra is installed and BinExport/BinDiff extensions are active
3. (Optional) Configure MCP client for patch triage tools:

```json
{
  "mcpServers": {
    "patch-tuesday": {
      "command": "python",
      "args": [
        "C:/path/to/patchDiffingNotes/mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py"
      ],
      "env": {
        "BASE_DIR": "C:/path/to/patch_bins",
        "PE_INDEX_DB": "C:/path/to/pe-index.chromadb"
      }
    }
  }
}
```

### Windows Internals RAG Setup

1. **Install dependencies:**
   ```bash
   pip install -r rag_corpora/requirements.txt
   ```

2. **Start LM Studio** with embedding model `nomic-embed-text-v1.5` running at `http://localhost:1234`

3. **Ingest the corpus:**
   ```bash
   python rag_corpora/winternals/winternals-ingestor.py --corpus ./rag-corpus --db ./winternals.chromadb
   ```

4. **Run the MCP server:**
   ```bash
   export WINTERNALS_DB=./winternals.chromadb
   python mcp_server/winternals_rag/winternals_rag_mcp.py
   ```

5. **Configure your LLM client** with the system prompt from `system_prompts/windows_reversing_specialist.md`

### Win-PE-Index RAG Setup

1. **Ingest the PE corpus:**
   ```bash
   python rag_corpora/win-pe-index/win-pe-index-ingestor.py --corpus ./rag-corpora/win-pe-index/extracted --db ./pe-index.chromadb
   ```

2. **Enable in patch-tuesday MCP server** by setting `PE_INDEX_DB` environment variable (see above)

---

## Usage

### Patch Diffing Workflow

1. **Triage CVEs:**
   ```bash
   python mcp_server/patch_tuesday_triage_analysis/fetch_patch_tuesday_interesting_vulns.py --month 2025-04
   ```

2. **Fetch binaries for a CVE:**
   ```bash
   python mcp_server/patch_tuesday_triage_analysis/fetch_cve_related_pre_post_patch_binaries.py --cve CVE-2025-29824
   ```

3. **Analyze with Ghidra:**
   - Open each binary in Ghidra
   - Run `full_script_suite.py` from the Script Manager (Window → Script Manager)
   - This executes: C++ class extraction → datatype merging → binexport generation

4. **Generate diff report:**
   ```bash
   python bindiff_high_roi_to_csv.py primary.BinExport secondary.BinExport
   ```

5. **Visual inspection:** Open the `.BinDiff` file in BinDiff GUI for detailed analysis

### Windows Internals RAG Usage

**Exact lookup:**
```python
search_exact("_EPROCESS")  # Returns all chunks for _EPROCESS struct
```

**Offset resolution with chaining:**
```python
search_offset("_KTHREAD", "0xB8")  # Resolves field at offset, auto-chains embedded structs
```

**Semantic search:**
```python
search_semantic("process termination")  # Cosine similarity for exploratory queries
```

### Win-PE-Index RAG Usage (via patch-tuesday MCP)

**Search by description/keyword:**
```python
search_pe_by_description("mailslot", top_k=5)  # Returns msfs.sys and related files
```

**Exact lookup by filename:**
```python
search_pe_by_name("tapisrv.dll")  # Returns metadata for Telephony Service DLL
```

---

## MCP Server Tools

### Patch Tuesday MCP Server (`patch-tuesday`)

| Tool | Arguments | Returns |
|------|-----------|--------|
| `fetch_patch_tuesday_cves` | `month`, `api_token` (optional) | List of high-exploitability CVEs with severity, CVSS, exploitability |
| `download_patch_binaries` | `cve_id`, `filename` (optional), `windows_version` | Paths to patched and vulnerable binaries, version info |
| `list_component_mappings` | `tag_filter` (optional substring) | Known CVE tag → binary filename mappings |
| `list_iat` | `filename` (PE filename, no path) | IAT of a PE from System32/drivers with DLL descriptions |
| `search_pe_by_description` | `keyword`, `top_k` (default 10) | PE files matching description keywords |
| `search_pe_by_name` | `filename` | Metadata for exact filename match |

### Windows Internals MCP Server (`winternals`)

| Tool | Arguments | Returns |
|------|-----------|--------|
| `search_exact` | Type/function name, `source` (optional) | All chunks for named type/function |
| `search_offset` | Struct name, hex offset | Field at offset with embedded struct chaining |
| `search_semantic` | Query string, `top_k` (default 5) | Cosine similarity search results |
| `list_sources` | — | Available knowledge base sources |
| `get_stats` | — | Database statistics and chunk counts |

---

## Environment Variables Reference

### Patch Tuesday MCP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_DIR` | `./patch_bins` | Directory for downloaded binaries |
| `PE_INDEX_DB` | *(not set)* | Path to PE index ChromaDB (enables `search_pe_*` tools) |
| `PE_INDEX_COLLECTION` | `pe_files` | ChromaDB collection name for PE index |
| `PE_INDEX_EMBED_URL` | `http://localhost:1234/v1` | LM Studio embedding endpoint |
| `PE_INDEX_EMBED_MODEL` | `text-embedding-nomic-embed-text-v1.5@f32` | Embedding model name |

### Windows Internals MCP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `WINTERNALS_DB` | *(required)* | Path to ChromaDB database |
| `WINTERNALS_EMBED_URL` | `http://localhost:1234/v1` | LM Studio embedding endpoint |
| `WINTERNALS_EMBED_MODEL` | `text-embedding-nomic-embed-text-v1.5@f32` | Embedding model name |

---

## Testing

The Windows Internals RAG system includes `test_questions.json` with 20 evaluation questions covering:
- Direct field lookups
- Embedded struct offset chains (e.g., `_KTHREAD.ApcState.Process`)
- Union/bitfield ambiguity
- Out-of-bounds / trick offsets

Use these to benchmark retrieval accuracy after ingestion.

---

## Recommended Reading

The blog post **[CVE-2026-20820 writeup by CravateRouge](https://cravaterouge.com/articles/cve-2026-20820/)** is highly recommended. It demonstrates this exact workflow end-to-end and covers:

- How to use jsacco's Ghidra GDT for Windows kernel types (relevant to `DatatypeMerger.py`)
- C++ class recovery with `CppClassExtractor.py`
- Patch diffing methodology with BinDiff

---

## Project Structure

```
patchDiffingNotes/
├── README.md                                    # This file
├── README_1.md                                  # Original patch diffing readme
├── README_2.md                                  # Original RAG readme
├── mcp_server/                                  # MCP servers
│   ├── patch_tuesday_triage_analysis/           # Patch Tuesday triage server
│   │   ├── fetch_cve_related_pre_post_patch_binaries.py
│   │   ├── fetch_patch_tuesday_interesting_vulns.py
│   │   └── patch_tuesday_triage_analysis_mcp_server.py
│   └── winternals_rag/                          # Windows Internals RAG server
│       └── winternals_rag_mcp.py
├── ghidra_scripts/                              # Ghidra analysis scripts
│   ├── full_script_suite.py
│   ├── C++ClassExtractor.py
│   ├── DatatypeMerger.py
│   └── post_script_export_binexports.py
├── bindiff_high_roi_to_csv.py                   # BinDiff analysis script
├── rag_corpora/                                 # RAG knowledge bases
│   ├── requirements.txt                         # Python dependencies
│   ├── winternals/                              # Windows Internals corpus
│   │   ├── winternals-corpus.zip
│   │   └── winternals-ingestor.py
│   └── win-pe-index/                            # PE file index corpus
│       ├── win-pe-index-corpus.zip
│       └── win-pe-index-ingestor.py
└── system_prompts/                              # System prompts for LLM sessions
    ├── patch_tuesday_triage.md                  # Patch Tuesday workflow prompt
    └── windows_reversing_specialist.md          # Windows RE specialist prompt
```

---

## License

This project is provided as-is for educational and research purposes.
