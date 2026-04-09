# AI Assistance in Windows Internals reverse engineering and patch diffing toolkit
---

## Overview

This project consists of three main components:

1. **Patch Diffing Workflow** — Automated tools for triaging CVEs from Microsoft Patch Tuesday, identifying updated binaries via KB file manifests, and using Ghidra + BinDiff to analyze binary differences.

2. **Windows Internals RAG** — A local RAG system providing build-accurate access to Windows kernel struct layouts, native API documentation, and WDK references via MCP servers.

3. **Win-PE-Index RAG** — A local RAG system indexing all PE files (DLLs, EXEs, SYS) from a standard Windows workstation with their names, descriptions, types, locations, and versions.

---

## Components

### Patch Diffing Workflow

| Tool | Purpose |
|------|--------|
| `mcp_server/patch_tuesday_triage_analysis/fetch_patch_tuesday_interesting_vulns.py` | Fetches high-exploitability CVEs from Microsoft MSRC CVRF API |
| `bindiff_high_roi_to_csv.py` | Runs BinDiff headlessly and exports changed functions to CSV |
| `mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py` | MCP server exposing CVE triage, KB file discovery, IAT analysis, and PE index search |

> **Note:** Binary discovery is now KB-CSV-based (see workflow below). The previous WinBIndex/COMPONENT_MAP approach (`fetch_cve_related_pre_post_patch_binaries.py`) has been removed.

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
3. Install MCP server dependencies:
   ```bash
   pip install requests beautifulsoup4 pefile chromadb openai mcp
   ```
4. (Optional) Configure MCP client for patch triage tools:

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

The workflow is KB-driven: instead of resolving binaries from individual CVE tags, it fetches Microsoft's official file-version manifest for the month's cumulative update and diffs it against the previous month to find files that actually changed version.

**Supported platform:** Windows 11 25H2 x64 only.

1. **Triage CVEs** (via MCP tool or standalone script):
   ```bash
   python mcp_server/patch_tuesday_triage_analysis/fetch_patch_tuesday_interesting_vulns.py --month 2026-03
   ```
   Returns high-exploitability CVEs (`Exploitation Detected` / `Exploitation More Likely`) with severity, CVSS score, and the KB number that patches them on 25H2.

2. **Discover updated binaries for the month** (via MCP tool `fetch_kb_updated_files`):
   - Resolves the cumulative update KB from MSRC CVRF
   - Downloads the file-version CSV from `support.microsoft.com/help/{KB}`
   - Filters for x64 `.exe`/`.dll`/`.sys` files
   - Diffs against the previous month's KB to find version-changed files only
   - Enriches each entry with `FileDescription` from the local PE on disk
   - Saves a CSV to `BASE_DIR/{month}_KB{kb}_11-25H2_updated_files.csv`

3. **Cross-reference CVEs with updated binaries** — use the CVE list from step 1 and the file list from step 2 to identify which changed binaries are associated with high-exploitability vulnerabilities.

4. **Analyze with Ghidra:**
   - Open pre/post-patch binaries in Ghidra
   - Run `full_script_suite.py` from the Script Manager (Window → Script Manager)
   - This executes: C++ class extraction → datatype merging → binexport generation

5. **Generate diff report:**
   ```bash
   python bindiff_high_roi_to_csv.py primary.BinExport secondary.BinExport
   ```

6. **Visual inspection:** Open the `.BinDiff` file in BinDiff GUI for detailed analysis

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
| `fetch_patch_tuesday_cves` | `month` (YYYY-MM or YYYY-Mon, default: current) | List of high-exploitability CVEs with severity, CVSS, exploitability, and KB number for 25H2 |
| `fetch_kb_updated_files` | `month`, `windows_version` (default: `11-25H2`), `compare_with_previous` (default: `True`) | Saves CSV to `BASE_DIR`; returns summary string with path and counts |
| `list_iat` | `filename` (PE filename, no path separators) | IAT of a PE from System32/drivers with DLL FileDescriptions |
| `search_pe_by_description` | `keyword`, `top_k` (default 10, max 20) | PE files semantically matching description keywords |
| `search_pe_by_name` | `filename` | Metadata for exact filename match |

#### `fetch_patch_tuesday_cves` output fields

| Field | Description |
|-------|-------------|
| `CVE_ID` | CVE identifier |
| `Title` | Vulnerability title |
| `Severity` | Critical / Important |
| `Exploitability` | Exploitation Detected / Exploitation More Likely |
| `CVSS_BaseScore` | CVSS 3.1 base score |
| `CVSS_Vector` | Full CVSS vector string |
| `KB` | KB number patching this CVE on Windows 11 25H2 x64, or `null` if not applicable |

#### `fetch_kb_updated_files` CSV columns

| Column | Description |
|--------|-------------|
| `file_name` | Binary filename (e.g. `srv2.sys`) |
| `description` | FileDescription from PE version info on local disk, or empty |
| `file_version` | Version in this month's KB |
| `previous_version` | Version in previous month's KB (empty if file is new) |

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
| `BASE_DIR` | `./patch_bins` | Output directory for KB updated-files CSVs |
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
│   │   ├── fetch_patch_tuesday_interesting_vulns.py  # CVE triage helpers
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
