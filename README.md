# AI Assistance in Windows Internals reverse engineering and patch diffing toolkit
---

## Overview

This project consists of two main components:

1. **Patch Diffing Workflow** — Automated tools for triaging CVEs from Microsoft Patch Tuesday, identifying updated binaries via KB file manifests, and using Ghidra + BinDiff to analyze binary differences.

2. **Ghidra Headless Batch Analyzer** — A containerized, headless batch analysis pipeline built around Ghidra 11.0.3. It automates importing Windows binaries, applying PDB symbols, running C++ class recovery and datatype enrichment scripts, and exporting results to BinExport format — all without opening the GUI.

> **See [ghidra_headless_batch_analyzer_docker/README.md](ghidra_headless_batch_analyzer_docker/README.md) for detailed documentation on the Ghidra pipeline, including build instructions, usage, and technical issues encountered during development.**

---

## Components

### Patch Diffing Workflow

| Tool | Purpose |
|------|---------|
| `mcp_server/patch_tuesday_triage_analysis/fetch_patch_tuesday_interesting_vulns.py` | Fetches high-exploitability CVEs from Microsoft MSRC CVRF API |
| `bindiff_high_roi_to_csv.py` | Runs BinDiff headlessly and exports changed functions to CSV |
| `mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py` | MCP server exposing CVE triage, KB file discovery, IAT analysis, and PE index search |

> **Note:** Binary discovery is now KB-CSV-based (see workflow below). The previous WinBIndex/COMPONENT_MAP approach (`fetch_cve_related_pre_post_patch_binaries.py`) has been removed.

### Ghidra Headless Batch Analyzer

A Docker-based pipeline for automated binary analysis. See the [dedicated README](ghidra_headless_batch_analyzer_docker/README.md) for full details.

**Key features:**
- Imports and analyzes binaries with Ghidra's auto-analysis
- Applies PDB symbols before analysis (if co-located with binaries)
- Runs post-analysis scripts: C++ class recovery, datatype enrichment from .gdt archives
- Exports to `.BinExport` format for BinDiff
- Handles project ownership for cross-user compatibility

---

## Ghidra Scripts

The Ghidra scripts are now located in `ghidra_headless_batch_analyzer_docker/Scripts/`. Brief descriptions:

| Script | Purpose |
|--------|---------|
| `CppClassExtractor.py` | Recovers C++ class structure from MSVC-compiled binaries using decompiler output |
| `DatatypeMerger.py` | Replaces empty/undefined composite types with definitions from external GDT archives |
| `post_script_export_binexports.py` | Exports the current program to a `.BinExport` file for BinDiff |

For detailed documentation on what each script does, see the [Ghidra pipeline README](ghidra_headless_batch_analyzer_docker/README.md#what-each-script-does).

---

## Setup

### Prerequisites

- Ghidra 11.0.3 PUBLIC (download from [official release](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip))
- BinExport extension (install via File → Install Extensions)
- BinDiff
- Python with required packages (`pip install requests beautifulsoup4 pefile chromadb openai mcp` for MCP server)
- LM Studio running locally at `http://localhost:1234` (for PE index embedding, if used)

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

### Ghidra Headless Pipeline Setup

See the [Ghidra pipeline README](ghidra_headless_batch_analyzer_docker/README.md) for:
- Docker build instructions
- Native (non-Docker) usage
- Environment variables
- Troubleshooting technical issues

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

4. **Analyze with Ghidra Headless Pipeline:**
   - Place pre/post-patch binaries in input directory
   - Run the Docker container (see [Ghidra pipeline README](ghidra_headless_batch_analyzer_docker/README.md))
   - This executes: PDB symbol application → auto-analysis → C++ class extraction → datatype merging → BinExport generation

5. **Generate diff report:**
   ```bash
   python bindiff_high_roi_to_csv.py primary.BinExport secondary.BinExport
   ```

6. **Visual inspection:** Open the `.BinDiff` file in BinDiff GUI for detailed analysis

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
├── bindiff_high_roi_to_csv.py                   # BinDiff analysis script
├── ghidra_headless_batch_analyzer_docker/       # Containerized Ghidra pipeline
│   ├── README.md                                # Detailed pipeline documentation
│   ├── Dockerfile                               # Container build definition
│   ├── headless_analyze.py                      # Python entrypoint (pyhidra)
│   ├── Scripts/                                 # Ghidra analysis scripts
│   │   ├── CppClassExtractor.py                 # C++ class / vtable recovery
│   │   ├── DatatypeMerger.py                    # Empty composite backfill from .gdt
│   │   ├── post_script_export_binexports.py     # Export to BinExport
│   │   ├── Windows_Driver_functons.gdt          # Windows driver function types
│   │   └── wdk_full_26100.gdt                   # WDK data type archive
│   └── extensions/                              # BinExport extension
└── mcp_server/                                  # MCP servers
    └── patch_tuesday_triage_analysis/
        ├── fetch_patch_tuesday_interesting_vulns.py  # CVE triage helpers
        └── patch_tuesday_triage_analysis_mcp_server.py
```

> **Note:** Ghidra 11.0.3 PUBLIC must be downloaded separately and placed in
> `ghidra_headless_batch_analyzer_docker/ghidra_11.0.3_PUBLIC/`.  
> Download: [ghidra_11.0.3_PUBLIC_20240410.zip](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip)

---

## License

This project is provided as-is for educational and research purposes.