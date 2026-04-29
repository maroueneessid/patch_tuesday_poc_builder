# AI Assistance in Windows Internals Reverse Engineering and Patch Diffing Toolkit

---

## Overview

This project provides an automated toolkit for triaging CVEs from Microsoft Patch Tuesday, identifying updated binaries via KB file manifests, and using Ghidra + BinDiff to analyze binary differences. It consists of three main components:

1. **Patch Diffing Workflow** — Automated tools for CVE triage, KB file discovery, and binary diffing analysis.

2. **Ghidra Headless Batch Analyzer** — A containerized, headless batch analysis pipeline built around Ghidra 11.0.3. It automates importing Windows binaries, applying PDB symbols, running C++ class recovery and datatype enrichment scripts, and exporting results to BinExport format.

3. **MCP Servers** — Three Model Context Protocol servers for AI assistant integration:
   - **Patch Tuesday Triage** — CVE triage and KB file discovery
   - **BinDiff Analysis** — Cross-platform BinDiff analysis with automatic platform detection
   - **Ghidra MCP Bridge** — Direct Ghidra integration for interactive analysis

> **See [ghidra_headless_batch_analyzer_docker/README.md](ghidra_headless_batch_analyzer_docker/README.md) for detailed documentation on the Ghidra pipeline, including build instructions, usage, and technical issues encountered during development.**

---

## Components

### MCP Servers

| Server | Purpose |
|--------|---------|
| `mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py` | CVE triage, KB file discovery, IAT analysis, and PE index search |
| `mcp_server/bindiff_analysis/bindiff_analysis_mcp_server.py` | BinDiff headless analysis with cross-platform support (Windows/Linux) |
| `mcp_server/ghidra_mcp/bridge_mcp_ghidra.py` | Ghidra MCP bridge for direct Ghidra integration |

### Ghidra MCP Bridge Setup

The Ghidra MCP bridge is from [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp). To set up:

```bash
git clone https://github.com/bethington/ghidra-mcp
cd ghidra-mcp
docker build -t ghidra-mcp-headless:latest -f docker/Dockerfile .
```

**MCP Configuration:**
```json
{
  "ghidra-mcp": {
    "command": "python3",
    "args": ["path/to/bridge_mcp_ghidra.py", "--transport", "stdio", "--no-lazy"],
    "env": {
      "GHIDRA_DEBUGGER_URL": "http://127.0.0.1:8099",
      "GHIDRA_MCP_URL": "http://127.0.0.1:8089",
      "PYTHONIOENCODING": "utf-8"
    }
  }
}
```

> **Note:** For binding on 0.0.0.0, an `AUTH_TOKEN` variable is required (hardcoded in docker-compose and bridge script).

---

## Ghidra Scripts

Located in `ghidra_headless_batch_analyzer_docker/Scripts/`:

| Script | Purpose |
|--------|---------|
| `CppClassExtractor.py` | Recovers C++ class structure from MSVC-compiled binaries using decompiler output. Identifies vtables, constructors, and infers member fields from typed assignments. |
| `DatatypeMerger.py` | Backfills empty/undefined composite types by matching names against external `.gdt` archives (e.g., WDK type libraries). |
| `post_script_export_binexports.py` | Exports the current program to a `.BinExport` file for BinDiff analysis. |

**GDT Archives:**
- `wdk_full_26100.gdt` — Windows Driver Kit type definitions for Windows 26100
- `Windows_Driver_functons.gdt` — Windows driver function types

For detailed documentation on what each script does, see the [Ghidra pipeline README](ghidra_headless_batch_analyzer_docker/README.md#what-each-script-does).

---

## Setup

### Prerequisites

- **Ghidra 11.0.3 PUBLIC** — Download from [official release](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip)
- **BinExport extension** — Install via Ghidra File → Install Extensions
- **BinDiff** — Install from [zynamics](https://www.zynamics.com/bindiff.html)
- **Python 3.10+** with required packages
- **Docker** (for Ghidra headless pipeline)
- **LM Studio** running locally at `http://localhost:1234` (for PE index embedding, optional)

### Install Python Dependencies

```bash
pip install requests beautifulsoup4 pefile chromadb openai mcp
```

### MCP Client Configuration

```json
{
  "mcpServers": {
    "patch-tuesday": {
      "command": "python",
      "args": ["C:/path/to/patch_tuesday_poc_builder/mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py"],
      "env": {
        "BASE_DIR": "C:/path/to/patch_bins"
      }
    },
    "bindiff-analysis": {
      "command": "python",
      "args": ["C:/path/to/patch_tuesday_poc_builder/mcp_server/bindiff_analysis/bindiff_analysis_mcp_server.py"],
      "env": {
        "BINDIFF_PATH": "C:/path/to/bindiff.exe"
      }
    },
    "ghidra-mcp": {
      "command": "python",
      "args": ["C:/path/to/patch_tuesday_poc_builder/mcp_server/ghidra_mcp/bridge_mcp_ghidra.py", "--transport", "stdio", "--no-lazy"],
      "env": {
        "GHIDRA_MCP_URL": "http://127.0.0.1:8089",
        "PYTHONIOENCODING": "utf-8"
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

#### 1. Triage CVEs

```bash
python mcp_server/patch_tuesday_triage_analysis/fetch_patch_tuesday_interesting_vulns.py --month 2025-04
```

Or use the MCP tool `fetch_patch_tuesday_cves` to get high-exploitability CVEs (`Exploitation Detected` / `Exploitation More Likely`) with severity, CVSS score, and the KB number that patches them on 25H2.

#### 2. Discover Updated Binaries

Use the MCP tool `fetch_kb_updated_files`:
- Resolves the cumulative update KB from MSRC CVRF
- Downloads the file-version CSV from `support.microsoft.com/help/{KB}`
- Filters for x64 `.exe`/`.dll`/`.sys` files
- Diffs against the previous month's KB to find version-changed files only
- Enriches each entry with `FileDescription` from the local PE on disk
- Saves a CSV to `BASE_DIR/{month}_KB{kb}_11-25H2_updated_files.csv`

#### 3. Cross-Reference CVEs with Updated Binaries

Use the CVE list from step 1 and the file list from step 2 to identify which changed binaries are associated with high-exploitability vulnerabilities.

#### 4. Analyze with Ghidra Headless Pipeline

```bash
docker run --rm \
  -v /path/to/binaries:/input \
  -v /path/to/output:/output \
  -e GHIDRA_USER=$USER \
  ghidra-pipeline
```

This executes: PDB symbol application → auto-analysis → C++ class extraction → datatype merging → BinExport generation.

#### 5. Run BinDiff Analysis

Use the MCP tool `analyze_bindiff` with the generated `.BinExport` files:

```
analyze_bindiff(
  primary_bin="path/to/old_version.BinExport",
  secondary_bin="path/to/new_version.BinExport",
  output_csv=True,
  verbose=True
)
```

Output includes:
- `*_functions_similarity_stats.csv` — Function-level similarity and confidence scores
- `*.BinDiff` database — For visual inspection in BinDiff GUI

#### 6. Visual Inspection

Open the `.BinDiff` file in BinDiff GUI for detailed analysis of changed functions.

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

### BinDiff Analysis MCP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `BINDIFF_PATH` | *(auto-detected)* | Path to BinDiff executable. If not set, searches platform-specific default locations. |
| `OUTPUT_DIR` | *(same as primary_bin)* | Directory for output files |

### Ghidra MCP Bridge

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_URL` | `http://127.0.0.1:8089` | Ghidra MCP server URL |
| `GHIDRA_DEBUGGER_URL` | `http://127.0.0.1:8099` | Ghidra debugger URL |
| `AUTH_TOKEN` | *(hardcoded)* | Authentication token for remote access |
| `GHIDRA_MCP_LOG_LEVEL` | `INFO` | Logging level |

---

## Recommended Reading

The blog post **[CVE-2026-20820 writeup by CravateRouge](https://cravaterouge.com/articles/cve-2026-20820/)** is highly recommended. It demonstrates this exact workflow end-to-end and covers:

- How to use jsacco's Ghidra GDT for Windows kernel types (relevant to `DatatypeMerger.py`)
- C++ class recovery with `CppClassExtractor.py`
- Patch diffing methodology with BinDiff

---

## Project Structure

```
patch_tuesday_poc_builder/
├── README.md                                    # This file
├── ghidra_headless_batch_analyzer_docker/       # Containerized Ghidra pipeline
│   ├── README.md                                # Detailed pipeline documentation
│   ├── Dockerfile                               # Container build definition
│   ├── headless_analyze.py                      # Python entrypoint (pyhidra)
│   ├── Scripts/                                 # Ghidra analysis scripts
│   │   ├── CppClassExtractor.py                 # C++ class / vtable recovery
│   │   ├── DatatypeMerger.py                    # Empty composite backfill from .gdt
│   │   ├── post_script_export_binexports.py    # Export to BinExport
│   │   ├── Windows_Driver_functons.gdt          # Windows driver function types
│   │   └── wdk_full_26100.gdt                   # WDK data type archive
│   └── extensions/                              # BinExport extension
└── mcp_server/                                  # MCP servers
    ├── patch_tuesday_triage_analysis/
    │   ├── patch_tuesday_triage_analysis_mcp_server.py  # CVE triage & KB tools
    │   └── fetch_patch_tuesday_interesting_vulns.py     # CVE triage helpers
    ├── bindiff_analysis/
    │   └── bindiff_analysis_mcp_server.py       # BinDiff analysis (cross-platform)
    └── ghidra_mcp/
        ├── bridge_mcp_ghidra.py                 # Ghidra MCP bridge
        ├── docker-compose.yml                   # Ghidra MCP docker config
        └── README.md                            # Ghidra MCP setup docs
```

> **Note:** Ghidra 11.0.3 PUBLIC must be downloaded separately and placed in
> `ghidra_headless_batch_analyzer_docker/ghidra_11.0.3_PUBLIC/`.  
> Download: [ghidra_11.0.3_PUBLIC_20240410.zip](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip)

---

## License

This project is provided as-is for educational and research purposes.
