# AI Assistance in Windows Internals Reverse Engineering and Patch Diffing Toolkit

---

## Overview

This project provides an automated toolkit for triaging CVEs from Microsoft Patch Tuesday, identifying updated binaries via KB file manifests, and diffing patched vs vulnerable binaries with ghidriff + Ghidra MCP. It consists of these main components:

1. **Patch Diffing Workflow** — Automated tools for CVE triage, KB file discovery, and binary diffing analysis.

2. **Ghidra Headless Batch Analyzer** — A containerized, headless batch analysis pipeline built around Ghidra 11.0.3. It automates importing Windows binaries, applying PDB symbols, running C++ class recovery and datatype enrichment scripts, and exporting results to BinExport format. (Legacy — superseded by the ghidriff pipeline.)

3. **MCP Servers** — Model Context Protocol servers for AI assistant integration:
   - **Patch Tuesday Triage** — CVE triage and KB file discovery
   - **Ghidra MCP Bridge** — Direct Ghidra integration for interactive analysis (pinned Ghidra 12.0.3 headless)
   - **Hyper-V + KD (dynamic testing)** — guest VM file transfer / lowpriv execution and KDNET kernel debugging for PoC validation

4. **Ghidriff Diffing** — Dockerized patched-vs-vulnerable binary diffing with automatic PDB download. Pinned to the ghidra-mcp server's exact Ghidra (12.0.3) and projects its outputs directly into the server's `/projects` mount, so diff artifacts are immediately analyzable by the bridge. **Currently the active diffing path.**

Validated end-to-end pipeline (2026-11-19):
```
MSRC/WinBIndex (patch-tuesday MCP)  →  ghidriff (pinned Ghidra 12.0.3, --user root)
→ ghidra_projects/ → ghidra-mcp bridge (load + decompile + xrefs)
→ Analysis/<CVE-CHAIN>/ findings  →  Hyper-V/KDNET dynamic validation of PoC ideas
```

> **See [ghidra_headless_batch_analyzer_docker/README.md](ghidra_headless_batch_analyzer_docker/README.md) for detailed documentation on the Ghidra pipeline, including build instructions, usage, and technical issues encountered during development.**

---

## Components

### MCP Servers

| Server | Purpose |
|--------|---------|
| `mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py` | CVE triage, KB file discovery, IAT analysis, and PE index search |
| `mcp_server/ghidra_mcp/bridge_mcp_ghidra.py` | Ghidra MCP bridge for direct Ghidra integration (pinned headless server, Ghidra 12.0.3) |
| `mcp_server/hyperv-mcp/` | Hyper-V guest ops: file transfer, lowpriv command execution, KDNET config, checkpoints |
| `mcp_server/kd-mcp/` | KDNET kernel debugging bridge (break/regs/stack/memory/breakpoints) against the Win11Poc VM |

The former bindiff-analysis server has been **removed** (code and config) — ghidriff
replaces it end to end; see the [Ghidriff pipeline](ghidriff/README.md) and the
[`skills/ghidriff-pipeline`](skills/ghidriff-pipeline/SKILL.md) skill.

> Working copy of the pipeline: `ghidriff/` (scripts + README) plus the current agent
> skills in `skills/` — `ghidriff-pipeline` is the authoritative step-by-step workflow
> (version gate, ownership gate, exact invocations, failure catalog).

### Ghidra MCP Bridge Setup

The Ghidra MCP bridge is from [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp). To set up:

```bash
git clone https://github.com/bethington/ghidra-mcp
git checkout a97aa975c85af7ce1c37c5bb619a50e248ca05c8
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

## Ghidriff Pipeline (validated 2026-11-19)

Static diffing of patched vs vulnerable binaries. See `ghidriff/README.md` for install and
[`skills/ghidriff-pipeline/SKILL.md`](skills/ghidriff-pipeline/SKILL.md) for the full workflow.
All paths derive from the workspace root (auto-detected; `DIFFING_BASE_DIR` override) —
nothing is hardcoded to a machine.

```bash
# one-time pin: streams the server's own Ghidra into <BASE>/.ghidra_pin/<version>
./ghidriff/install_pinned_ghidra.sh
# gates + staging rehearsal only (no run)
./ghidriff/run_diff.sh --check-only <CVE_CHAIN> <PROJECT_NAME> <old_bin> <new_bin>
# diff (runs all gates, verifies ownership, prints the ghidra-mcp handoff)
./ghidriff/run_diff.sh <CVE_CHAIN> <PROJECT_NAME> <old_bin> <new_bin>
```

Hard rules baked into the tooling:
- **Version gate** — ghidriff must run the SAME Ghidra (incl. patch version) as the
  ghidra-mcp server; the server side is never casually touched. Mismatch → stop and report.
- **Ownership gate** — diff runs are `--user root` so Ghidra projects match the server user
  (otherwise `NotOwnerException`).
- **No monkey patching** — on version/tooling incompatibilities, stop and report; align
  versions instead. On a 12.0.3 pin the default `VersionTrackingDiff` engine works.

### Dynamic testing layer (Hyper-V + KDNET)

`mcp_server/hyperv-mcp/` and `mcp_server/kd-mcp/` provide guest-side and kernel-side live
testing for PoC development: stage files into the Win11Poc guest, execute as the lowpriv
user (`hyperv_victim_run*`), snapshot/restore checkpoints, then attach KDNET and inspect
kernel state. Setup + validated workflow: [`skills/hyperv-kdnet-kd-mcp/SKILL.md`](skills/hyperv-kdnet-kd-mcp/SKILL.md)
(hard rules: elevation required, kill zombie kd + restart kd-mcp if the port is taken,
**never retarget KDNet unprompted**; working connect string is recorded in the skill).

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

- **Docker Desktop** — runs the ghidra-mcp headless server + ghidriff (pinned Ghidra provisioned into the workspace by `ghidriff/install_pinned_ghidra.sh`)
- **Python 3.10+** with required packages
- **LM Studio** running locally at `http://localhost:1234` (for PE index embedding, optional)
- Legacy batch analyzer only (optional): Ghidra 11.0.3 PUBLIC — [official release](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip)

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
    "ghidra-mcp": {
      "command": "python",
      "args": ["C:/path/to/patch_tuesday_poc_builder/mcp_server/ghidra_mcp/bridge_mcp_ghidra.py", "--transport", "stdio", "--no-lazy"],
      "env": {
        "GHIDRA_MCP_URL": "http://127.0.0.1:8089",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
```

> **Note:** ghidriff (the diffing engine) is not an MCP server — it is invoked via
> `ghidriff/run_diff.sh`; no client config entry is needed for it.

### Ghidra Headless Pipeline Setup

See the [Ghidra pipeline README](ghidra_headless_batch_analyzer_docker/README.md) for:
- Docker build instructions
- Native (non-Docker) usage
- Environment variables
- Troubleshooting technical issues

---

## Usage

> **The current diffing workflow is the ghidriff pipeline (previous section).** The numbered
> steps below are the legacy BinExport/BinDiff flow via `ghidra_headless_batch_analyzer_docker`
> + the retired bindiff-analysis server — kept for reference only.

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
  ghidra-pipeline your_project_name
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

### BinDiff Analysis MCP Server — REMOVED

Removed from the toolkit (ghidriff replaced it; see the Ghidriff Pipeline section).

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
├── ghidriff/                                    # ACTIVE diffing workflow (ghidriff)
│   ├── README.md                                # workspace contract, pinning rules, gotchas
│   ├── install_pinned_ghidra.sh                 # pin server Ghidra into <BASE>/.ghidra_pin/<ver>
│   └── run_diff.sh                              # validated diff run (gates + handoff, --check-only)
├── skills/                                      # agent skills synced with live workspace copies
│   ├── ghidriff-pipeline/SKILL.md               # end-to-end pipeline (validated 2026-11-19)
│   ├── ghidra-mcp/SKILL.md                      # headless server usage + validated specifics
│   ├── hyperv-kdnet-kd-mcp/SKILL.md             # Hyper-V + KDNET dynamic testing (+ scripts/)
│   ├── patcht-tuesday-triage-skill/SKILL.md     # Patch Tuesday triage workflow
│   └── vulnerability-research-methodology/SKILL.md
├── ghidra_headless_batch_analyzer_docker/       # Legacy containerized Ghidra 11.0.3 pipeline
│   ├── README.md  Dockerfile  headless_analyze.py
│   ├── Scripts/                                 # CppClassExtractor, DatatypeMerger, BinExport export
│   └── extensions/                              # BinExport extension
└── mcp_server/                                  # MCP servers
    ├── patch_tuesday_triage_analysis/           # CVE triage & KB tools (active)
    ├── ghidra_mcp/                              # bridge + docker-compose (pinned headless server)
    ├── hyperv-mcp/                              # Hyper-V guest ops (dynamic testing)
    ├── kd-mcp/                                  # KDNET kernel debugging (dynamic testing)
    └── ghidra_mcp/                              # bridge + docker-compose (pinned headless server)
```

> **Note:** Ghidra 11.0.3 PUBLIC (legacy batch analyzer) must be downloaded separately and
> placed in `ghidra_headless_batch_analyzer_docker/ghidra_11.0.3_PUBLIC/`.
> The ghidriff Ghidra pin is workspace-local (`<BASE>/.ghidra_pin/<version>/`), generated by
> `install_pinned_ghidra.sh` from the running ghidra-mcp container — never committed.

---
## TO DOs

- Add individual PDB download to the patch_tuesday mcp server . Use `symchk` against individual binary. (in case false download)
- ~~Find a the most stable and working verion of [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) and pin in this project.~~ **Resolved 2026-11-19:** server pinned at Ghidra 12.0.3; the whole pipeline validated against it (`skills/ghidriff-pipeline`), ghidriff side pinned to the same version via `ghidriff/install_pinned_ghidra.sh`.
- ~~Configure [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) into a docker container but with Multi instance ghidra (to use multiple agent on different ghidra project simultaneously).~~ Single instance running; multi-instance still open (note: headless jar holds one project at a time per server — would need N containers + N bridges).
- ~~Add finding unmatched functions between diffs not only similarities between functions in the Bindiff analysis mcp.~~ **Resolved 2026-11-19:** ghidriff reports added (unmatched-new) / deleted (unmatched-old) functions alongside matches (`added_funcs/deleted_funcs/unmatched_funcs` in the .ghidriff.md / json).
- ~~in `patch_tuesday_mcp`, figure out why the handle of last downloaded binaries isn't released~~ **Diagnosed 2026-11-19 (workaround documented):** lingering open handles cause `Device or resource busy` on move/delete; workaround `sleep 8` retry → `cp -f` + `rm -f` fallback (skills/ghidriff-pipeline failure catalog). Root cause in the server code still worth fixing.
- Migrate the legacy BinDiff headless batch pipeline docs (`ghidra_headless_batch_analyzer_docker/`) to reference the ghidriff flow where relevant (BinExport export remains useful for GUI review).
