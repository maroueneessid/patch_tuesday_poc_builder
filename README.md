# Patch Diffing Workflow with Ghidra and BinDiff

## Setup

- Ghidra 11.0.3+
- BinExport extension compatible with your Ghidra version (install via File → Install Extensions)
- BinDiff
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — MCP server for Ghidra, enables AI-assisted reverse engineering via Claude

---

## Scripts

### `mcp_server/fetch_cve_related_pre_post_patch_binaries.py`

Downloads the patched and vulnerable Windows binaries for a given CVE directly from the Microsoft Symbol Server, using WinBIndex to resolve version metadata.

```bash
# CVE mode — auto-resolves component and patch month
python mcp_server/fetch_cve_related_pre_post_patch_binaries.py --cve CVE-2025-29824

# Manual mode
python mcp_server/fetch_cve_related_pre_post_patch_binaries.py --filename clfs.sys --patch-month 2025-04

# With options
python mcp_server/fetch_cve_related_pre_post_patch_binaries.py --cve CVE-2025-29824 --windows-version 11-23H2 --output-dir ./bins
```

Options:
- `--cve` — CVE ID (auto-resolves component and patch month via MSRC API)
- `--filename` — Binary filename (e.g. `clfs.sys`); requires `--patch-month`
- `--patch-month` — Month as `YYYY-MM`
- `--windows-version` — Target Windows version (default: `11-24H2`)
- `--output-dir` — Directory to save binaries (default: current directory)

### `mcp_server/fetch_patch_tuesday_interesting_vulns.py`

Fetches CVEs from the Microsoft MSRC CVRF API filtered by high exploitability (Exploitation Detected or More Likely).

```bash
# Current month, text output
python mcp_server/fetch_patch_tuesday_interesting_vulns.py

# Specific month, CSV output
python mcp_server/fetch_patch_tuesday_interesting_vulns.py --month 2025-04 --format csv

# JSON output with optional Azure AD token for historical access
python mcp_server/fetch_patch_tuesday_interesting_vulns.py --month 2025-01 --format json --token <bearer_token>
```

Options:
- `--month / -m` — Month as `YYYY-MM` or `YYYY-Mon` (default: current month)
- `--format / -f` — Output format: `text`, `csv`, or `json` (default: `text`)
- `--token / -t` — Optional Azure AD bearer token (required for some historical months)

### `bindiff_high_roi_to_csv.py`

Takes two `.BinExport` files, runs BinDiff headlessly, then queries the resulting `.BinDiff` SQLite database to extract functions with similarity < 1.0 (i.e. changed functions), sorted by similarity ascending. Outputs a CSV.

```bash
python bindiff_high_roi_to_csv.py <primary.BinExport> <secondary.BinExport>
```

Requires `bindiff` to be in your PATH (or update the path in the script).

---

## MCP Server (`mcp_server/`)

`patch_tuesday_mcp_server.py` wraps the two fetch scripts above into a single [Model Context Protocol](https://modelcontextprotocol.io/) server, exposing the full Patch Tuesday triage and binary download workflow as tools to any MCP-compatible client.

### Running

```bash
python mcp_server/patch_tuesday_mcp_server.py [--base-dir ./patch_bins]
```

The server uses stdio transport. `--base-dir` sets where binaries are saved (default: `./patch_bins`); each CVE gets its own subdirectory: `{base_dir}/{CVE_ID}/`.

### Example MCP client config

```json
{
  "mcpServers": {
    "patch-tuesday": {
      "command": "python",
      "args": [
        "C:/path/to/patchDiffingNotes/mcp_server/patch_tuesday_mcp_server.py",
        "--base-dir", "C:/path/to/patch_bins"
      ]
    }
  }
}
```

### Exposed Tools

| Tool | Arguments | Returns |
|------|-----------|---------|
| `fetch_patch_tuesday_cves` | `month` (YYYY-MM), `api_token` (optional) | List of high-exploitability CVEs with severity, CVSS, exploitability |
| `download_patch_binaries` | `cve_id`, `filename` (optional), `windows_version` | Paths to patched and vulnerable binaries, version info |
| `list_component_mappings` | `tag_filter` (optional substring) | Known CVE tag → binary filename mappings |
| `list_iat` | `filename` (PE filename, no path) | IAT of a PE from System32/drivers with DLL descriptions |

---

## Ghidra Scripts (`ghidra_scripts/`)

These scripts are meant to be loaded and run from the **Ghidra Script Manager** (Window → Script Manager), not from the command line.

### `full_script_suite.py` — Orchestrator

Run this script to execute the full pipeline in the correct order:

1. `CppClassExtractor.py`
2. `DatatypeMerger.py`
3. `post_script_export_binexports.py`

Just run `full_script_suite.py` from the Script Manager and the other three scripts will be called in sequence.

---

### `CppClassExtractor.py`

Recovers C++ class structure from MSVC-compiled binaries using Ghidra's decompiler output. It:

- Enumerates MSVC-style backtick vtable symbols from the Symbol Tree
- Finds constructors and initializer methods per class and decompiles them
- Parses the decompiled C text to extract vtable stores and typed field assignments
- Builds vtable `StructureDataType`s, applies them at vtable addresses, and wires vptrs at the correct offsets into the class struct
- Applies any typed fields discovered from the decompiler output

### `DatatypeMerger.py`

Replaces empty/undefined composite types (structures and unions) in the current program's data type manager with matching non-empty definitions found in any currently open Ghidra data type archive (GDT).

This is particularly useful when combined with an external Windows kernel GDT — see the blog post below for details on jsacco's Ghidra GDT, which provides pre-built Windows type definitions that this script can pull in automatically.

### `post_script_export_binexports.py`

Exports the current program to a `.BinExport` file in the same directory as the binary, using the BinExport Ghidra extension. This is the last step before running BinDiff.

---

## Recommended Reading

The blog post **[CVE-2026-20820 writeup by CravateRouge](https://cravaterouge.com/articles/cve-2026-20820/)** is highly recommended. It demonstrates this exact workflow end-to-end and covers:

- How to use jsacco's Ghidra GDT for Windows kernel types (relevant to `DatatypeMerger.py`)
- C++ class recovery with `CppClassExtractor.py`
- Patch diffing methodology with BinDiff

---

## Workflow Summary

1. Triage Patch Tuesday CVEs with `mcp_server/fetch_patch_tuesday_interesting_vulns.py` (or via the MCP server)
2. Fetch pre/post-patch binaries with `mcp_server/fetch_cve_related_pre_post_patch_binaries.py` (or via the MCP server)
3. Open each binary in Ghidra and run `full_script_suite.py` from the Script Manager
   - This extracts C++ classes, merges datatypes from open GDT archives, then exports `.BinExport`
4. Run `bindiff_high_roi_to_csv.py` on the two `.BinExport` files to get a ranked CSV of changed functions
5. Open the `.BinDiff` file in the BinDiff GUI for visual diffing
