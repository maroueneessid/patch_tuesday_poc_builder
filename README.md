# Patch Diffing Workflow with Ghidra and BinDiff

## Setup

- Ghidra 11.0.3+
- BinExport extension compatible with your Ghidra version (install via File → Install Extensions)
- BinDiff
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — MCP server for Ghidra, enables AI-assisted reverse engineering via Claude

## Scripts

### `fetch_cve_related_pre_post_patch_binaries.py`

Downloads the patched and vulnerable Windows binaries for a given CVE directly from the Microsoft Symbol Server, using WinBIndex to resolve version metadata.

```bash
# CVE mode — auto-resolves component and patch month
python fetch_cve_related_pre_post_patch_binaries.py --cve CVE-2025-29824

# Manual mode
python fetch_cve_related_pre_post_patch_binaries.py --filename clfs.sys --patch-month 2025-04

# With options
python fetch_cve_related_pre_post_patch_binaries.py --cve CVE-2025-29824 --windows-version 11-23H2 --output-dir ./bins
```

### `bindiff_high_roi_to_csv.py`

Takes two `.BinExport` files, runs BinDiff headlessly, then queries the resulting `.BinDiff` SQLite database to extract functions with similarity < 1.0 (i.e. changed functions), sorted by similarity ascending. Outputs a CSV.

```bash
python bindiff_high_roi_to_csv.py <primary.BinExport> <secondary.BinExport>
```

Requires `bindiff` to be in your PATH (or update the path in the script).

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

1. Fetch pre/post-patch binaries with `fetch_cve_related_pre_post_patch_binaries.py`
2. Open each binary in Ghidra and run `full_script_suite.py` from the Script Manager
   - This extracts C++ classes, merges datatypes from open GDT archives, then exports `.BinExport`
3. Run `bindiff_high_roi_to_csv.py` on the two `.BinExport` files to get a ranked CSV of changed functions
4. Open the `.BinDiff` file in the BinDiff GUI for visual diffing
