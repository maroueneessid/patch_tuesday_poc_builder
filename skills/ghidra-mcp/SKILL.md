---
name: ghidra-mcp
description: |-
  Skill for interacting with bethington/ghidra-mcp running as a headless Docker container.
  Use this skill whenever the user asks to analyze a binary in Ghidra, decompile functions,
  list functions, rename symbols, create structs, run Ghidra scripts, do cross-binary
  documentation transfer, or any reverse engineering task involving Ghidra MCP tools.
  Also use when the user mentions Ghidra projects, .gpr files, or references binaries
  that should be analyzed with Ghidra. Covers docker path mapping rules and validated
  headless-mode specifics for opening and analyzing ghidriff-generated diff projects.
disable-model-invocation: false
---

# Ghidra MCP — Usage Skill

## Initialization — Always First

Call `connect_instance` before any other Ghidra MCP tool in every session. No exceptions.

---

## Path Mapping (Docker Container)

The host filesystem and container filesystem are **not the same**.

Volume mount layout:
```
/host/path/to/ghidra_projects  →  /projects
/host/path/to/diffs            →  /diffs
```

### Rules

1. **Never use host paths** in tool parameters. All paths must be container-relative.
2. **Project paths**: `/projects/<ProjectName>/<ProjectName>.gpr`
3. **Binary imports**: `/diffs/<path_to_binary>`
4. **Program name** (`program=` parameter): just the filename, not the full path. E.g. `ole32_10.0.26100.7920.dll`
5. If the user gives a host path, silently convert it. Convert backslashes to forward slashes.

### Conversion Examples

| User says | Tool receives |
|-----------|---------------|
| `C:\Users\...\ghidra_projects\PatchDiff\clfs.sys` | `/projects/PatchDiff/clfs.sys` |
| `ghidra_projects\April2026\ntdll.dll` | `/projects/April2026/ntdll.dll` |
| "the ntdll project" | `/projects/ntdll/` |
| `/projects/MyProj/target.exe` | `/projects/MyProj/target.exe` |
| "import the binary from diffs" | `/diffs/<binary_name>` |

---

## Headless Mode — Validated Specifics (2026-11-19, Ghidra 12.0.3 server)

The headless jar does not run the Ghidra GUI (`PluginTool` unavailable). Several tools
that exist in the full toolset are **GUI-only and will error** — use the headless
alternatives:

| GUI-only (avoid headless) | Headless alternative |
|---|---|
| `open_program(path)` | `open_project('<gpr path>')` then `load_program_from_project(...)` |
| `list_project_files(folder)` | `get_project_info` (gives counts) + read `ghidriff.log` for program names |
| `list_scripts` / script runner | runs but reports GUI requirement; do not rely on it headless |

### Opening a project headless

1. `open_project(path='/projects/<ProjectName>/<ProjectName>.gpr')` → `{"success": true}`.
   The headless jar keeps **one project open at a time** — call `close_project` first if
   another project is open (also flushes stale in-memory state).
2. Load programs with `load_program_from_project(path='/<DomainFileName>')` — the path is a
   **project-internal DomainFile path** (relative to the project root), NOT a filesystem path.
3. After load, query tools address the program by the **display name returned by the load
   call** (plain filename, e.g. `msi_10.0.26100.9974.dll`) — pass it as `program=` ever after.

### Failure modes (validated)

- **Generic `Failed to load program: ...`** — the jar hides the cause. Diagnose from the
  server-side log: `docker logs ghidra_mcp-ghidra-mcp-1 2>&1` and grep with context around
  `ERROR`/`Exception`. Real causes are version mismatch (`created with a newer version of
  Ghidra`) or ownership (`ghidra.util.NotOwnerException: Project is owned by vscode`).
- **Stale `.lock` / `.lock~` files** — a writer (e.g. ghidriff) leaves them; `open_project`
  refuses while they exist. Clear them on the host first (`rm -f *.lock *.lock~`).
- **Project ownership** — the server runs as `root` inside the container; a project written
  by another container user is rejected. In this workspace ghidriff must run with
  `--user root` (see the `ghidriff-pipeline` skill — it covers this end to end).
- **Version gate** — DomainFiles written by a *newer* Ghidra than the server cannot be
  opened (`created with a newer version of Ghidra, and can not be processed`). Ghidra 12.0.3
  (server) reads older projects fine. The diff side must be pinned to the server's Ghidra —
  enforced by the `ghidriff-pipeline` skill Phase 0 gate. **Stop and report on mismatch; never
  monkey-patch.**

### Validated battery (ghidriff-written diff projects)

`get_metadata(program=...)` → `search_functions(pattern, program=...)` →
`decompile_function(addr, program=...)` → `get_function_callers` / `get_xrefs_to` —
all addressable by plain filename with `program=`, no re-analysis needed (ghidriff already
analyzed + applied PDB symbols). Executable path in metadata reads `/ghidriff_in/<file>` —
this proves the program came from the diff pipeline.

Full pipeline (download → ghidriff diff → Ghidra MCP analysis → findings) lives in the
`ghidriff-pipeline` skill.
