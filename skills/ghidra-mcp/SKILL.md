---
name: ghidra-mcp
description: |-
  Skill for interacting with bethington/ghidra-mcp running as a headless Docker container.
    Use whenever the user asks to analyze a binary in Ghidra, decompile functions, list
    functions, rename symbols, create structs, run scripts, do cross-binary documentation
    transfer, or any reverse engineering task involving Ghidra MCP tools. Also use when
    the user mentions Ghidra projects, .gpr files, or references binaries to analyze.
    This skill is critical for getting the initialization sequence right and for correct
    file path handling — the Ghidra MCP server runs inside a Docker container with
    different mount points than the host.
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
3. **Binary imports**: `/diffs/<binary_filename>`
4. **Program name** (`program=` parameter): just the filename, not the full path. E.g. `ole32_10.0.26100.7920.dll`
5. If the user gives a host path, silently convert it. Convert backslashes to forward slashes.

### Conversion Examples

| User says | Tool receives |
|-----------|---------------|
| `C:\Users\User\Desktop\DiffingBaseDir\ghidra_projects\PatchDiff\clfs.sys` | `/projects/PatchDiff/clfs.sys` |
| `ghidra_projects\April2026\ntdll.dll` | `/projects/April2026/ntdll.dll` |
| "the ntdll project" | `/projects/ntdll/` |
| `/projects/MyProj/target.exe` | `/projects/MyProj/target.exe` |
| "import the binary from diffs" | `/diffs/<binary_name>` |
