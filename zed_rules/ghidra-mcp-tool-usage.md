---
name: ghidra-mcp
description: >
  Skill for interacting with bethington/ghidra-mcp running as a headless Docker container.
  Use this skill whenever the user asks to analyze a binary in Ghidra, decompile functions,
  list functions, rename symbols, create structs, run Ghidra scripts, do cross-binary
  documentation transfer, or any reverse engineering task involving Ghidra MCP tools.
  Also use when the user mentions Ghidra projects, .gpr files, or references binaries
  that should be analyzed with Ghidra. This skill is critical for getting the initialization
  sequence right and for correct file path handling — the Ghidra MCP server runs inside a
  Docker container with different mount points than the host.
---

# Ghidra MCP — Complete Usage Skill

## Path Mapping (Docker Container)

**The host filesystem and the container filesystem are different.**

The Docker volume mount maps host directories into the container:

```yaml
volumes:
  - /host/path/to/ghidra_projects:/projects
  - /host/path/to/diffs:/diffs
```

### Rules

1. **NEVER use host paths** (like `C:\Users\...` or `/home/user/...`) when calling any Ghidra MCP tool. All paths must be **container-relative**.

2. **Project paths** follow: `/projects/<ProjectName>/<ProjectName>.gpr`

3. **Binary paths** for import follow: `/diffs/<path_to_binary>`

4. If the user provides a host path, **silently convert it** to the container path. Convert backslashes to forward slashes.

5. **Program names** in the `program=` parameter use just the filename (e.g., `ole32_10.0.26100.7920.dll`), NOT the full path.

### Path Conversion Examples

| User says | Tool receives |
|-----------|---------------|
| `C:\Users\User\Desktop\DiffingBaseDir\ghidra_projects\PatchDiff\clfs.sys` | `/projects/PatchDiff/clfs.sys` |
| `ghidra_projects\April2026\ntdll.dll` | `/projects/April2026/ntdll.dll` |
| "the ntdll project" | `/projects/ntdll/` (infer) |
| `/projects/MyProj/target.exe` | `/projects/MyProj/target.exe` (already correct) |
| "import the binary from diffs" | `/diffs/<binary_name>` |

### Initial Usage

1. Alway use the `connect_instance` tool call at the very beginning

