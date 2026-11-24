# Ghidriff — patched vs vulnerable binary diffing

Ghidriff replaces the BinDiff MCP workflow as the static diffing engine of the toolkit
(that server has been removed). Validated end-to-end on 2026-11-19 (CVE-2026-105501
Windows Installer cluster, EoP) including the handoff into the ghidra-mcp server and the
downstream triage / decompile / xref battery. The authoritative workflow:
[`skills/ghidriff-pipeline/SKILL.md`](../skills/ghidriff-pipeline/SKILL.md).

## Workspace contract — runs anywhere

Everything is derived from the workspace root `<BASE>` (auto-detected by walking up from
the script's own directory, overridable with `DIFFING_BASE_DIR`):

```
<BASE>/
├── diffs/<CVE_CHAIN>/            staged binaries: 2 versions + 2 PDBs, <module>_<version> names
├── ghidra_projects/              Ghidra projects — the MCP server mounts this as /projects
├── Analysis/<CVE_CHAIN>/ghidriff/  outputs: .ghidriff.md/.json, ghidriff.log, gzfs/, symbols/
└── .ghidra_pin/<version>/        pinned Ghidra, extracted from the MCP server's container
```

No absolute machine paths are baked into the tooling. If the repo sits outside `<BASE>`,
set `DIFFING_BASE_DIR` and run it from there.

## Components

| File | Purpose |
|---|---|
| `install_pinned_ghidra.sh` | One-time: reads the ghidra-mcp server's Ghidra version, streams its install to `<BASE>/.ghidra_pin/<version>/` (tar stream → `docker cp` fallback). Idempotent; refuses version mismatches. |
| `run_diff.sh` | Validated diff run with every gotcha baked in: version gate, auto pin provisioning, staging checks, `MSYS_NO_PATHCONV=1`, `--user root` + PYTHONPATH, pinned `GHIDRA_INSTALL_DIR`, detached run + polling, `OWNER="root"` verification, lock cleanup, ghidra-mcp handoff printed at the end. `--check-only` runs just the gates. |

## Install

```bash
docker pull ghcr.io/clearbluejar/ghidriff:latest      # bundled Ghidra + Java, nothing else needed
./ghidriff/install_pinned_ghidra.sh                   # one-time, ~850MB into <BASE>/.ghidra_pin/<ver>
```

## Version pinning — the rules

- The **ghidra-mcp server is the pinned side** (Ghidra 12.0.3 in-image at `/opt/ghidra`).
  It is version-finicky by design — do not casually rebuild/upgrade it.
- Ghidriff's released image ships a **newer** Ghidra (12.2 as of 2026-11-19). Unpinned runs
  produce projects the server cannot open
  (`created with a newer version of Ghidra, and can not be processed`).
- `run_diff.sh` resolves the pin automatically: `GHIDRA_PIN_DIR` env →
  `<BASE>/.ghidra_pin/<server_version>` → auto-provisions it via `install_pinned_ghidra.sh`.
  The version-stamped directory means several pins can coexist while aligning versions.
- On a ≤ 12.0.x pin the **default `VersionTrackingDiff` engine works** (better matching than
  SimpleDiff). Only 12.2-era unpinned images need `--engine SimpleDiff`
  (`DUMMY_MONITOR` AttributeError is a 12.2-side removal).

## Why `--user root`

The ghidra-mcp server runs as `root`; Ghidra rejects foreign-owned projects
(`ghidra.util.NotOwnerException: Project is owned by vscode`). Ghidriff's image runs as
`vscode` with its venv in `/home/vscode/.local`, so the run adds `--user root` and
`PYTHONPATH=/home/vscode/.local/lib/python3.13/site-packages`. Every run is verified
afterwards: `OWNER="root"` must appear in `ghidra_projects/<project>/<project>.rep/project.prp`.

## Quick start

```bash
# 0. (optional) gate + staging rehearsal, launches nothing
./ghidriff/run_diff.sh --check-only <CVE_CHAIN> <PROJECT_NAME> <old_bin> <new_bin>
# 1. stage binaries (patch-tuesday MCP downloads land in <BASE>/diffs/; move into <CVE_CHAIN>/)
# 2. diff
./ghidriff/run_diff.sh <CVE_CHAIN> <PROJECT_NAME> <old_bin> <new_bin>
# 3. follow the printed handoff: open_project → load_program_from_project → program= queries
```

Env knobs: `DIFFING_BASE_DIR` (workspace root), `GHIDRA_PIN_DIR` (explicit pin override),
`GHIDRA_MCP_CONTAINER`, `GHIDRIFF_IMAGE`, `GHIDRIFF_TIMEOUT_SEC` (default 3600).

## Known gotchas (full catalog in the pipeline skill)

- Git Bash rewrites container paths → `MSYS_NO_PATHCONV=1` mandatory (handled in the script).
- The ghidriff log **appends** across runs — always `tail` it.
- Rerunning against an existing project dir requires same Ghidra version + owner; the script
  deletes the dir to force a clean run (projects are regenerable in minutes).
- `docker exec` binary streams can be mangled on some Docker Desktop hosts — the install
  script detects this and falls back to `docker cp` + normalization automatically.
- Never patch ghidriff or the MCP server to force compatibility — stop and align versions
  instead (user rule).
