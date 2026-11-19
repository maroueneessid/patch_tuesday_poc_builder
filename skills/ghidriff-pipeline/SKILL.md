---
name: ghidriff-pipeline
description: >
  Mandatory end-to-end pipeline for Windows Patch Tuesday binary diffing using ghidriff
  (Docker) + ghidra-mcp analysis. Replaces the bindiff MCP workflow. Use whenever the user
  wants to diff patched vs vulnerable binaries, triage patch changes in Ghidra, or whenever
  ghidriff / "diff this binary pair" / patch-diff triage is mentioned. Enforces the
  workspace directory contract, the Ghidra version gate, ownership rules, exact docker
  invocations, and the stop-and-report rule for version/tooling incompatibilities
  (no monkey patching ever).
---

# Ghidriff Pipeline — diff → Ghidra MCP → findings

Replaces the bindiff MCP (that server is removed from active config). Patch-tuesday MCP,
ghidra-mcp, deepwiki, microsoft_learn stay enabled — they are the downstream consumers.

**Validated stack (2026-11-19):** ghidra-mcp pinned at Ghidra 12.0.3 (server jar runs as root)
↔ ghidriff running that same Ghidra, run `--user root`, default `VersionTrackingDiff` engine.
Full battery green on the CVE-2026-105501 MSI cluster.

## Workspace contract — works anywhere, nothing hardcoded

`<BASE>` is the workspace root. It is **auto-detected** (the pipeline scripts walk up from
their own location until they find it) or set explicitly via `DIFFING_BASE_DIR`:

```
<BASE>/
├── diffs/<CVE_CHAIN>/            2 binaries + 2 PDBs per cluster (versioned filenames)
├── ghidra_projects/              Ghidra projects — MCP server mounts it as /projects
├── Analysis/<CVE_CHAIN>/ghidriff/  ghidriff outputs (md/json/log/symbols/gzfs)
├── .ghidra_pin/<version>/        pinned Ghidra (auto-created from the MCP server's container)
├── cves_<YYYY_MMM>.md            triage step-1 output (root)
├── kb_files_<KB>.md              triage step-2 output (root)
└── cve_file_mapping.md           triage step-3 gate + download plan (root)
```

CVE dirs chain with underscores, no spaces/dashes inside names:
`CVE-2026-105501_CVE-2026-119398_CVE-2026-119892_CVE-2026-119903`.
Binary names keep `<module>_<full_version>` (`msi_10.0.26100.9711.dll`); old/vulnerable first everywhere.
If the repo containing `ghidriff/*.sh` sits elsewhere, run it with `DIFFING_BASE_DIR=/path/to/BASE`.

## Phase 0 — Version gate + pin (auto via scripts)

Ghidra versions must match **exactly (incl. patch version)** between the ghidra-mcp server
and the Ghidra that ghidriff runs with. All of this is automated:

```bash
# from the workspace (repo copy or any checkout of patch_tuesday_poc_builder)
ghidriff/install_pinned_ghidra.sh     # one-time: docker cp the SERVER's Ghidra into <BASE>/.ghidra_pin/<ver>
ghidriff/run_diff.sh --check-only ... # gate + staging check without launching anything
```

Manual check, if you ever need it:
```sh
docker exec ghidra_mcp-ghidra-mcp-1 sh -c "grep application.version /opt/ghidra/Ghidra/application.properties"   # server side
grep application.version <BASE>/.ghidra_pin/<ver>/Ghidra/application.properties                                  # pin side
```

Hard rule: on a mismatch **STOP and report** (state both versions, propose alignment via
`install_pinned_ghidra.sh` or a matching release download — never silently upgrade/downgrade,
never monkey-patch). Real failure text when versions mismatch (ghidriff 12.2 → server 12.0.3):
`ERROR ...: this file was created with a newer version of Ghidra, and can not be processed.`
The server side is the pinned, finicky one; ghidriff is the side that gets aligned.
If the server ever gets a newer Ghidra, re-run `install_pinned_ghidra.sh` to re-pin (the
version-stamped dir keeps old pins around).

Engine note: on pins ≤ 12.0.x the **default VersionTrackingDiff engine works** (and matches
better). 12.2-era unpinned images crash with
`AttributeError: ... no attribute 'DUMMY_MONITOR'` — a 12.2-side Java API removal; on 12.0.3
pins do NOT pass `--engine` (or use `--engine SimpleDiff` only as a stopgap).

Verify the server is up: `docker ps --filter name=ghidra_mcp` (container name overridable via
`GHIDRA_MCP_CONTAINER`).

## Phase 1 — Download + staging binaries

1. **Triage gate** (patcht-tuesday-triage-skill): `cves_<YYYY_MMM>.md`, `kb_files_<KB>.md`,
   `cve_file_mapping.md` must exist. Verify assumed baselines against WinBIndex — often one
   patch older than the table guess:
   `download_patch_binaries(filename, patch_month="YYYY-MM", windows_version="11-24H2")`
   returns the real `vulnerable_version`/`patched_version` pair (both + PDBs land in `diffs/` root).
2. Stage per cluster (relative to `<BASE>`; handles can linger from the patch-tuesday MCP —
   retry then copy):

```sh
mkdir -p "diffs/<CVE_CHAIN>"
mv diffs/<module>_<oldver> "diffs/<CVE_CHAIN>/" || { sleep 8; cp -f diffs/<module>_<oldver> "diffs/<CVE_CHAIN>/" && rm -f diffs/<module>_<oldver>; }
mv diffs/<module>_<oldver>.pdb "diffs/<CVE_CHAIN>/"
mv diffs/<module>_<newver>.dll "diffs/<CVE_CHAIN>/" ; mv diffs/<module>_<newver>.pdb "diffs/<CVE_CHAIN>/"
rm -f diffs/<duplicate root copies>    # verify with ls before deleting
ls -la "diffs/<CVE_CHAIN>/"            # 4 files expected
```

3. `[WinError 183]` mid-download = leftover state: delete stray root files it created and
   re-run the download once.

## Phase 2 — Run ghidriff

Primary: the repo's `ghidriff/run_diff.sh` (auto-detects BASE, auto-provisions the pin,
applies all flags, verifies ownership, prints the handoff):

```bash
# from any checkout of patch_tuesday_poc_builder
ghidriff/run_diff.sh [--check-only] <CVE_CHAIN> <PROJECT_NAME> <old_bin> <new_bin> [extra ghidriff args]
```

What it runs (for reference/debugging; `<BASE>` = workspace root, `<PIN>` = the version's
pin dir — resolved by the script):

```sh
MSYS_NO_PATHCONV=1 docker run -d --user root --name ghidriff_<short> \
  -v "<BASE>/diffs/<CVE_CHAIN>:/ghidriff_in" \
  -v "<BASE>/ghidra_projects:/ghidriff_projects" \
  -v "<BASE>/Analysis/<CVE_CHAIN>/ghidriff:/ghidriff_out" \
  -v "<PIN>:/ghidra_home" -e GHIDRA_INSTALL_DIR=/ghidra_home \
  -e PYTHONPATH=/home/vscode/.local/lib/python3.13/site-packages \
  ghcr.io/clearbluejar/ghidriff:latest \
  -o /ghidriff_out -p /ghidriff_projects -n <CVE>_<MODULE> \
  -s /ghidriff_out/symbols -g /ghidriff_out/gzfs \
  --log-path /ghidriff_out/ghidriff.log \
  /ghidriff_in/<module>_<oldver>.dll /ghidriff_in/<module>_<newver>.dll
```

Why each flag is mandatory:
- `MSYS_NO_PATHCONV=1` — Git Bash rewrites `/ghidriff_in/...` args into
  `C:/.../PortableGit/...` inside the container → `FileNotFoundError: Missing Bins`.
- `--user root` + PYTHONPATH override — the ghidra-mcp server runs as root and Ghidra
  rejects foreign-owned projects (`ghidra.util.NotOwnerException: Project is owned by
  vscode`); ghidriff's venv lives in `/home/vscode/.local`, invisible to root without it.
  After the run, `OWNER="root"` must appear in `project.prp` (run_diff.sh verifies).

Completion checks:

```sh
docker ps -a --filter name=ghidriff_<short> --format '{{.Status}}'    # want: Exited (0)
docker rm -f ghidriff_<short>                                         # after reviewing outputs
ls "<BASE>/Analysis/<CVE_CHAIN>/ghidriff/"    # <old>-<new>.ghidriff.md, ghidriff.log, gzfs/, json/, symbols/
ls "<BASE>/ghidra_projects/"                  # <CVE>_<MODULE>-<old>-<new>/
```

Project naming is deterministic: `<PROJECT_NAME>-<old_basename>-<new_basename>`.
~3.5 MB DLLs: analysis + VersionTrackingDiff ≈ 10–15 min. The `.md` is the triage input
(vulnerability-research-methodology: Tier 0 = the `Added` section, then name-scan /
surgical-change signals). The log **appends** across runs — always `tail` it.

**Project-reuse rule (before every rerun):** `setup_project()` REUSES an existing project;
one written by a different Ghidra version or owner cannot be reused → delete the old project
dir first (`run_diff.sh` does this). If deletion happened while the MCP jar had it open,
same-name recreation may hit a phantom `FileExistsError` → `close_project` on the MCP side,
or use a fresh `-n <CVE>_<MODULE>_<tag>` name.

## Phase 3 — Hand off to ghidra-mcp (VALIDATED end-to-end 2026-11-19)

1. `list_instances` / `connect_instance`. If another project is open server-side:
   `close_project` (the headless jar keeps one project).
2. Clear stale locks: `rm -f <BASE>/ghidra_projects/<PROJECT>-<old>-<new>/*.lock*` (run_diff.sh already does).
3. `open_project(path='/projects/<PROJECT>-<old>-<new>/<PROJECT>-<old>-<new>.gpr')` →
   `get_project_info` shows `file_count`/`program_count` (expect 2).
4. Load each program — path is a **DomainFile path** (project-internal, NOT filesystem):
   `load_program_from_project(path='/msi_10.0.26100.9711.dll-0c6d53')` → returns the display
   name. Program names = `<basename>-<first6_of_hash>`, stable per inputs; read from the
   ghidriff.log tail (`Program: ...-xxxxxx imported:`). `open_program` / `list_project_files`
   are GUI-only in this build — never use them headless.
5. After load, address programs by the plain filename the load returned
   (`program='msi_10.0.26100.9974.dll'`). Metadata's executable path `/ghidriff_in/<file>`
   proves provenance.

Validated battery (all green 2026-11-19):
- `get_metadata` — 5891 vs 6012 funcs; PDB symbols 70372 vs 71530.
- `search_functions('FindAndValidateContextFromCallerPID', program=patched)` → both class
  sites; same search on `program=old` → "No functions matching" (programmatic added-proof).
- `decompile_function(@1801c5364, program=patched)` → full PDB-named pseudocode
  (feature-gated fix, CWE-863/367 shape).
- `get_function_callers` → `Invoke @ 180153ee0` (dispatch path).

## Phase 4 — Findings

Write analysis into `<BASE>/Analysis/<CVE_CHAIN>/` per vulnerability-research-methodology
(`triage.md`, `coverage.md`, `func_*.md`, `chain_*.md`). The ghidriff `.md`/json are the
ranking inputs; ghidra-mcp tools provide the decompile/xref proof.

## Failure catalog

| Symptom | Cause | Action |
|---|---|---|
| `FileNotFoundError: Missing Bins` | MSYS path mangling | rerun with `MSYS_NO_PATHCONV=1` (run_diff.sh handles it) |
| `ModuleNotFoundError: No module named 'ghidriff'` | root run can't see vscode's venv | `-e PYTHONPATH=/home/vscode/.local/lib/python3.13/site-packages` |
| `NotOwnerException: Project is owned by vscode` | diff ran as default user | `--user root` (+PYTHONPATH); verify `OWNER="root"` in project.prp |
|jar errors too generic | jar logs detail server-side | `docker logs ghidra_mcp-ghidra-mcp-1 2>&1`, grep context around `Error` — real cause (version/owner) is there |
| `FileExistsError` recreating a deleted project dir | jar/mount caches the deleted dir | `close_project` → retry, else fresh `-n` project name |
| `AttributeError ... DUMMY_MONITOR` | default engine on 12.2-era image | pin ≤12.0.x (Phase 0); `--engine SimpleDiff` only as stopgap |
| `created with a newer version of Ghidra` on load | diff Ghidra > server Ghidra | **STOP, report both versions, align via install_pinned_ghidra.sh — never patch/downgrade silently** |
| `mv: ... Permission denied` normalizing docker cp output | cross-mount dir move on Docker Desktop | use `exec tar` stream → `docker cp` + `cp -a` fallback (install script does both) |
| `tar: not a tar archive` streaming from container | docker exec binary stream broken on the host | harmless — install script falls back to `docker cp` automatically |
| `list_project_files`/`open_program` GUI error | headless build | `open_project(.gpr)` + `load_program_from_project('/<name>')` |
| `Project is locked` / lock files remain | stale writer `.lock*` | `rm -f *.lock *.lock~` |
| `Device or resource busy` moving files | patch-tuesday MCP open handle | `sleep 8` retry → `cp -f` + `rm -f` fallback |
| download `[WinError 183]` mid-rename | leftover partial state | delete strays, re-download |
