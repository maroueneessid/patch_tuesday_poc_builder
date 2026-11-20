# Windows Internals RE & Patch Diffing Toolkit

AI-assisted toolkit for Microsoft Patch Tuesday analysis: CVE triage from MSRC, KB-driven
binary discovery, patched-vs-vulnerable **diffing with ghidriff**, decompile/xref analysis
through **Ghidra MCP**, and **Hyper-V/KDNET** dynamic validation for PoC work.

Streamlined 2026-11-19: the BinDiff MCP server and the legacy Ghidra 11.0.3 batch analyzer
were removed — ghidriff is the single diffing engine. The pipeline is validated end-to-end
on the CVE-2026-105501 Windows Installer EoP cluster, including the server handoff
(load → search → decompile → callers) and the downstream triage/decompile/xref battery.

## Pipeline at a glance

```
MSRC / WinBIndex (patch-tuesday MCP)          CVE triage + binary discovery + download
        ↓
ghidriff  (ghidriff/run_diff.sh)              PDB auto-download + full analysis + diff
        ↓  writes
<BASE>/ghidra_projects/  +  <BASE>/Analysis/<CVE-CHAIN>/ghidriff/
        ↓
ghidra-mcp bridge                             open_project → load_program → search/decompile/xref
        ↓
<BASE>/Analysis/<CVE-CHAIN>/                  findings per vulnerability-research-methodology
        ↓
hyperv-mcp + kd-mcp                           dynamic validation of PoC ideas on Win11Poc
```

Component inventory: `ghidriff/` (diffing scripts + README), `skills/` (five agent skills),
`mcp_server/` (patch-tuesday triage, ghidra-mcp bridge, hyperv-mcp, kd-mcp).
Removed: `bindiff_analysis` server, `ghidra_headless_batch_analyzer_docker`.
The removed components' scripts live in git history if ever needed again.

## Workspace contract — works anywhere

Everything derives from `<BASE>`, auto-detected by the scripts (walk-up from the script's
own directory) or set explicitly via `DIFFING_BASE_DIR`:

```
<BASE>/
├── diffs/<CVE_CHAIN>/                staged binaries: 2 versions + 2 PDBs, <module>_<version> names
├── ghidra_projects/                  Ghidra projects — the MCP server mounts this as /projects
├── Analysis/<CVE_CHAIN>/ghidriff/    outputs: .ghidriff.md/.json, ghidriff.log, gzfs/, symbols/
├── .ghidra_pin/<version>/            pinned Ghidra (auto-created from the MCP server's container)
├── cves_<YYYY_MMM>.md                triage outputs (root)
├── kb_files_<KB>.md                  KB file manifest + cve_file_mapping.md (root)
└── fix_ownership.ps1                 workspace helper
```

CVE dirs chain with underscores (`CVE-A_CVE-B_CVE-C`); binaries keep `<module>_<version>`
names; **old/vulnerable version listed first everywhere**.

## Setup — pragmatic steps

1. **Docker Desktop** running (the only hard prerequisite for the containers).
2. **Start the ghidra-mcp headless server** — image `ghidra-mcp-headless:latest`:

```bash
git clone https://github.com/bethington/ghidra-mcp /tmp/ghidra-mcp
cd /tmp/ghidra-mcp && git checkout a97aa975c85af7ce1c37c5bb619a50e248ca05c8
docker build -t ghidra-mcp-headless:latest -f docker/Dockerfile .
```

   Wire the volumes with this repo's compose (`mcp_server/ghidra_mcp/docker-compose.yml`)
   — it interpolates `${DIFFING_BASE_DIR}` with this machine's default baked in:

```bash
DIFFING_BASE_DIR=/path/to/your/<BASE> docker compose -f mcp_server/ghidra_mcp/docker-compose.yml up -d
```

3. **Patch-tuesday MCP** in the agent's client config:

```json
"patch-tuesday": {
  "command": "python",
  "args": ["<repo>/mcp_server/patch_tuesday_triage_analysis/patch_tuesday_triage_analysis_mcp_server.py"],
  "env": { "BASE_DIR": "<BASE>/diffs" }
},
"ghidra-mcp": {
  "command": "python",
  "args": ["<repo>/mcp_server/ghidra_mcp/bridge_mcp_ghidra.py", "--transport", "stdio", "--no-lazy"],
  "env": {
    "GHIDRA_MCP_URL": "http://127.0.0.1:8089",
    "GHIDRA_DEBUGGER_URL": "http://127.0.0.1:8099",
    "PYTHONIOENCODING": "utf-8"
  }
}
```

4. **ghidriff** (no other install — one image pull):

```bash
docker pull ghcr.io/clearbluejar/ghidriff:latest
./ghidriff/install_pinned_ghidra.sh      # one-time: pins the server's exact Ghidra into <BASE>/.ghidra_pin/<ver>
```

5. **Deploy the agent skills** — copy `skills/*` next to your agent's skill directory
   (project `.agents/skills/` or global `~/.agents/skills/`). They are the operational
   manual: `ghidriff-pipeline` (master workflow), `ghidra-mcp` (server usage),
   `vulnerability-research-methodology`, `patcht-tuesday-triage-skill`,
   `hyperv-kdnet-kd-mcp` (dynamic testing).

Python deps for the MCP servers (host side): `pip install requests beautifulsoup4 pefile chromadb openai mcp`.
Optional: LM Studio at `http://localhost:1234` for PE-index embedding.

## Quick start — one CVE cluster, end to end

1. Triage gates: write `cves_<YYYY_MMM>.md`, `kb_files_<KB>.md`, `cve_file_mapping.md`
   (tools `fetch_patch_tuesday_cves` / `fetch_kb_updated_files`; rules in the triage skill).
2. `download_patch_binaries(filename, patch_month, windows_version)` → land in `<BASE>/diffs/`
   root; move both pairs per cluster into `diffs/<CVE_CHAIN>/` (WinBIndex tells you the REAL
   vulnerable baseline — trust it over table guesses).
3. `ghidriff/run_diff.sh --check-only <CVE_CHAIN> <PROJECT_NAME> <old_bin> <new_bin>`
    (gates + staging rehearsal, launches nothing), then drop `--check-only` for the run.
4. Follow the printed handoff:
   `open_project('/projects/<proj>/<proj>.gpr')` →
   `load_program_from_project('/<name>-<hash6>')` → query tools with `program='<filename>'`.
5. Triage the `.ghidriff.md` / `json/*.ghidriff.json` per `vulnerability-research-methodology`
   (Tier 0 = the Added section); write findings into `<BASE>/Analysis/<CVE_CHAIN>/`.
6. When a PoC needs a live machine: hyperv/kd per `hyperv-kdnet-kd-mcp`.

## Environment variables

| Variable | Where | Purpose |
|---|---|---|
| `DIFFING_BASE_DIR` | run_diff.sh / install script / compose | workspace root; auto-detected otherwise |
| `GHIDRA_PIN_DIR` | run_diff.sh | explicit pinned-Ghidra override (default `<BASE>/.ghidra_pin/<ver>`) |
| `GHIDRA_MCP_CONTAINER` | scripts | server container name (default `ghidra_mcp-ghidra-mcp-1`) |
| `GHIDRIFF_IMAGE` / `GHIDRIFF_TIMEOUT_SEC` | run_diff.sh | image / completion timeout (default 3600) |
| `GHIDRA_MCP_PORT` / `GHIDRA_MCP_AUTH_TOKEN` / `JAVA_OPTS` | compose | server wiring |
| `BASE_DIR` | patch-tuesday MCP | `<BASE>/diffs` (KB CSVs + downloads land here) |

## Gotchas — (deliberately short; the scripts absorb the rest)

- **Version gate / ownership gate stop = informational**: `run_diff.sh` self-heals pin
  provisioning; a hard stop only fires when the *server* side changed meaningfully — follow
  the printed guidance and re-run `install_pinned_ghidra.sh`. Never monkey-patch either side.
- **The patch-tuesday MCP keeps file handles open** after downloads: a `Device or resource
  busy` move → `sleep 8` retry, then `cp -f` + `rm -f` fallback. Root fix still pending
  (see TODOs).
- `ghidriff.log` **appends** across runs — always read its tail.
- The MCP jar holds **one project open** — `close_project` before pointing it at another
  diff project.

## Remaining TODOs

- Per-binary PDB fallback download via `symchk` in the patch-tuesday MCP (only if WinBIndex
  misses a file).
- Root-fix the lingering handle release in the patch-tuesday MCP downloader.
- Multi-instance ghidra-mcp for parallel agents — one headless jar serves one open project,
  so this means N containers + N bridges on N ports.

## Recommended reading

[CravateRouge's CVE-2026-20820 writeup](https://cravaterouge.com/articles/cve-2026-20820/) —
end-to-end demo of the same methodology (the class-recovery / GDT-typing pieces it describes
map to the removed legacy scripts, both recoverable from git history; PDB symbol application
is now automatic inside ghidriff).
