# Ghidra Headless Analysis Pipeline

A containerized, headless batch analysis pipeline built around [Ghidra](https://ghidra-sre.org/) 11.0.3. It automates importing Windows binaries (`.exe`, `.dll`, `.sys`, etc.), applying PDB symbols, running C++ class recovery and datatype enrichment scripts, and exporting results to BinExport format — all without opening the GUI.

---

## What It Does

Given a directory of binaries (and optional co-located `.pdb` files), the pipeline:

1. **Imports & Analyzes** each binary with Ghidra’s auto-analysis.
2. **Applies PDB Symbols** (if present) before analysis via the PDB Universal analyzer.
3. **Runs Post-Analysis Scripts**:
   - `CppClassExtractor.py` — Recovers C++ vtables, virtual function tables, and class layouts from decompiler output.
   - `DatatypeMerger.py` — Backfills empty structures/unions by matching names against `.gdt` archives (e.g., WDK type libraries).
   - `post_script_export_binexports.py` — Exports each analyzed program to `.BinExport`.
4. **Patches Project Ownership** so projects can be opened by any user (removes `OWNER` from `.gpr` files).

---

## Versions & Dependencies

| Component | Version / Source |
|---|---|
| **Ghidra** | 11.0.3 PUBLIC |
| **Java** | 17 (Eclipse Temurin `17-jdk-jammy`) |
| **Python** | 3 (via `python3`, `python3-pip`) |
| **pyhidra** | 1.2.0 (pinned for Ghidra 11.0.3 compatibility) |
| **BinExport Extension** | `ghidra_11.0.3_PUBLIC_20240417_BinExport.zip` |
| **Protobuf** | 3.25.1 (shipped with BinExport; overrides Ghidra’s 3.21.8) |

---

## Project Layout

```
ghidra_headless_batch_analyzer_docker/
├── Dockerfile                          # Container build definition
├── headless_analyze.py                 # Python entrypoint (pyhidra)
├── ghidra_11.0.3_PUBLIC/               # Ghidra installation (extracted)
├── extensions/
│   └── ghidra_11.0.3_PUBLIC_20240417_BinExport.zip
├── Scripts/                            # Jython post-analysis scripts
│   ├── CppClassExtractor.py            # C++ class / vtable recovery
│   ├── DatatypeMerger.py               # Empty composite backfill from .gdt
│   ├── post_script_export_binexports.py# Export to BinExport
│   ├── Windows_Driver_functons.gdt     # Windows driver function types
│   └── wdk_full_26100.gdt              # WDK data type archive
├── fix_ownership.sh                    # Linux/macOS project ownership fix
├── fix_ownership.ps1                   # Windows project ownership fix
└── ghidra-analyze.md                   # Skill definition for invoking the analyzer
```

---

## What Each Script Does

### `CppClassExtractor.py`
- Enumerates MSVC-style backticked vtables (`` `vftable' `` and `` `vftable'{for `Base'} ``) in the Symbol Tree.
- Identifies constructors / initializers per class and **decompiles** them.
- Parses decompiled C text to find:
  - **vptr assignments** (`*(...)this = &_vftable_...`) to determine vtable offsets.
  - **typed field assignments** (casted LHS like `*(_TYPE **)(this + NNN) = ...`) to infer member fields.
- Builds `StructureDataType` definitions for each class, applies them at vtable addresses, and wires vptrs into the class layout.

### `DatatypeMerger.py`
- Scans the current program’s Data Type Manager (DTM) for empty composites (`Structure` or `Union` with 0 components or `isNotYetDefined()`).
- Loads **all `.gdt` archives** found in the same directory as the script.
- Replaces each empty composite with the first non-empty same-named definition found in those archives.
- In headless mode, it resolves the script directory from `sourceFile.getParentFile()` or from `getScriptArgs()`.

### `post_script_export_binexports.py`
- Invokes the **BinExport** extension’s `BinExportExporter` against the current program.
- Writes `<binary_name>.BinExport` next to the original binary in the output folder.

### `.gdt Archives`
- `Windows_Driver_functons.gdt` and `wdk_full_26100.gdt` provide Windows Driver Kit (WDK) type definitions. `DatatypeMerger.py` auto-loads these at runtime to resolve driver-specific structures.

---

## Technical Issues Encountered During Development

The following issues are documented in inline comments in `headless_analyze.py` and the `Dockerfile`:

### 1. Windows Charmap Codec Errors
**Symptom:** `UnicodeDecodeError: 'charmap' codec can't decode byte ...` on Windows.  
**Fix:** Set `PYTHONUTF8=1` before running. The entrypoint warns and auto-sets it if missing.

### 2. Ghidra Project Ownership Lock
**Symptom:** `.gpr` files contain `OWNER="<username>"`, preventing other users (or containers) from opening the project.  
**Fix:** The pipeline post-processes all `.gpr` files with a regex to strip the `OWNER` attribute. The container also sets `GHIDRA_USER=""` by default and supports overriding via `-e GHIDRA_USER=YourWindowsUsername`.

### 3. Java `user.name` Locks Projects
**Symptom:** Even without an `OWNER` tag, Ghidra derives ownership from the JVM `user.name` property.  
**Fix:** The launcher is configured with `-Duser.name={ghidra_user}` when `GHIDRA_USER` is provided.

### 4. JVM Background Threads Prevent Clean Exit
**Symptom:** The Python script hangs at the end because JVM non-daemon threads keep the process alive.  
**Fix:** The script ends with `os._exit(0)` to force immediate termination after all work is complete.

### 5. Protobuf Version Conflict
**Symptom:** BinExport requires protobuf **3.25.1**, but Ghidra 11.0.3 ships protobuf **3.21.8** in `Framework-AsyncComm`. Loading BinExport causes runtime linkage errors.  
**Fix:** During the Docker build, the Dockerfile copies `protobuf-java-3.25.1.jar` from the BinExport extension over Ghidra’s `protobuf-java-3.21.8.jar`.

### 6. Ghidra API Drift (`markProgramAnalyzed`)
**Symptom:** Method names for marking a program as analyzed differ across Ghidra versions.  
**Fix:** The code tries `GhidraProgramUtilities.markProgramAnalyzed(program)`, falls back to `setAnalyzedFlag(program, True)`, and silently ignores `AttributeError` if neither exists.

### 7. Headless Script Directory Resolution
**Symptom:** In headless mode, `sourceFile` may be unavailable, so `DatatypeMerger.py` cannot locate `.gdt` files relative to itself.  
**Fix:** `headless_analyze.py` passes the scripts directory as a script argument (`--script_args`), and `DatatypeMerger.py` falls back to `getScriptArgs()` when `sourceFile` is absent.

---

## Build

1. **Extract Ghidra** — Download Ghidra 11.0.3 PUBLIC and extract it so that `ghidra_11.0.3_PUBLIC/` is in the same directory as the Dockerfile.

2. **Add BinExport extension** — Place the BinExport extension zip in the `extensions/` directory:
   ```
   extensions/ghidra_11.0.3_PUBLIC_20240417_BinExport.zip
   ```

3. **Build the image**:
   ```bash
   docker build -t ghidra-pipeline .
   ```

> **Prerequisites:**
> - Docker daemon running
> - `ghidra_11.0.3_PUBLIC/` directory present (unzipped Ghidra installation)
> - `extensions/` directory contains the BinExport `.zip`

---

## Run

### Basic Usage
Mount your binaries to `/input` and an output directory to `/output`:

```bash
docker run --rm \
  -v /path/to/your/binaries:/input \
  -v /path/to/your/output:/output \
  -e GHIDRA_USER=$USER \
  ghidra-pipeline
```

### Overriding the Project Name

The Dockerfile's `ENTRYPOINT` bakes in the input directory (`/input`), scripts directory, and output directory (`/output`). The only argument you can override via `CMD` is the **project name**:

```bash
docker run --rm \
  -v /path/to/your/binaries:/input \
  -v /path/to/your/output:/output \
  -e GHIDRA_USER=$USER \
  ghidra-pipeline \
  MyCustomProjectName
```

If you need different mount points or directories, use the **Native (Non-Docker) Usage** method instead.

### Environment Variables

| Variable | Description |
|---|---|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra inside the container. **Default:** `/opt/ghidra` |
| `PYTHONUTF8` | Forces UTF-8 mode for Python. **Default:** `1` |
| `GHIDRA_USER` | Overrides Java `user.name` for portable project ownership. **Default:** *(empty)* |

### Native (Non-Docker) Usage
If you have Ghidra 11.0.3 and pyhidra installed locally:

```powershell
# Windows
$env:PYTHONUTF8 = "1"
$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra_11.0.3_PUBLIC"
python headless_analyze.py C:\path\to\binaries --scripts-dir .\Scripts --project-dir .\ghidra_projects
```

```bash
# Linux / macOS
export PYTHONUTF8=1
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.0.3_PUBLIC
python3 headless_analyze.py /path/to/binaries --scripts-dir ./Scripts --project-dir ./ghidra_projects
```

---

## Troubleshooting

### `StringIndexOutOfBoundsException` During Analysis

**Symptom:** Analysis fails with:
```
java.lang.java.lang.StringIndexOutOfBoundsException: begin 4, end 3, length 3
```

**Cause:** This is typically caused by:
1. **pyhidra version mismatch** - Using a pyhidra version incompatible with Ghidra 11.0.3
2. **PDB analyzer issue** - The PDB Universal analyzer encountering an unexpected path format

**Solutions:**

1. **Rebuild the Docker image** to ensure pyhidra 1.2.3 is installed:
   ```bash
   docker build --no-cache -t ghidra-pipeline .
   ```

2. **Skip PDB loading** if the error persists:
   - Modify the Dockerfile `CMD` to add `--skip-pdb`:
     ```dockerfile
     CMD ["DefaultProject", "--skip-pdb"]
     ```
   - Or run with custom arguments:
     ```bash
     docker run --rm \
       -v /path/to/binaries:/input \
       -v /path/to/output:/output \
       ghidra-pipeline \
       MyProject --skip-pdb
     ```

3. **Check binary compatibility** - Some binaries with unusual paths or names may cause issues. The script now continues processing remaining binaries even if one fails.

---

## Output

After a successful run, `/output` (or your `--project-dir`) will contain:

- **Ghidra project files** (`.gpr`, `.rep`) for each input directory.
- **`<binary>.BinExport`** files (one per binary) exported by the post-analysis script.
- Any additional artifacts written by the Jython scripts (e.g., updated datatype archives if the scripts are extended to export them).

---

## Troubleshooting

### Project Ownership Issues

If you encounter ownership errors when opening Ghidra projects created by the container (e.g., "Project is owned by another user"), you can manually fix the project ownership using the provided utility scripts:

#### Linux / macOS (`fix_ownership.sh`)

```bash
./fix_ownership.sh /path/to/ghidra_projects [username]
```

- If `username` is omitted, defaults to the current user (`$(whoami)`).
- Patches all `project.prp` files found under the given directory.

#### Windows (`fix_ownership.ps1`)

```powershell
.\fix_ownership.ps1 -ProjectDir C:\path\to\ghidra_projects [-Username YourUsername]
```

- If `-Username` is omitted, defaults to `$env:USERNAME`.
- Patches all `project.prp` files found under the given directory.

#### What These Scripts Do

Ghidra stores project ownership in `.rep/project.prp` files with entries like:

```
NAME="OWNER" TYPE="string" VALUE="container_user"
```

These scripts recursively find all `project.prp` files and update the `OWNER` value to your specified username, allowing you to open the projects in the Ghidra GUI without permission errors.

---
