# Patch Diffing Workflow with Ghidra and BinDiff

### Setup

- Ghidra 11.0.3
- BinExport compatible with the Ghidra version.
- BinDiff.

### Description

Automated binary diffing pipeline using Ghidra headless analysis and BinExport for patch analysis.

## Directory Structure
```
project_root/
├── diffs/                          # Generated BinExport files for diffing
│   ├── <PE_name>/
│   │   ├── patched_<PE_name>.BinExport
│   │   └── unpatched_<PE_name>.BinExport
├── patched/                        # Patched binaries
│   └── <PE_name>/
│       ├── <PE_name>.dll
│       └── <PE_name>.pdb           # Optional, auto-loaded if present
└── unpatched/                      # Original binaries
    └── <PE_name>/
        ├── <PE_name>.dll
        └── <PE_name>.pdb           # Optional, auto-loaded if present
```

## Prerequisites

- Ghidra 11.0.3+ installed at `C:\MyProgs\Ghidra\ghidra_11.0.3_PUBLIC\`
- BinExport extension installed in Ghidra
- `binExport.py` script placed in `C:\MyProgs\Ghidra\Scripts\`
- PowerShell 5.0+

## Setup

1. **Install BinExport extension** in Ghidra GUI (File → Install Extensions)

2. **Place binaries** in the directory structure:
   - Patched binaries → `patched/<PE_name>/`
   - Unpatched binaries → `unpatched/<PE_name>/`
   - PDB files (optional) must match DLL/EXE name and be in same folder

3. **Create the Python export script** (`C:\MyProgs\Ghidra\Scripts\binExport.py`) . [`binExport.py`](./binExport.py)

## Usage

### Single Binary Analysis
```powershell
C:\MyProgs\Ghidra\ghidra_11.0.3_PUBLIC\support\analyzeHeadless.bat `
  "C:\MyProgs\Ghidra\Projects\CVE-2026-20843" `
  "patched" `
  -import "C:\path\to\patched\RasMediaManager\RasMediaManager.dll" `
  -analysisTimeoutPerFile 300 `
  -scriptPath C:\MyProgs\Ghidra\Scripts `
  -postScript "binExport.py"
```

### Batch Processing (Recommended)

Use the PowerShell wrapper script [`diff_bins.ps1`](./diff_bins.ps1):
```powershell
# Process all patched binaries
.\diff_bins.ps1 "C:\Users\User\Desktop\optimal_dffing\patched" patched

# Process all unpatched binaries
.\diff_bins.ps1 "C:\Users\User\Desktop\optimal_dffing\unpatched" unpatched
```

**Script parameters:**
- First argument: Full path to patched or unpatched directory
- Second argument: Type (`patched` or `unpatched`)

### PowerShell Wrapper Script (`diff_bins.ps1`)


## Output

After running the scripts, BinExport files will be generated in:
```
diffs/
└── <PE_name>/
    ├── patched_<PE_name>.BinExport
    └── unpatched_<PE_name>.BinExport
```

These `.BinExport` files can be loaded into BinDiff for visual comparison.

## Workflow Summary

1. Organize binaries in `patched/` and `unpatched/` directories
2. Run `diff_bins.ps1` for both patched and unpatched sets
3. Ghidra analyzes each binary (imports, applies PDBs, runs analysis)
4. Python script exports to BinExport format in `diffs/<PE_name>/`
5. Use BinDiff to compare `patched_*.BinExport` vs `unpatched_*.BinExport`

## Notes

- **PDB files**: Automatically loaded if they match the PE name and are in the same directory
- **Analysis timeout**: Default 300 seconds per file (adjustable in script)
- **Project separation**: Patched and unpatched binaries use separate Ghidra projects to avoid naming conflicts
- **Cross-platform**: Python script uses Java File APIs for Windows/Linux compatibility