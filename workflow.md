# Workflow for quick diffing

### Setup

- Ghidra 11.0.3
- BinExport 

### Steps

- **1/** Find interesting PEs by checking latest updated ones. command in [here](./useful_commands.md) 
- **2/** Collect PEs and their PDBs for the patched and unpatched version using [dll_and_pdb_collection](./dll_and_pdb_collection.ps1)
- **3/** Run ghidra auto analysis + export .binExport files. --> TODO ghidra headless script 


### Dir structure for automation

- This root dir will be given to the ghidra headless analyzer as input.
```
C:\USERS\USER\DESKTOP\OPTIMAL_DIR_STRUCTURE
├───patched
│   ├───iprtprio
│   └───iprtrmgr
└───unpatched
    ├───iprtprio
    └───iprtrmgr
```
- Input to the post-analyze script will be parent directory in which it will either look for or create a directory with the analyzed pe name as a first parameter and a filename (without the extension) as second parameter (patched or unpatched)

- .Java script should be added under `GHIDRA_HOME\Ghidra\Features\Base\ghidra_scripts\<PostScriptName>.java`