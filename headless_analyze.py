#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Headless batch analysis pipeline using pyhidra (Ghidra 11.0.3 + BinExport).

Usage:
    set PYTHONUTF8=1
    python headless_analyze.py <binary_dir> [--scripts-dir <path>] [--project-dir <path>]

Arguments:
    binary_dir      Directory containing binaries (.exe, .dll, .sys) and co-located .pdb files.
                    The directory name becomes the Ghidra project name.

Options:
    --scripts-dir   Directory containing post-analysis Ghidra scripts.
                    Defaults to ./ghidra_scripts/
    --project-dir   Where to create the Ghidra project.
                    Defaults to ./ghidra_projects/

Requires:
    pip install pyhidra
    GHIDRA_INSTALL_DIR env var pointing to Ghidra 11.0.3 installation.
    PYTHONUTF8=1 env var to avoid charmap codec errors on Windows.
"""

import argparse
import sys
import os
from pathlib import Path

# Force UTF-8 on Windows if not already set
if os.name == "nt" and os.environ.get("PYTHONUTF8") != "1":
    print("[WARN] PYTHONUTF8 not set. Setting it now. If you see charmap errors,")
    print("       restart with: set PYTHONUTF8=1 && python headless_analyze.py ...")
    os.environ["PYTHONUTF8"] = "1"

BINARY_EXTENSIONS = {".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".scr"}

POST_SCRIPTS = [
    "CppClassExtractor.py",
    "DatatypeMerger.py",
    "post_script_export_binexports.py",
]


def find_binaries(binary_dir: Path) -> list:
    binaries = []
    for f in sorted(binary_dir.iterdir()):
        if f.is_file() and f.suffix.lower() in BINARY_EXTENSIONS:
            binaries.append(f)
    return binaries


def check_pdb(binary_path: Path):
    pdb = binary_path.with_suffix(".pdb")
    return pdb if pdb.exists() else None


def apply_pdb(flat_api, program, pdb_path: Path):
    """Set PDB file for the PDB Universal analyzer before analysis."""
    from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
    from java.io import File as JFile

    pdb_file = JFile(str(pdb_path))
    PdbUniversalAnalyzer.setPdbFileOption(program, pdb_file)
    print(f"  PDB configured: {pdb_path.name}")


def main():
    parser = argparse.ArgumentParser(
        description="Headless Ghidra batch analysis via pyhidra"
    )
    parser.add_argument(
        "binary_dir", type=Path,
        help="Directory containing binaries and co-located .pdb files"
    )
    parser.add_argument(
        "--scripts-dir", type=Path, default=Path("./ghidra_scripts"),
        help="Directory containing post-analysis Ghidra scripts (default: ./ghidra_scripts/)"
    )
    parser.add_argument(
        "--project-dir", type=Path, default=Path("./ghidra_projects"),
        help="Where to store Ghidra projects (default: ./ghidra_projects/)"
    )

    args = parser.parse_args()

    binary_dir = args.binary_dir.resolve()
    scripts_dir = args.scripts_dir.resolve()
    project_dir = args.project_dir.resolve()

    if not binary_dir.is_dir():
        print(f"[ERROR] Not a directory: {binary_dir}")
        sys.exit(1)

    missing = [s for s in POST_SCRIPTS if not (scripts_dir / s).exists()]
    if missing:
        print(f"[WARN] Missing scripts in {scripts_dir}: {', '.join(missing)}")

    binaries = find_binaries(binary_dir)
    if not binaries:
        print(f"[ERROR] No binaries found in {binary_dir}")
        sys.exit(1)

    project_name = binary_dir.name

    print(f"Project:    {project_name}")
    print(f"Binaries:   {len(binaries)} found in {binary_dir}")
    print(f"Scripts:    {scripts_dir}")
    print(f"Project at: {project_dir / project_name}")
    print()

    project_dir.mkdir(parents=True, exist_ok=True)

    import pyhidra

    for i, binary_path in enumerate(binaries, 1):
        pdb_path = check_pdb(binary_path)

        print(f"[{i}/{len(binaries)}] {binary_path.name}")

        # Phase 1: Import with analyze=False, apply PDB, then analyze
        print(f"  Importing...")
        with pyhidra.open_program(
            str(binary_path),
            project_name=project_name,
            project_location=str(project_dir),
            analyze=False,
        ) as flat_api:
            program = flat_api.getCurrentProgram()

            # Apply PDB before analysis
            if pdb_path:
                apply_pdb(flat_api, program, pdb_path)

            # Now analyze with PDB configured
            print(f"  Analyzing (with PDB)...")
            from ghidra.app.script import GhidraScriptUtil
            from ghidra.program.util import GhidraProgramUtilities
            GhidraScriptUtil.acquireBundleHostReference()
            flat_api.analyzeAll(program)
            # Mark as analyzed (method name varies by Ghidra version)
            try:
                GhidraProgramUtilities.markProgramAnalyzed(program)
            except AttributeError:
                try:
                    GhidraProgramUtilities.setAnalyzedFlag(program, True)
                except AttributeError:
                    pass  # Not critical
            print(f"  Analysis complete: {program.getName()}")

        # Phase 2: Run each post-script
        for script_name in POST_SCRIPTS:
            script_path = scripts_dir / script_name
            if not script_path.exists():
                print(f"  [WARN] Script not found, skipping: {script_name}")
                continue

            print(f"  Running {script_name}...")
            try:
                pyhidra.run_script(
                    str(binary_path),
                    str(script_path),
                    project_name=project_name,
                    project_location=str(project_dir),
                    analyze=False,
                    script_args=[str(scripts_dir)],
                )
            except Exception as e:
                print(f"  [ERROR] {script_name} failed: {e}")

        print()

    print("Done.")

    # Release the bundle host reference and shut down
    try:
        from ghidra.app.script import GhidraScriptUtil
        GhidraScriptUtil.releaseBundleHostReference()
    except Exception:
        pass

    # Force JVM shutdown
    import jpype
    if jpype.isJVMStarted():
        jpype.shutdownJVM()


if __name__ == "__main__":
    main()
    os._exit(0)
