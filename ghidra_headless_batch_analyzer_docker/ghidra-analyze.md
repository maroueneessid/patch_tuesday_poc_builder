# Skill: ghidra-analyze

Run the `ghidra-analyzer` Docker container against a directory of binaries.

## Trigger

When the user asks to analyze binaries with Ghidra, run the ghidra analyzer, or invokes `/ghidra-analyze`.

## Steps

1. Ask the user for two pieces of information (ask together in one message):
   - **Input directory** — the host path containing the binaries to analyze (e.g. `C:\Users\User\Desktop\DiffingBaseDir\mmc_lpe`)
   - **Output directory** — the host path where Ghidra project files should be written (e.g. `C:\Users\User\Desktop\ghidra_projects`)

2. Derive the **project name** from the basename of the input directory:
   - Strip any trailing slashes from the input path
   - Take the last path component as the project name
   - Example: `C:\Users\User\Desktop\DiffingBaseDir\mmc_lpe` → project name = `mmc_lpe`

3. Build the docker run command:
   ```
   docker run --rm \
     -v <input_dir>:/input \
     -v <output_dir>:/output \
     ghidra-analyzer <project_name>
   ```

4. Show the fully expanded command to the user and confirm before running.

5. Execute the command via Bash. Stream output so the user can follow Ghidra's analysis progress.

6. Report success or failure when the container exits.

## Notes

- The image name is always `ghidra-analyzer` (built from the Dockerfile in this repo).
- The project name is **always** derived from the input directory basename — never ask the user for it separately.
- The output directory **must always** be asked for — never assume or default it.
- On Windows, Docker Desktop accepts both `C:\...` Windows paths and `/c/...` MSYS paths in `-v` mounts; use the Windows path form the user provides as-is.
