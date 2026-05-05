# CVE PoC Development Rules

## OPSEC: Naming and Documentation
All source files, namespaces, classes, functions, variables, and comments must use
neutral/generic terminology. The code should look like a legitimate test tool or
diagnostic utility if read by someone without context.

NEVER use:
- "CVE", "exploit", "payload", "shellcode", "trigger", "vulnerability", "vuln"
  in any identifier, filename, directory name, or comment
- Descriptions like "triggers exploitable path", "causes crash for exploitation",
  "overwrites return address"

USE instead:
- Project/directory names: `fs-test`, `svc-diag`, `reg-probe`, `io-benchmark`
- Function names: `run_test`, `send_request`, `validate_result`, `perform_check`
- Comments: describe WHAT the code does mechanically, not WHY it's interesting
  - Good: `// Set file attributes before rename operation`
  - Bad: `// Setup race condition window for TOCTOU exploit`

Include debugging output (return codes, error messages, GetLastError values,
NTSTATUS codes) as plain print/printf statements. No ASCII art, no tables,
no banners, no colored output.

## Privilege Model
Always assume execution as a **standard unprivileged user** — not in Administrators,
not in any special group, no UAC elevation, no sudo.

**Before generating any code**, enumerate privilege requirements explicitly:
1. What privilege level does the PoC itself need to run?
2. Does the PoC setup require any prior privileged action?
   (e.g., installing a service, creating a symlink in a protected directory,
   writing to HKLM, enabling a feature)
3. Does the target component/service need to be in a specific state?
   (e.g., service running, scheduled task registered, specific policy enabled)

State these as a prerequisites section BEFORE the code. If any step requires
elevation, say so explicitly and explain whether this is an expected precondition
of the attack scenario (e.g., "attacker needs write access to C:\ProgramData\X,
which is world-writable by default") or if it limits the bug's impact.

## Reproducibility

### Unique identifiers
Any PoC that interacts with GUIDs, UUIDs, CLSIDs, named objects, or other
unique identifiers: always generate them at runtime. Never hardcode a
specific GUID/UUID. Provide a helper function that creates a fresh one
on each execution.

### Build requirements
- **Static linking always.** Every build command/script must produce a
  statically linked binary. No dependency on Visual C++ redistributables,
  .NET framework versions, or shared libraries that may not be present.
- Provide exact build commands (cl.exe flags, gcc/g++ flags, or CMake
  configuration) — do not assume the user knows the right linker flags.

### Runtime assumptions
- The built binary must run on a **bare Windows/Linux install** with no
  developer tools (no Visual Studio, no Python, no SDK, no WDK).
- If the PoC loads a DLL, driver, file, or any payload: that path is a
  **required command-line argument**, never hardcoded.
  Pattern: `if (argc < 2) { printf("Usage: %s <path_to_payload>\n", argv[0]); return 1; }`
- If the PoC needs a specific file/directory structure, generate it
  programmatically at runtime or document the exact setup steps.

### Environment independence
- No assumptions about drive letters beyond C:\ on Windows
- Use environment variables or runtime APIs for system paths
  (`GetSystemDirectory`, `GetTempPath`, `SHGetKnownFolderPath`)
- No assumptions about specific Windows build numbers unless the
  vulnerability is version-specific (in which case, detect and bail
  with a clear message if the version doesn't match)

## Language and Approach Priority
Prefer native/compiled languages in this order:
1. **C** — for kernel-adjacent, syscall-level, or minimal-dependency PoCs
2. **C++** — when COM, WinRT, or C++ APIs are the natural interface
3. **C#** — when .NET APIs are the only/cleanest path (e.g., some COM
   interop, WMI, certain Windows services)

Avoid scripting languages (Python, PowerShell, batch) for the core PoC
unless the vulnerability specifically lives in a scripting/interpreted context.

Helper/setup scripts (creating directory structures, copying files) are fine
in PowerShell/batch, but the actual trigger must be compiled.

**Exception**: If the vulnerability is specifically in a GUI component, COM
object requiring OLE automation, or something that fundamentally requires
user interaction — use the appropriate approach and note why a programmatic
PoC isn't feasible.