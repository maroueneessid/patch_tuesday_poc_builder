# Patch Diffing Workflow

## Phase 1: Triage — Selecting Functions to Investigate
You are provided with a BinDiff/statistics file showing function-level similarity scores.

DO NOT assume the lowest-similarity functions are the most security-relevant. Low similarity often means refactoring, logging changes, telemetry additions, or ETW instrumentation — not security fixes.

Prioritize functions for investigation using these signals (in rough order of value):
1. **Name-based signals**: Functions whose names contain security-relevant keywords — Validate, Parse, Sanitize, Check, Auth, Privilege, Impersonate, Token, Grant, Access, Acl, Security, Encrypt, Decrypt, Verify, Boundary, Bounds, Length, Size, Count, Alloc, Free, Lock, Handle, Elevation, SetDacl, SetSecurityDescriptor — that also show as changed
2. **Patch-specific patterns**: Small, surgical changes (1-5 basic blocks modified) in otherwise stable functions — these are more likely targeted fixes than large-scale refactors
3. **Similarity + context**: Medium-similarity functions (70-95%) in code paths that handle untrusted input, IPC, RPC, file I/O, or registry operations
4. **New validation/checks**: Functions where the patched version adds bounds checks, null checks, length validation, or error handling that the unpatched version lacks

Only after evaluating these signals should you consider raw similarity ranking as a tiebreaker.

## Phase 2: Vulnerability Analysis
When you find a potentially interesting code change:

1. **Characterize the fix**: What exactly changed? Added bounds check? Changed comparison operator? Added null check? New error path? Removed functionality?
2. **Identify the CWE**: Map the unpatched behavior to a concrete weakness class (CWE-122 heap overflow, CWE-59 link following, CWE-416 use-after-free, CWE-190 integer overflow, etc.)
3. **Assess exploitability**: Can the unpatched code path lead to a realistic primitive?
   - Memory corruption → read/write primitive → code execution?
   - TOCTOU → symlink/junction → arbitrary file write/delete?
   - Logic flaw → privilege escalation → token manipulation?
   - Integer overflow → undersized allocation → heap overflow?
   
   If none of these apply, say so explicitly rather than speculating.

## Phase 3: Reachability Analysis
Before concluding a bug is exploitable, trace the call chain backwards:

1. Use `get_function_callers` / `get_xrefs_to` to walk up the call graph from the vulnerable function
2. At each caller, check: are the parameters that reach the vulnerable code path derived from user-controlled input? (file content, registry values, RPC parameters, network data, environment variables, named pipe data)
3. Continue until you either:
   - Reach an exported function / RPC handler / IPC endpoint / syscall entry → document the full chain
   - Reach a point where all callers use hardcoded/trusted values → the bug likely isn't reachable from untrusted input, state this clearly
4. Note any authentication or privilege requirements along the path (does the caller require admin? Is it a service running as SYSTEM? Is it reachable from a low-privilege context?)

## Phase 4: Chaining and Broader Context
If a bug has limited impact on its own:
1. Search Microsoft Learn MCP for documentation on the affected component — understand its intended security boundary and trust model
2. Look up previous CVEs for the same component/binary to identify known attack patterns and prior art
3. Consider what other components interact with the affected mechanism:
   - Does it share memory/handles/tokens with other services?
   - Is the output consumed by a higher-privilege component?
   - Can it be combined with a known primitive (e.g., arbitrary delete → EoP via installer rollback)?
4. Propose concrete chaining scenarios, not vague "could potentially be combined" statements

## Tool Usage Notes
- Use **Microsoft Learn MCP** for Win32/NT API documentation, security model details, and component architecture
- When referencing API behavior, prefer Microsoft's documentation over assumptions from decompiled code
- Use the `program` parameter to query across patched/unpatched binaries without switching context when comparing specific functions side-by-side