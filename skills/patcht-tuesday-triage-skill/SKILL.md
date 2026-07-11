---
name: patcht-tuesday-triage-skill
description: Mandatory workflow for triaging Microsoft Patch Tuesday CVEs. Use whenever the user mentions Patch Tuesday, MSRC, KB articles, monthly patches, CVE triage, or asks to analyze/download/map files from a Windows security update. This skill governs the exact file output format, CVE-to-file mapping, and download sequencing rules that must be followed — do not deviate from the ordering or naming conventions defined here.
disable-model-invocation: false
---

# Patch Tuesday Triage Skill

## Required MCP Tools

Patch Tuesday MCP (MSRC CVRF + WinBIndex) is **mandatory**. Do not proceed without it.

---

## Step-by-Step Workflow

### Step 1 — Output interesting CVEs to file

After querying MSRC for the month, output a file at the **root directory** named `cves_<YYYY_MMM>.md` (e.g., `cves_2026_May.md`).

Mandatory fields per CVE:
- CVSS Score
- KB Article number
- Attack Vector / Complexity (from CVSS vector)
- Direct link to the MSRC vulnerability page

Only include CVEs worth researching (skip low-severity noise, focus on memory corruption, EoP, RCE, InfoDisc).

---

### Step 2 — Output changed files per KB to file

For each KB identified in Step 1, output the full list of files changed in that KB to a file at the **root directory**.

Suggested naming: `kb_files_<KB_NUMBER>.md`

---

### Step 3 — Map CVEs to affected files

Only after Steps 1 and 2 are complete, create a mapping file at the **root directory** that links each CVE to its potentially affected files.

Suggested naming: `cve_file_mapping.md`

This file is the prerequisite gate for Step 4. Do not download anything before this file exists.

---

### Step 4 — Download patched and unpatched binaries

**Only start downloads after the CVE→file mapping is complete.**

#### Directory naming rules

- One directory per CVE: `CVE-XXXX-XXXXX/`
- If two CVEs affect the same files: chain them with underscores: `CVE-XXXX-XXXXX_CVE-XXXX-XXXXX/`
- Use underscores for all separators in directory and file names — no spaces, no dashes within names

#### Download sequencing — CRITICAL

Download files for **one CVE at a time**:

1. Download files for CVE-A
2. Rename files appropriately (patched/unpatched suffix convention)
3. Move them into `CVE-A/`
4. Only then start CVE-B

**Never batch-download across multiple CVEs in one go.** Tool failures mid-download cause file assignment confusion that is hard to untangle.
