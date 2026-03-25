#!/usr/bin/env python3
"""
patch_tuesday_mcp_server.py — MCP server for Patch Tuesday research workflow.

Combines CVE fetching (MSRC CVRF API) and patched/vulnerable binary downloading
(WinBIndex + Microsoft Symbol Server) into a single MCP server.

Usage:
    python patch_tuesday_mcp_server.py --base-dir /path/to/research
    BASE_DIR=/path/to/research python patch_tuesday_mcp_server.py

All downloaded files are placed inside {base_dir}/{CVE_ID}/ — never loose in base_dir.
"""

import argparse
import gzip
import json
import os
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pefile
import requests
from mcp.server.fastmcp import FastMCP

SYSTEM32 = Path(r"C:\Windows\System32")
DRIVERS  = SYSTEM32 / "drivers"


def _resolve_pe_path(filename: str) -> Optional[Path]:
    """Return the first existing path for filename in System32 or drivers\\."""
    for base in (SYSTEM32, DRIVERS):
        p = base / filename
        if p.exists():
            return p
    return None

# ── Import pure helpers from original scripts (no sys.exit on import) ─────────

from fetch_patch_tuesday_interesting_vulns import (
    get_severity,
    get_cvss_info,
)

from fetch_cve_related_pre_post_patch_binaries import (
    COMPONENT_MAP,
    MONTH_NAMES,
    DEFAULT_WINDOWS_VERSION,
    WINBINDEX_URL,
    SYMBOL_SERVER_URL,
    validate_cve,
    get_patch_tuesday,       # noqa: F401 — used by select_versions internally
    is_near_patch_tuesday,   # noqa: F401 — used by select_versions internally
    select_versions,
)

# ── Server setup ──────────────────────────────────────────────────────────────

MSRC_CVE_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"
MSRC_CVRF_URL = "https://api.msrc.microsoft.com/cvrf"


def _parse_base_dir() -> str:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--base-dir", default=os.environ.get("BASE_DIR", "./patch_bins"))
    args, _ = parser.parse_known_args()
    return os.path.abspath(args.base_dir)


BASE_DIR = _parse_base_dir()
mcp = FastMCP("patch-tuesday")

# ── HTTP helper with retry ────────────────────────────────────────────────────


def _http_get(url: str, stream: bool = False, timeout: int = 60, **kwargs) -> requests.Response:
    """GET with up to 3 attempts, exponential backoff.

    Retries on network errors and HTTP 5xx only. HTTP 4xx is returned
    immediately for the caller to handle (client errors should not be retried).
    """
    last_exc: Optional[Exception] = None
    for attempt in range(3):
        try:
            r = requests.get(url, stream=stream, timeout=timeout, **kwargs)
            if r.status_code < 500:
                return r
            last_exc = RuntimeError(f"HTTP {r.status_code}")
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
        if attempt < 2:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Request to {url} failed after 3 attempts: {last_exc}")


def _stream_to_file(url: str, dest: str, timeout: int = 120) -> None:
    """Download url to dest path, streaming. Raises RuntimeError on failure."""
    r = _http_get(url, stream=True, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} downloading {url}")
    with open(dest, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)


# ── Exploitability helpers — highest severity wins across all Type==1 entries ─

_EXPLOIT_RANK: Dict[str, int] = {
    "exploitation detected": 2,
    "exploitation more likely": 1,
}


def _get_best_exploitability(vuln: Dict) -> Optional[str]:
    """Return the highest-severity exploitability string across all Type==1 Threats.

    CVRF documents can have multiple Type==1 Threat entries for the same CVE
    (one per affected product). We pick the worst-case entry rather than the
    first, to avoid misclassifying a CVE because a lower-risk product appeared
    first in the array.
    """
    best_rank = -1
    best_val: Optional[str] = None
    for threat in vuln.get("Threats", []):
        if threat.get("Type") != 1:
            continue
        desc = threat.get("Description", {})
        val = desc.get("Value", "") if isinstance(desc, dict) else str(desc or "")
        if not val:
            continue
        rank = _EXPLOIT_RANK.get(val.strip().lower(), 0)
        if best_val is None or rank > best_rank:
            best_rank = rank
            best_val = val
    return best_val.strip() if best_val else None


def _is_high_exploitability(exploit_str: Optional[str]) -> bool:
    if not exploit_str:
        return False
    low = exploit_str.lower()
    return "exploitation detected" in low or "exploitation more likely" in low


# ── CVE → filename + patch month resolution ───────────────────────────────────


def _resolve_cve(cve_id: str) -> Tuple[str, List[str], str]:
    """Query MSRC and return (tag, [filenames_from_map], patch_month YYYY-MM).

    Raises RuntimeError / ValueError on failure. Never calls sys.exit.
    """
    url = f"{MSRC_CVE_URL}/{cve_id}"
    r = _http_get(url, headers={"Accept": "application/json"}, timeout=30)
    if r.status_code == 404:
        raise RuntimeError(f"{cve_id} not found in the Microsoft database")
    if r.status_code != 200:
        raise RuntimeError(f"MSRC API returned HTTP {r.status_code} for {cve_id}")

    data = r.json()
    tag: str = data.get("tag", "")
    if tag.startswith("Role: "):
        tag = tag[6:]

    filenames = [c["file"] for c in COMPONENT_MAP if c["name"] == tag]

    release_number: str = data.get("releaseNumber") or ""
    if not release_number or "-" not in release_number:
        raise ValueError(
            f"Cannot determine patch month: MSRC returned "
            f"releaseNumber='{release_number}' for {cve_id}. "
            "Use download_patch_binaries with filename= and re-check manually."
        )
    try:
        year, month_name = release_number.split("-", 1)
        patch_month = f"{year}-{MONTH_NAMES[month_name]}"
    except KeyError:
        raise ValueError(
            f"Unknown month abbreviation in releaseNumber '{release_number}'. "
            "Expected format: YYYY-Mon (e.g. 2025-Apr)."
        )

    return tag, filenames, patch_month


# ── COMPONENT_MAP grouped helper ──────────────────────────────────────────────


def _grouped_component_map() -> List[Dict[str, Any]]:
    groups: Dict[str, List[str]] = {}
    for entry in COMPONENT_MAP:
        groups.setdefault(entry["name"], []).append(entry["file"])
    return [{"tag_name": k, "filenames": v} for k, v in groups.items()]


# ── Binary download pipeline ──────────────────────────────────────────────────


def _download_pair(
    filename: str,
    patch_month: str,
    output_dir: str,
    windows_version: str,
) -> Dict[str, Any]:
    """Download patched + vulnerable binaries for one filename into output_dir.

    WinBIndex .json.gz is kept in a TemporaryDirectory and never written to
    output_dir. Returns a result dict; on failure, sets 'error' and returns
    early without raising so callers can surface the message cleanly.
    """
    result: Dict[str, Any] = {
        "filename": filename,
        "patched_path": None,
        "vulnerable_path": None,
        "patched_version": None,
        "vulnerable_version": None,
        "kb_id": None,
        "error": None,
    }

    os.makedirs(output_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Step 1: fetch WinBIndex database
        db_url = f"{WINBINDEX_URL}/{filename}.json.gz"
        db_path = os.path.join(tmpdir, f"{Path(filename).stem}.json.gz")
        try:
            _stream_to_file(db_url, db_path, timeout=60)
        except RuntimeError as exc:
            result["error"] = f"WinBIndex fetch failed for '{filename}': {exc}"
            return result

        # Step 2: select patched / vulnerable versions (pure, no HTTP)
        patched, vulnerable = select_versions(db_path, windows_version, patch_month)

    if not patched:
        result["error"] = (
            f"No patched version found for '{filename}' "
            f"on {windows_version} in {patch_month}. "
            "Try a different windows_version."
        )
        return result
    if not vulnerable:
        result["error"] = (
            f"No vulnerable version found for '{filename}' "
            f"on {windows_version} prior to {patch_month}. "
            "Try a different windows_version."
        )
        return result

    result["kb_id"] = patched.get("kb_id")
    result["patched_version"] = patched["release_version"]
    result["vulnerable_version"] = vulnerable["release_version"]

    # Step 3: download both binaries from Symbol Server
    stem = Path(filename).stem
    ext = Path(filename).suffix

    for ver_info, label, path_key in (
        (patched, "patched", "patched_path"),
        (vulnerable, "vulnerable", "vulnerable_path"),
    ):
        ts_hex = f"{int(ver_info['timestamp']):08X}"
        sz_hex = f"{int(ver_info['virtual_size']):X}"
        bin_url = f"{SYMBOL_SERVER_URL}/{filename}/{ts_hex}{sz_hex}/{filename}"
        local_name = f"{stem}_{ver_info['release_version']}{ext}"
        local_path = os.path.join(output_dir, local_name)
        try:
            _stream_to_file(bin_url, local_path, timeout=120)
        except RuntimeError as exc:
            result["error"] = f"Symbol Server download failed for {label} '{filename}': {exc}"
            return result
        result[path_key] = local_path

    return result


# ── MCP Tools ─────────────────────────────────────────────────────────────────


@mcp.tool()
def fetch_patch_tuesday_cves(month: str = "", api_token: str = "") -> List[Dict[str, Any]]:
    """Fetch high-exploitability CVEs from a Patch Tuesday month.

    Returns CVEs where exploitability is 'Exploitation Detected' or
    'Exploitation More Likely'. Use the returned CVE_IDs with
    download_patch_binaries to fetch the corresponding binaries.

    Args:
        month: Target month as YYYY-MM or YYYY-Mon (e.g. '2025-03' or '2025-Mar').
               Defaults to the current month.
        api_token: Optional Azure AD bearer token — required for months older
                   than the current one.

    Returns:
        List of dicts: {CVE_ID, Title, Severity, Exploitability,
                        CVSS_BaseScore, CVSS_Vector}
    """
    headers: Dict[str, str] = {"Accept": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    if month:
        for fmt in ("%Y-%m", "%Y-%b"):
            try:
                dt = datetime.strptime(month, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(
                f"Invalid month format '{month}'. Use YYYY-MM or YYYY-Mon "
                "(e.g. 2025-03, 2025-Mar)."
            )
    else:
        dt = datetime.now()

    slug = f"{dt.year}-{dt.strftime('%b')}"
    r = _http_get(f"{MSRC_CVRF_URL}/{slug}", headers=headers, timeout=30)
    if r.status_code == 401:
        raise PermissionError("MSRC API: Unauthorized — api_token required for historical data.")
    if r.status_code != 200:
        raise RuntimeError(f"MSRC CVRF API error: HTTP {r.status_code} for month '{slug}'.")

    vulnerabilities = r.json().get("Vulnerability", [])
    cves = []
    for vuln in vulnerabilities:
        exploit_str = _get_best_exploitability(vuln)
        if not _is_high_exploitability(exploit_str):
            continue
        cvss = get_cvss_info(vuln)
        title_field = vuln.get("Title", "")
        cves.append({
            "CVE_ID": vuln.get("CVE", "N/A"),
            "Title": title_field.get("Value", "") if isinstance(title_field, dict) else title_field,
            "Severity": get_severity(vuln),
            "Exploitability": exploit_str,
            "CVSS_BaseScore": cvss["BaseScore"],
            "CVSS_Vector": cvss["Vector"],
        })
    return cves


@mcp.tool()
def download_patch_binaries(
    cve_id: str,
    filename: str = "",
    windows_version: str = DEFAULT_WINDOWS_VERSION,
) -> Dict[str, Any]:
    """Download patched and vulnerable Windows binaries for a CVE.

    Files are saved to {base_dir}/{cve_id}/ (created automatically).
    The base_dir is configured when the server starts via --base-dir or
    the BASE_DIR environment variable.

    Resolution rules:
    - If filename is omitted: the binary is resolved from COMPONENT_MAP using
      the CVE's MSRC security tag. If the tag maps to multiple files (e.g.
      'Windows Hyper-V' → 4 files), an error is returned listing the candidates
      — re-call with the specific filename you want.
    - If filename is provided: COMPONENT_MAP is bypassed entirely; the patch
      month is still resolved from MSRC using the CVE ID.

    After a successful download the result includes kb_id — the KB article that
    patched this binary. Pass extra filenames you suspect were co-patched in
    that KB to additional download_patch_binaries calls.

    Args:
        cve_id: CVE identifier, e.g. 'CVE-2025-29824'.
        filename: Binary filename to download, e.g. 'clfs.sys'. Optional.
        windows_version: Target Windows version (default: '11-24H2').

    Returns:
        Dict with keys: cve_id, tag, patch_month, kb_id, filename,
        patched_path, vulnerable_path, patched_version, vulnerable_version, error.
        On success, error is None. On failure, error contains a description and
        the path fields are None.
    """
    cve_id = cve_id.strip().upper()
    if not validate_cve(cve_id):
        raise ValueError(f"Invalid CVE format '{cve_id}'. Expected CVE-YYYY-NNNNN.")

    result: Dict[str, Any] = {
        "cve_id": cve_id,
        "tag": None,
        "patch_month": None,
        "kb_id": None,
        "filename": filename or None,
        "patched_path": None,
        "vulnerable_path": None,
        "patched_version": None,
        "vulnerable_version": None,
        "error": None,
    }

    tag, mapped_files, patch_month = _resolve_cve(cve_id)
    result["tag"] = tag
    result["patch_month"] = patch_month

    if not filename:
        if not mapped_files:
            result["error"] = (
                f"No COMPONENT_MAP entry for tag '{tag}'. "
                "Re-call with filename=<binary> to specify it explicitly. "
                "Use list_component_mappings() to browse known mappings."
            )
            return result
        if len(mapped_files) > 1:
            result["error"] = (
                f"Tag '{tag}' maps to multiple files: {', '.join(mapped_files)}. "
                "Re-call with filename=<one of these>."
            )
            return result
        filename = mapped_files[0]

    result["filename"] = filename
    output_dir = os.path.join(BASE_DIR, cve_id)
    file_result = _download_pair(filename, patch_month, output_dir, windows_version)

    result["kb_id"] = file_result["kb_id"]
    result["patched_path"] = file_result["patched_path"]
    result["vulnerable_path"] = file_result["vulnerable_path"]
    result["patched_version"] = file_result["patched_version"]
    result["vulnerable_version"] = file_result["vulnerable_version"]
    result["error"] = file_result["error"]
    return result


@mcp.tool()
def list_component_mappings(tag_filter: str = "") -> List[Dict[str, Any]]:
    """List known CVE security tag → binary filename mappings.

    Grouped by tag so multi-file components (e.g. 'Windows Hyper-V' → 4 files)
    appear as a single entry. Useful for checking what filename to pass when
    download_patch_binaries reports an ambiguity, or for discovering what's
    covered before attempting a download.

    Args:
        tag_filter: Optional case-insensitive substring to filter tag names.

    Returns:
        List of dicts: {tag_name: str, filenames: list[str]}
    """
    groups = _grouped_component_map()
    if tag_filter:
        lf = tag_filter.lower()
        groups = [g for g in groups if lf in g["tag_name"].lower()]
    return groups


def _pe_file_description(pe_path: Path) -> Optional[str]:
    """Extract FileDescription from a PE's VS_VERSIONINFO block, or None."""
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        for file_info_block in getattr(pe, "FileInfo", []):
            for info in (file_info_block if isinstance(file_info_block, list) else [file_info_block]):
                if getattr(info, "Key", None) != b"StringFileInfo":
                    continue
                for st in getattr(info, "StringTable", []):
                    for k, v in st.entries.items():
                        if k == b"FileDescription" and v:
                            return v.decode(errors="replace").strip()
    except Exception:
        pass
    finally:
        try:
            pe.close()  # noqa: F821
        except Exception:
            pass
    return None


def _safe_filename(filename: str) -> Optional[str]:
    """Return filename if it contains no path separators, else None."""
    if os.sep in filename or "/" in filename or "\\" in filename:
        return None
    return filename


@mcp.tool()
def list_iat(filename: str) -> Dict[str, Any]:
    """List unique DLLs imported by a PE file and their FileDescription.

    Parses the IAT of a PE in C:\\Windows\\System32, collects the unique set
    of imported DLL names, then reads the FileDescription from each DLL's
    VS_VERSIONINFO block (when the DLL is also present in System32).

    Use the descriptions to quickly filter which dependencies are relevant
    to the component you are investigating (e.g. skip generic runtime DLLs,
    focus on subsystem-specific ones).

    Lookup is restricted to C:\\Windows\\System32 and C:\\Windows\\System32\\drivers
    — no path separators allowed in filename.

    Args:
        filename: PE filename, e.g. 'clfs.sys', 'ntoskrnl.exe', 'lsass.exe'.

    Returns:
        Dict with keys:
          filepath — absolute path that was parsed
          dlls     — list of {dll, description, found_in_system32}
                     description is None when the DLL is not in System32 or
                     has no FileDescription (e.g. api-ms-win-* forwarder stubs)
          error    — None on success, error string on failure
    """
    result: Dict[str, Any] = {"filepath": None, "dlls": [], "error": None}

    if not _safe_filename(filename):
        result["error"] = "filename must not contain path separators."
        return result

    pe_path = _resolve_pe_path(filename)
    if pe_path is None:
        result["filepath"] = str(SYSTEM32 / filename)
        result["error"] = f"'{filename}' not found in {SYSTEM32} or {DRIVERS}."
        return result
    result["filepath"] = str(pe_path)

    # Parse import directory of the target PE
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except pefile.PEFormatError as exc:
        result["error"] = f"pefile could not parse '{filename}': {exc}"
        return result
    except OSError as exc:
        result["error"] = f"Could not read '{filename}': {exc}"
        return result

    # Collect unique DLL names (preserve IAT order, deduplicate)
    seen: set = set()
    unique_dlls: List[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll_name = entry.dll.decode(errors="replace")
        if dll_name.lower() not in seen:
            seen.add(dll_name.lower())
            unique_dlls.append(dll_name)
    pe.close()

    # Resolve FileDescription for each unique DLL (System32, then drivers\)
    dlls = []
    for dll_name in unique_dlls:
        dll_path = _resolve_pe_path(dll_name)
        found = dll_path is not None
        description = _pe_file_description(dll_path) if found else None
        dlls.append({
            "dll": dll_name,
            "description": description,
            "found_in_system32": found,
        })

    result["dlls"] = dlls
    return result


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
