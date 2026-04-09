#!/usr/bin/env python3
"""
patch_tuesday_mcp_server.py — MCP server for Patch Tuesday research workflow.

KB-CSV-based workflow: for a given Patch Tuesday month and Windows platform,
fetches Microsoft's file-version manifest CSV for the cumulative update KB,
filters for .exe/.dll/.sys, and diffs against the previous month's KB to find
files that actually changed version (not just repackaged).

Configuration (all env vars):
    BASE_DIR             — directory for downloaded binaries (default: ./patch_bins)
    PE_INDEX_DB          — path to pe-index ChromaDB (optional, enables search_pe_* tools)
    PE_INDEX_COLLECTION  — ChromaDB collection name (default: pe_files)
    PE_INDEX_EMBED_URL   — embedding endpoint (default: http://localhost:1234/v1)
    PE_INDEX_EMBED_MODEL — embedding model (default: text-embedding-nomic-embed-text-v1.5@f32)

Usage:
    BASE_DIR=./research PE_INDEX_DB=./pe-index.chromadb python patch_tuesday_mcp_server.py
"""

import csv
import gzip
import io
import json
import os
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import chromadb
import pefile
import requests
from bs4 import BeautifulSoup
from openai import OpenAI
from mcp.server.fastmcp import FastMCP

SYSTEM32 = Path(r"C:\Windows\System32")
DRIVERS  = SYSTEM32 / "drivers"

# ── PE Index config ──────────────────────────────────────────────────────────

PE_INDEX_DB          = os.environ.get("PE_INDEX_DB", "")
PE_INDEX_COLLECTION  = os.environ.get("PE_INDEX_COLLECTION", "pe_files")
PE_INDEX_EMBED_URL   = os.environ.get("PE_INDEX_EMBED_URL", "http://localhost:1234/v1")
PE_INDEX_EMBED_MODEL = os.environ.get(
    "PE_INDEX_EMBED_MODEL", "text-embedding-nomic-embed-text-v1.5@f32"
)

# ── Import CVE helpers ────────────────────────────────────────────────────────

from fetch_patch_tuesday_interesting_vulns import (
    get_severity,
    get_cvss_info,
)

# ── Server setup ──────────────────────────────────────────────────────────────

MSRC_CVRF_URL = "https://api.msrc.microsoft.com/cvrf"

BASE_DIR = os.path.abspath(os.environ.get("BASE_DIR", "./patch_bins"))
mcp = FastMCP("patch-tuesday")

# Maps user-friendly windows_version strings to MSRC ProductID strings used in
# CVRF Remediation entries. IDs are stable across all monthly CVRF documents.
# 20438 = Windows 11 25H2 x64, 20437 = Windows 11 25H2 ARM64.
# Only x64 is tracked here; ARM64 shares the same KB but a different CSV section.
WINDOWS_VERSION_PRODUCT_IDS: Dict[str, List[str]] = {
    "11-25H2": ["20438"],
}

DEFAULT_WINDOWS_VERSION = "11-25H2"

_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys"}

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


# ── Exploitability helpers ────────────────────────────────────────────────────

_EXPLOIT_RANK: Dict[str, int] = {
    "exploitation detected": 2,
    "exploitation more likely": 1,
}


def _get_best_exploitability(vuln: Dict) -> Optional[str]:
    """Return the highest-severity exploitability string across all Type==1 Threats."""
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


# ── PE path helper ────────────────────────────────────────────────────────────


def _resolve_pe_path(filename: str) -> Optional[Path]:
    """Return the first existing path for filename in System32 or drivers\\."""
    for base in (SYSTEM32, DRIVERS):
        p = base / filename
        if p.exists():
            return p
    return None


# ── KB CSV workflow helpers ───────────────────────────────────────────────────


def _parse_month(month: str) -> datetime:
    """Parse YYYY-MM or YYYY-Mon into a datetime. Raises ValueError if invalid."""
    for fmt in ("%Y-%m", "%Y-%b"):
        try:
            return datetime.strptime(month, fmt)
        except ValueError:
            continue
    raise ValueError(
        f"Invalid month format '{month}'. Use YYYY-MM or YYYY-Mon (e.g. 2025-04, 2025-Apr)."
    )


def _get_previous_month(month: str) -> str:
    """Return the YYYY-Mon string for the month preceding *month*."""
    dt = _parse_month(month)
    if dt.month == 1:
        prev = dt.replace(year=dt.year - 1, month=12)
    else:
        prev = dt.replace(month=dt.month - 1)
    return prev.strftime("%Y-%b")


def _extract_kb_for_vuln(vuln: Dict, target_ids: set) -> Optional[str]:
    """Return the Security Update KB number for target_ids from a vuln's Remediations.

    In CVRF JSON: Type==2 is Vendor Fix, Type==3 is Release Notes, Type==6 is
    Known Issue. SubType filters out Hotpatch and Monthly Rollup entries.
    """
    for rem in vuln.get("Remediations", []):
        if rem.get("Type") != 2:
            continue
        if rem.get("SubType") != "Security Update":
            continue
        if not set(rem.get("ProductID", [])) & target_ids:
            continue
        desc = rem.get("Description", {})
        kb = desc.get("Value", "").strip() if isinstance(desc, dict) else ""
        if kb:
            return kb
    return None


def _fetch_kb_for_platform(month: str, windows_version: str) -> Optional[str]:
    """Return the Security Update KB number for *windows_version* in *month*.

    Fetches the MSRC CVRF document for *month* and returns the first KB found
    via _extract_kb_for_vuln across all vulnerabilities. Returns None if no
    match is found.

    Args:
        month: YYYY-MM or YYYY-Mon (e.g. '2025-04' or '2025-Apr').
        windows_version: Key from WINDOWS_VERSION_PRODUCT_IDS (e.g. '11-25H2').

    Raises:
        ValueError: If windows_version is not in WINDOWS_VERSION_PRODUCT_IDS.
    """
    target_ids = set(WINDOWS_VERSION_PRODUCT_IDS.get(windows_version, []))
    if not target_ids:
        raise ValueError(
            f"Unknown windows_version '{windows_version}'. "
            f"Known: {list(WINDOWS_VERSION_PRODUCT_IDS)}"
        )

    dt = _parse_month(month)
    slug = f"{dt.year}-{dt.strftime('%b')}"

    r = _http_get(f"{MSRC_CVRF_URL}/{slug}", headers={"Accept": "application/json"}, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"MSRC CVRF API error: HTTP {r.status_code} for month '{slug}'.")

    for vuln in r.json().get("Vulnerability", []):
        kb = _extract_kb_for_vuln(vuln, target_ids)
        if kb:
            return kb

    return None


def _fetch_kb_file_list(kb_number: str, arch: str = "x64") -> List[Dict[str, str]]:
    """Fetch Microsoft's file-version CSV for a KB and return filtered rows.

    Fetches https://support.microsoft.com/help/{kb_number}, finds the
    ocpExternalLink anchor whose text contains 'download the file information
    for cumulative update {kb_number}', downloads the CSV via the fwlink URL,
    and returns only rows for .exe/.dll/.sys files from sections matching *arch*.

    Args:
        kb_number: Bare KB number without 'KB' prefix, e.g. '5077181'.
        arch: Architecture substring to match in section titles, e.g. 'x64'.
              Only rows from sections whose title contains this string are returned.

    Returns:
        List of dicts with keys: file_name, file_version, file_size, date, time.

    Raises:
        RuntimeError: If the support page is unreachable, the CSV link is not
                      found, or the CSV download fails.
    """
    support_url = f"https://support.microsoft.com/help/{kb_number}"
    r = _http_get(support_url, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(
            f"Support page returned HTTP {r.status_code} for KB {kb_number} ({support_url})"
        )

    soup = BeautifulSoup(r.text, "html.parser")
    csv_url: Optional[str] = None
    target_text = f"download the file information for cumulative update {kb_number.lower()}"

    # Primary: exact anchor text match
    for a in soup.find_all("a", class_="ocpExternalLink"):
        if target_text in a.get_text(strip=True).lower():
            csv_url = a.get("href", "").strip()
            break

    # Fallback: any ocpExternalLink with 'file information' pointing to fwlink
    if not csv_url:
        for a in soup.find_all("a", class_="ocpExternalLink"):
            href = a.get("href", "")
            if "go.microsoft.com/fwlink" in href and "file information" in a.get_text(strip=True).lower():
                csv_url = href.strip()
                break

    if not csv_url:
        raise RuntimeError(
            f"Could not find CSV download link on {support_url}. "
            "The page may require JavaScript rendering or the link text pattern changed."
        )

    r2 = _http_get(csv_url, timeout=60)
    if r2.status_code != 200:
        raise RuntimeError(
            f"CSV download failed HTTP {r2.status_code} from {csv_url}"
        )

    content = r2.content.decode("utf-8-sig")

    # The CSV has section-title rows before each real header, e.g.:
    #   "Windows 11, version 25H2 LCU x64-based"  ← section title
    #   "File name, File version, Date, Time, File size"  ← header
    #   "foo.dll, 10.0.26200.xxx, ..."  ← data
    # Multiple sections (one per arch) separated by blank lines.
    # Only collect rows from sections whose title contains *arch*.
    rows: List[Dict[str, str]] = []
    current_headers: Optional[List[str]] = None
    in_target_section: bool = False
    for line in content.splitlines():
        if not line.strip():
            current_headers = None
            in_target_section = False
            continue
        row = next(csv.reader([line]))
        if not row:
            continue
        if row[0].strip() == "File name":
            current_headers = [c.strip() for c in row]
            continue
        if current_headers is None:
            # Section title row — check if it matches target arch
            section_title = " ".join(row).lower()
            in_target_section = arch.lower() in section_title
            continue
        if not in_target_section:
            continue
        entry = {
            current_headers[i]: row[i].strip() if i < len(row) else ""
            for i in range(len(current_headers))
        }
        fname = entry.get("File name", "")
        basename = fname.replace("\\", "/").split("/")[-1]
        ext = os.path.splitext(basename)[1].lower()
        if ext not in _EXECUTABLE_EXTENSIONS:
            continue
        rows.append({
            "file_name": basename,
            "file_version": entry.get("File version", ""),
            "file_size": entry.get("File size", ""),
            "date": entry.get("Date", ""),
            "time": entry.get("Time", ""),
        })
    return rows


def _version_tuple(ver: str) -> tuple:
    """Convert '10.0.26100.3915' to (10, 0, 26100, 3915) for comparison."""
    try:
        return tuple(int(x) for x in ver.split("."))
    except ValueError:
        return (0,)


def _compare_kb_files(
    current: List[Dict[str, str]],
    previous: List[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Return entries from *current* whose version differs from *previous*.

    Files new in current (absent from previous) are included with
    previous_version=None. Arch variants (e.g. x64 and arm64 copies of the
    same basename) are deduplicated by keeping the highest version per basename.

    Args:
        current: File list from the current month's KB CSV.
        previous: File list from the previous month's KB CSV.

    Returns:
        Subset of *current* (deduplicated by basename) augmented with a
        'previous_version' key.
    """
    # Build previous map: lowercase basename → highest version seen
    prev_map: Dict[str, str] = {}
    for entry in previous:
        fname = entry["file_name"].lower()
        ver = entry["file_version"]
        existing = prev_map.get(fname)
        if existing is None or _version_tuple(ver) > _version_tuple(existing):
            prev_map[fname] = ver

    changed: List[Dict[str, Any]] = []
    seen: set = set()
    for entry in current:
        fname = entry["file_name"].lower()
        if fname in seen:
            continue
        seen.add(fname)
        prev_ver = prev_map.get(fname)
        curr_ver = entry["file_version"]
        if prev_ver is None or curr_ver != prev_ver:
            changed.append({**entry, "previous_version": prev_ver})
    return changed


# ── MCP Tools ─────────────────────────────────────────────────────────────────


@mcp.tool()
def fetch_patch_tuesday_cves(month: str = "") -> List[Dict[str, Any]]:
    """Fetch high-exploitability CVEs from a Patch Tuesday month.

    Returns CVEs where exploitability is 'Exploitation Detected' or
    'Exploitation More Likely'.

    Args:
        month: Target month as YYYY-MM or YYYY-Mon (e.g. '2025-03' or '2025-Mar').
               Defaults to the current month.

    Returns:
        List of dicts: {CVE_ID, Title, Severity, Exploitability,
                        CVSS_BaseScore, CVSS_Vector, KB}
    """
    dt = _parse_month(month) if month else datetime.now()
    slug = f"{dt.year}-{dt.strftime('%b')}"

    r = _http_get(f"{MSRC_CVRF_URL}/{slug}", headers={"Accept": "application/json"}, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"MSRC CVRF API error: HTTP {r.status_code} for month '{slug}'.")

    vulnerabilities = r.json().get("Vulnerability", [])
    target_ids = set(WINDOWS_VERSION_PRODUCT_IDS[DEFAULT_WINDOWS_VERSION])
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
            "KB": _extract_kb_for_vuln(vuln, target_ids),
        })
    return cves


@mcp.tool()
def fetch_kb_updated_files(
    month: str = "",
    windows_version: str = DEFAULT_WINDOWS_VERSION,
    compare_with_previous: bool = True,
) -> str:
    """Fetch .exe/.dll/.sys files updated in a Patch Tuesday KB and save to CSV.

    Resolves the cumulative update KB from MSRC CVRF, downloads Microsoft's
    file-version CSV, diffs against the previous month to find version-changed
    files, enriches each with its local PE FileDescription, and writes the full
    result to BASE_DIR as a CSV file.

    Returns a one-line summary string (path + counts) — no large payload.

    Args:
        month: Target Patch Tuesday month as YYYY-MM or YYYY-Mon. Defaults to current month.
        windows_version: Platform key — currently only '11-25H2' is supported.
        compare_with_previous: If True (default), return only files whose version
                               changed vs. the previous month.
    """
    effective_month = month or datetime.now().strftime("%Y-%b")

    try:
        kb = _fetch_kb_for_platform(effective_month, windows_version)
        if not kb:
            return (
                f"ERROR: No vendor-fix remediation found for "
                f"windows_version='{windows_version}' in month '{effective_month}'."
            )

        current_files = _fetch_kb_file_list(kb)
        total_in_kb = len(current_files)

        prev_kb = None
        if compare_with_previous:
            prev_month = _get_previous_month(effective_month)
            prev_kb = _fetch_kb_for_platform(prev_month, windows_version)
            if prev_kb:
                prev_files = _fetch_kb_file_list(prev_kb)
                candidates = _compare_kb_files(current_files, prev_files)
            else:
                candidates = current_files
        else:
            candidates = current_files

        # Write CSV to BASE_DIR
        os.makedirs(BASE_DIR, exist_ok=True)
        filename = f"{effective_month}_KB{kb}_{windows_version}_updated_files.csv"
        out_path = os.path.join(BASE_DIR, filename)

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["file_name", "description", "file_version", "previous_version"])
            for entry in candidates:
                pe_path = _resolve_pe_path(entry["file_name"])
                desc = (_pe_file_description(pe_path) or "") if pe_path else ""
                writer.writerow([
                    entry["file_name"],
                    desc,
                    entry["file_version"],
                    entry.get("previous_version") or "",
                ])

        prev_info = f", diff vs KB{prev_kb}" if prev_kb else ""
        return (
            f"Saved {len(candidates)} files (of {total_in_kb} in KB{kb}{prev_info}) "
            f"to {out_path}"
        )

    except (RuntimeError, ValueError, PermissionError, OSError) as exc:
        return f"ERROR: {exc}"


@mcp.tool()
def list_iat(filename: str) -> Dict[str, Any]:
    """List unique DLLs imported by a PE file and their FileDescription.

    Parses the IAT of a PE in C:\\Windows\\System32, collects the unique set
    of imported DLL names, then reads the FileDescription from each DLL's
    VS_VERSIONINFO block (when the DLL is also present in System32).

    Args:
        filename: PE filename, e.g. 'clfs.sys', 'ntoskrnl.exe', 'lsass.exe'.
                  No path separators allowed.

    Returns:
        Dict with keys:
          filepath — absolute path that was parsed
          dlls     — list of {dll, description, found_in_system32}
          error    — None on success, error string on failure
    """
    result: Dict[str, Any] = {"filepath": None, "dlls": [], "error": None}

    if os.sep in filename or "/" in filename or "\\" in filename:
        result["error"] = "filename must not contain path separators."
        return result

    pe_path = _resolve_pe_path(filename)
    if pe_path is None:
        result["filepath"] = str(SYSTEM32 / filename)
        result["error"] = f"'{filename}' not found in {SYSTEM32} or {DRIVERS}."
        return result
    result["filepath"] = str(pe_path)

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

    seen: set = set()
    unique_dlls: List[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll_name = entry.dll.decode(errors="replace")
        if dll_name.lower() not in seen:
            seen.add(dll_name.lower())
            unique_dlls.append(dll_name)
    pe.close()

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


# ── PE Index tools ────────────────────────────────────────────────────────────


def _pe_index_available() -> bool:
    return bool(PE_INDEX_DB) and os.path.isdir(os.path.expanduser(PE_INDEX_DB))


def _pe_index_collection():
    db = chromadb.PersistentClient(path=os.path.expanduser(PE_INDEX_DB))
    return db.get_or_create_collection(
        name=PE_INDEX_COLLECTION, metadata={"hnsw:space": "cosine"}
    )


def _pe_index_embed(text: str):
    client = OpenAI(base_url=PE_INDEX_EMBED_URL, api_key="lm-studio")
    resp = client.embeddings.create(model=PE_INDEX_EMBED_MODEL, input=[text])
    return resp.data[0].embedding


def _extract_description(doc_text: str) -> Optional[str]:
    """Pull the Description line out of a pe-index markdown document."""
    parts = doc_text.split("**Description:** ")
    if len(parts) > 1:
        return parts[1].split("\n")[0].strip()
    return None


@mcp.tool()
def search_pe_by_description(keyword: str, top_k: int = 10) -> Dict[str, Any]:
    """Search Windows PE files (DLL/EXE/SYS) by their FileDescription.

    Resolves a subsystem name or vulnerability title to the actual binary.
    For example: 'mailslot' → msfs.sys, 'telephony' → tapisrv.dll.

    Args:
        keyword: Subsystem or description keywords.
        top_k: Number of results (default 10, max 20).
    """
    result: Dict[str, Any] = {"results": [], "count": 0, "error": None}

    if not _pe_index_available():
        result["error"] = "PE_INDEX_DB not configured or path does not exist."
        return result

    top_k = min(max(top_k, 1), 20)

    try:
        col = _pe_index_collection()
        qe = _pe_index_embed(keyword)
        raw = col.query(
            query_embeddings=[qe],
            n_results=top_k,
            where={"source": "pe-index"},
            include=["documents", "metadatas", "distances"],
        )

        if not raw["ids"][0]:
            return result

        for i in range(len(raw["ids"][0])):
            meta = raw["metadatas"][0][i]
            dist = raw["distances"][0][i]
            desc = _extract_description(raw["documents"][0][i])
            result["results"].append({
                "name": meta.get("name", "?"),
                "description": desc,
                "type": meta.get("type", "?"),
                "location": meta.get("location", "?"),
                "version": meta.get("version", ""),
                "similarity": round(1 - dist, 4),
            })

        result["count"] = len(result["results"])
    except Exception as e:
        result["error"] = f"PE index search error: {e}"

    return result


@mcp.tool()
def search_pe_by_name(filename: str) -> Dict[str, Any]:
    """Look up a PE file by exact filename to get its description and metadata.

    Args:
        filename: Exact PE filename, e.g. 'msfs.sys', 'profsvc.dll'.
    """
    result: Dict[str, Any] = {
        "name": filename,
        "description": None,
        "type": None,
        "location": None,
        "version": None,
        "found": False,
        "error": None,
    }

    if not _pe_index_available():
        result["error"] = "PE_INDEX_DB not configured or path does not exist."
        return result

    try:
        col = _pe_index_collection()
        raw = col.get(
            where={"$and": [{"source": "pe-index"}, {"name": filename}]},
            include=["documents", "metadatas"],
        )

        if not raw["ids"]:
            return result

        meta = raw["metadatas"][0]
        result["found"] = True
        result["type"] = meta.get("type")
        result["location"] = meta.get("location")
        result["version"] = meta.get("version")
        result["description"] = _extract_description(raw["documents"][0])

    except Exception as e:
        result["error"] = f"PE index lookup error: {e}"

    return result


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
