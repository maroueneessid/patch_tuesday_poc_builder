#!/usr/bin/env python3
"""
fetch_binaries.py - Download patched & vulnerable Windows binaries for a given CVE.

Inspired by DiffRays' file_downloader module.

Usage:
    # CVE mode - automatically resolves component and patch month
    python fetch_binaries.py --cve CVE-2025-29824

    # Manual mode - specify component filename and patch month directly
    python fetch_binaries.py --filename clfs.sys --patch-month 2025-04

    # With options
    python fetch_binaries.py --cve CVE-2025-29824 --windows-version 11-23H2 --output-dir ./bins
"""

import argparse
import gzip
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

# ── Constants ────────────────────────────────────────────────────────────────

MSRC_API_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"
WINBINDEX_URL = "https://winbindex.m417z.com/data/by_filename_compressed"
SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols"
DEFAULT_WINDOWS_VERSION = "11-24H2"

# Maps Microsoft Security tag names → Windows binary filenames
COMPONENT_MAP: List[Dict[str, str]] = [
    {"name": "Windows Common Log File System Driver", "file": "clfs.sys"},
    {"name": "Windows Composite Image File System", "file": "cimfs.sys"},
    {"name": "Windows DWM Core Library", "file": "dwmcore.dll"},
    {"name": "Windows Telephony Service", "file": "tapisrv.dll"},
    {"name": "Windows Kernel", "file": "ntoskrnl.exe"},
    {"name": "Windows USB Print Driver", "file": "usbprint.sys"},
    {"name": "Windows upnphost.dll", "file": "upnphost.dll"},
    {"name": "Windows Internet Information Services", "file": "http.sys"},
    {"name": "Microsoft Streaming Service", "file": "mskssrv.sys"},
    {"name": "Windows Resilient File System (ReFS)", "file": "refs.sys"},
    {"name": "Windows Win32 Kernel Subsystem", "file": "win32kfull.sys"},
    {"name": "Windows TCP/IP", "file": "tcpip.sys"},
    {"name": "Kernel Streaming WOW Thunk Service Driver", "file": "ksthunk.sys"},
    {"name": "Windows exFAT File System", "file": "exfat.sys"},
    {"name": "Windows Fast FAT Driver", "file": "fastfat.sys"},
    {"name": "Windows USB Video Driver", "file": "usbvideo.sys"},
    {"name": "Microsoft Management Console", "file": "mmc.exe"},
    {"name": "Microsoft Local Security Authority Server (lsasrv)", "file": "lsasrv.dll"},
    {"name": "Windows Message Queuing", "file": "mqsvc.exe"},
    {"name": "Windows Kerberos", "file": "kerberos.dll"},
    {"name": "Windows Ancillary Function Driver for WinSock", "file": "afd.sys"},
    {"name": "Winlogon", "file": "winlogon.exe"},
    {"name": "Windows Hyper-V NT Kernel Integration VSP", "file": "vkrnlintvsp.sys"},
    {"name": "Windows Hyper-V", "file": "hvix64.exe"},
    {"name": "Windows Hyper-V", "file": "hvax64.exe"},
    {"name": "Windows Hyper-V", "file": "hvloader.dll"},
    {"name": "Windows Hyper-V", "file": "kdhvcom.dll"},
    {"name": "Windows Power Dependency Coordinator", "file": "pdc.sys"},
    {"name": "Windows Cryptographic Services", "file": "cryptsvc.dll"},
    {"name": "Windows Remote Desktop Services", "file": "termsrv.dll"},
    {"name": "Windows BitLocker", "file": "fvevol.sys"},
    {"name": "Windows Core Messaging", "file": "CoreMessaging.dll"},
    {"name": "Windows Boot Manager", "file": "bootmgfw.efi"},
    {"name": "Windows Boot Loader", "file": "winload.exe"},
    {"name": "Windows Task Scheduler", "file": "WPTaskScheduler.dll"},
    {"name": "Windows Secure Channel", "file": "schannel.dll"},
    {"name": "Windows Local Session Manager (LSM)", "file": "lsm.dll"},
    {"name": "Windows LDAP - Lightweight Directory Access Protocol", "file": "Wldap32.dll"},
    {"name": "Web Threat Defense (WTD.sys)", "file": "wtd.sys"},
    {"name": "Windows Storage Port Driver", "file": "storport.sys"},
    {"name": "Windows NTFS", "file": "ntfs.sys"},
    {"name": "Windows Netlogon", "file": "netlogon.dll"},
    {"name": "Windows Remote Access Connection Manager", "file": "rasman.dll"},
    {"name": "Windows Local Security Authority Subsystem Service (LSASS)", "file": "lsass.exe"},
    {"name": "Windows DHCP Server", "file": "dhcpssvc.dll"},
]

MONTH_NAMES = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def info(msg: str) -> None:
    print(f"[*] {msg}")


def ok(msg: str) -> None:
    print(f"[+] {msg}")


def err(msg: str) -> None:
    print(f"[-] {msg}", file=sys.stderr)


def get_patch_tuesday(year: int, month: int) -> datetime:
    """Return the second Tuesday of the given month."""
    first_day = datetime(year, month, 1)
    days_to_tuesday = (1 - first_day.weekday()) % 7  # 1 = Tuesday
    if days_to_tuesday == 0 and first_day.weekday() != 1:
        days_to_tuesday = 7
    return datetime(year, month, 1 + days_to_tuesday + 7)


def is_near_patch_tuesday(date_str: str, target_month: str, tolerance: int = 2) -> bool:
    """Check if *date_str* (YYYY-MM-DD) falls within ±tolerance days of
    Patch Tuesday for *target_month* (YYYY-MM)."""
    try:
        date = datetime.strptime(date_str, "%Y-%m-%d")
        y, m = map(int, target_month.split("-"))
        if date.year != y or date.month != m:
            return False
        pt = get_patch_tuesday(y, m)
        return abs((date - pt).days) <= tolerance
    except (ValueError, TypeError):
        return False


# ── Step 1: Resolve CVE → filename + patch month ────────────────────────────

def validate_cve(cve_id: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", cve_id, re.IGNORECASE))


def fetch_cve_data(cve_id: str) -> Optional[Dict]:
    """Query the Microsoft MSRC API for CVE metadata."""
    url = f"{MSRC_API_URL}/{cve_id}"
    try:
        r = requests.get(url, headers={"Accept": "application/json"}, timeout=30)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            err(f"CVE {cve_id} not found in the Microsoft database")
        else:
            err(f"MSRC API returned HTTP {r.status_code}")
    except requests.RequestException as exc:
        err(f"MSRC request failed: {exc}")
    return None


def resolve_cve(cve_id: str) -> Tuple[str, str]:
    """Return (binary_filename, patch_month_YYYY-MM) from a CVE ID.
    Exits on failure."""
    data = fetch_cve_data(cve_id)
    if not data:
        sys.exit(1)

    tag = data.get("tag", "")
    if tag.startswith("Role: "):
        tag = tag[6:]

    # Find matching binary filename
    filenames = [c["file"] for c in COMPONENT_MAP if c["name"] == tag]
    if not filenames:
        err(f"No component mapping for tag '{tag}'. Use --filename / --patch-month instead.")
        sys.exit(1)

    # Parse release month
    release_number = data.get("releaseNumber", "")  # e.g. "2025-Sep"
    try:
        year, month_name = release_number.split("-")
        patch_month = f"{year}-{MONTH_NAMES[month_name]}"
    except (ValueError, KeyError):
        err(f"Cannot parse release number '{release_number}'")
        sys.exit(1)

    ok(f"CVE tag: {tag}")
    ok(f"Component file: {filenames[0]}")
    ok(f"Patch month: {patch_month}")

    return filenames[0], patch_month


# ── Step 2: Download WinBIndex version database ─────────────────────────────

def download_winbindex_db(filename: str, output_dir: str) -> str:
    """Download the compressed JSON database for *filename* from WinBIndex.
    Returns the local path to the .json.gz file."""
    url = f"{WINBINDEX_URL}/{filename}.json.gz"
    local_path = os.path.join(output_dir, f"{Path(filename).stem}.json.gz")

    info(f"Downloading WinBIndex database: {url}")
    try:
        r = requests.get(url, stream=True, timeout=60)
        r.raise_for_status()
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        ok(f"Saved database: {local_path}")
        return local_path
    except requests.RequestException as exc:
        err(f"Failed to download WinBIndex database: {exc}")
        sys.exit(1)


# ── Step 3: Select patched & vulnerable versions ────────────────────────────

def _extract_version_entry(
    entry: Dict, sha256: str, kb_id: str, kb_data: Dict, source_label: str
) -> Optional[Dict]:
    """Build a version-entry dict from a WinBIndex record, or None if
    essential fields are missing."""
    file_info = entry.get("fileInfo", {})
    timestamp = file_info.get("timestamp")
    virtual_size = file_info.get("virtualSize")
    update_info = kb_data.get("updateInfo", {})
    release_date = update_info.get("releaseDate")

    assemblies = kb_data.get("assemblies", {})
    if assemblies:
        first = next(iter(assemblies.values()))
        release_version = first.get("assemblyIdentity", {}).get("version", "")
    else:
        release_version = update_info.get("releaseVersion", "")

    if not all([timestamp, virtual_size, release_date, release_version]):
        return None

    return {
        "timestamp": timestamp,
        "virtual_size": virtual_size,
        "sha256": sha256,
        "release_date": release_date,
        "kb_id": kb_id,
        "release_version": release_version,
        "source": source_label,
    }


def select_versions(
    db_path: str, windows_version: str, patch_month: str
) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Parse the WinBIndex database and return (patched, vulnerable) version
    info dicts.  The patched version comes from the patch month's Patch
    Tuesday; the vulnerable version comes from the previous month."""

    with gzip.open(db_path, "rt", encoding="utf-8") as f:
        data = json.load(f)

    target_year, target_month = map(int, patch_month.split("-"))

    # Previous month
    if target_month == 1:
        prev_year, prev_month = target_year - 1, 12
    else:
        prev_year, prev_month = target_year, target_month - 1
    prev_month_str = f"{prev_year:04d}-{prev_month:02d}"
    prev_pt = get_patch_tuesday(prev_year, prev_month)

    info(f"Patch month: {patch_month}  (PT: {get_patch_tuesday(target_year, target_month).date()})")
    info(f"Vulnerable month: {prev_month_str}  (PT: {prev_pt.date()})")

    patch_versions: Dict[str, Dict] = {}
    vuln_pt: Dict[str, Dict] = {}
    vuln_after_pt: Dict[str, Dict] = {}
    vuln_all: Dict[str, Dict] = {}

    def _process_entry(ve: Dict) -> None:
        rd = ve["release_date"]
        rv = ve["release_version"]

        # Patched: near current month's Patch Tuesday
        if is_near_patch_tuesday(rd, patch_month):
            if rv not in patch_versions or rd > patch_versions[rv]["release_date"]:
                patch_versions[rv] = ve

        # Vulnerable: from previous month
        elif rd.startswith(prev_month_str):
            if rv not in vuln_all or rd > vuln_all[rv]["release_date"]:
                vuln_all[rv] = ve
            try:
                rd_dt = datetime.strptime(rd, "%Y-%m-%d")
                if is_near_patch_tuesday(rd, prev_month_str):
                    if rv not in vuln_pt or rd > vuln_pt[rv]["release_date"]:
                        vuln_pt[rv] = ve
                elif rd_dt >= prev_pt:
                    if rv not in vuln_after_pt or rd > vuln_after_pt[rv]["release_date"]:
                        vuln_after_pt[rv] = ve
            except ValueError:
                pass

    for sha256, entry in data.items():
        fi = entry.get("fileInfo", {})
        if not fi.get("timestamp") or not fi.get("virtualSize"):
            continue

        win_vers = entry.get("windowsVersions", {})

        # Direct matches
        if windows_version in win_vers:
            for kb_id, kb_data in win_vers[windows_version].items():
                ve = _extract_version_entry(entry, sha256, kb_id, kb_data,
                                            f"direct ({windows_version})")
                if ve:
                    _process_entry(ve)

        # Fallback: otherWindowsVersions cross-references
        for cur_ver, ver_data in win_vers.items():
            if cur_ver == windows_version:
                continue
            for kb_id, kb_data in ver_data.items():
                other = kb_data.get("updateInfo", {}).get("otherWindowsVersions", [])
                if windows_version in other:
                    ve = _extract_version_entry(entry, sha256, kb_id, kb_data,
                                                f"fallback ({cur_ver}->{windows_version})")
                    if ve:
                        _process_entry(ve)

    def _pick_best(d: Dict[str, Dict]) -> Optional[Dict]:
        if not d:
            return None
        by_date = sorted(d.values(), key=lambda v: v["release_date"], reverse=True)
        direct = [v for v in by_date if v["source"].startswith("direct")]
        return direct[0] if direct else by_date[0]

    patched = _pick_best(patch_versions)
    vulnerable = _pick_best(vuln_pt) or _pick_best(vuln_after_pt) or _pick_best(vuln_all)

    if patched:
        ok(f"Patched  → {patched['release_version']}  ({patched['release_date']})")
    else:
        err("No patched version found")

    if vulnerable:
        ok(f"Vulnerable → {vulnerable['release_version']}  ({vulnerable['release_date']})")
    else:
        err("No vulnerable version found")

    return patched, vulnerable


# ── Step 4: Download binaries from Microsoft Symbol Server ───────────────────

def download_binary(version_info: Dict, filename: str, label: str, output_dir: str) -> str:
    """Download a binary from the Microsoft Symbol Server.
    Returns the local file path."""
    ts_hex = f"{version_info['timestamp']:08X}"
    sz_hex = f"{version_info['virtual_size']:X}"
    url = f"{SYMBOL_SERVER_URL}/{filename}/{ts_hex}{sz_hex}/{filename}"

    stem = Path(filename).stem
    ext = Path(filename).suffix
    local_name = f"{stem}_{version_info['release_version']}{ext}"
    local_path = os.path.join(output_dir, local_name)

    info(f"Downloading {label}: {url}")
    try:
        r = requests.get(url, stream=True, timeout=120)
        r.raise_for_status()
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        size = os.path.getsize(local_path)
        ok(f"Saved {label}: {local_path}  ({size:,} bytes)")
        return local_path
    except requests.RequestException as exc:
        err(f"Failed to download {label}: {exc}")
        sys.exit(1)


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download patched & vulnerable Windows binaries for a CVE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python fetch_binaries.py --cve CVE-2025-29824
  python fetch_binaries.py --filename clfs.sys --patch-month 2025-04
  python fetch_binaries.py --cve CVE-2025-29824 -w 11-23H2 -o ./bins
""",
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--cve", help="CVE ID (e.g. CVE-2025-29824)")
    source.add_argument("--filename", "-f", help="Binary filename (e.g. clfs.sys)")

    parser.add_argument("--patch-month", "-m",
                        help="Patch month YYYY-MM (required with --filename)")
    parser.add_argument("--windows-version", "-w", default=DEFAULT_WINDOWS_VERSION,
                        help=f"Target Windows version (default: {DEFAULT_WINDOWS_VERSION})")
    parser.add_argument("--output-dir", "-o", default=".",
                        help="Directory to save downloaded files (default: cwd)")

    args = parser.parse_args()

    # Resolve inputs
    if args.cve:
        cve_id = args.cve.strip().upper()
        if not validate_cve(cve_id):
            err("Invalid CVE format. Expected CVE-YYYY-NNNNN")
            sys.exit(1)
        filename, patch_month = resolve_cve(cve_id)
    else:
        if not args.patch_month:
            err("--patch-month is required when using --filename")
            sys.exit(1)
        if not re.match(r"^\d{4}-\d{2}$", args.patch_month):
            err("Invalid --patch-month format. Expected YYYY-MM")
            sys.exit(1)
        filename = args.filename
        patch_month = args.patch_month

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    # Download WinBIndex version database
    db_path = download_winbindex_db(filename, output_dir)

    try:
        # Select versions
        patched, vulnerable = select_versions(db_path, args.windows_version, patch_month)

        if not patched:
            err(f"No patched version found for {patch_month}")
            sys.exit(1)
        if not vulnerable:
            err("No vulnerable version found for previous month")
            sys.exit(1)

        # Download both binaries
        print()
        patched_path = download_binary(patched, filename, "patched", output_dir)
        vulnerable_path = download_binary(vulnerable, filename, "vulnerable", output_dir)

        # Summary
        print()
        ok("Done!")
        print(f"    Patched:    {patched_path}")
        print(f"    Vulnerable: {vulnerable_path}")

    finally:
        # Clean up the temporary database file
        try:
            os.remove(db_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
