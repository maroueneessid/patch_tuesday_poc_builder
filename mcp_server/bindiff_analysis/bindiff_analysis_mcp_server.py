#!/usr/bin/env python3
"""
bindiff_analysis_mcp_server.py — MCP server for BinDiff high-ROI analysis.

Runs BinDiff headless analysis on two BinExport files and extracts high-yield
function differences (functions with similarity between 0 and 1, indicating
logic changes rather than identical or completely different functions).

IMPORTANT VERSION ORDERING:
    - primary_bin: The OLDEST version of the binary (patched version, e.g., before update)
    - secondary_bin: The NEWEST version of the binary (unpatched version, e.g., after update)

    Example filename convention:
        certmmc_10.0.26100.7920.dll  <- OLDER (primary_bin)
        certmmc_10.0.26100.8115.dll  <- NEWER (secondary_bin)

        mmcss_10.0.26100.7309.sys    <- OLDER (primary_bin)
        mmcss_10.0.26100.8115.sys    <- NEWER (secondary_bin)

    The version number (e.g., 10.0.26100.7920) is extracted from the filename
    and validated to ensure primary_bin is older than secondary_bin.

Configuration (env vars):
    BINDIFF_PATH    — Path to bindiff executable (default: auto-detected based on platform)
    OUTPUT_DIR      — Directory for output files (default: same dir as primary_bin)

Platform Support:
    - Windows: Looks for 'bindiff.exe' in PATH or common install locations
    - Linux: Looks for 'bindiff' in PATH

Usage:
    python bindiff_analysis_mcp_server.py
"""

import csv
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mcp.server.fastmcp import FastMCP

# ── Platform Detection ────────────────────────────────────────────────────────

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"


def _get_default_bindiff_paths() -> List[str]:
    """Get default BinDiff executable paths based on platform.

    Returns:
        List of possible BinDiff executable paths/names to try.
    """
    if IS_WINDOWS:
        return [
            "bindiff.exe",
            # Common BinDiff installation paths on Windows
            os.path.expandvars(r"%PROGRAMFILES%\BinDiff\bindiff.exe"),
            os.path.expandvars(r"%PROGRAMFILES(x86)%\BinDiff\bindiff.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\BinDiff\bindiff.exe"),
        ]
    elif IS_LINUX:
        return [
            "bindiff",
            "/usr/bin/bindiff",
            "/usr/local/bin/bindiff",
            os.path.expanduser("~/.local/bin/bindiff"),
        ]
    else:
        # macOS or other platforms
        return ["bindiff"]


def _find_bindiff_executable() -> Tuple[bool, str, str]:
    """Find BinDiff executable on the system.

    Checks for BINDIFF_PATH env var first, then searches default locations.

    Returns:
        Tuple of (found, path_or_message, platform_info)
        - found: True if executable was found
        - path_or_message: Path to executable if found, error message if not
        - platform_info: Current platform description
    """
    platform_info = f"{platform.system()} ({platform.machine()})"

    # Check for explicit BINDIFF_PATH env var first
    env_path = os.environ.get("BINDIFF_PATH")
    if env_path:
        if os.path.isfile(env_path) or shutil.which(env_path):
            return (True, env_path, platform_info)
        else:
            return (
                False,
                f"BINDIFF_PATH environment variable set to '{env_path}' but executable not found.",
                platform_info,
            )

    # Search default locations
    for candidate in _get_default_bindiff_paths():
        # Check if it's an absolute path
        if os.path.isabs(candidate):
            if os.path.isfile(candidate):
                return (True, candidate, platform_info)
        else:
            # Check in PATH using shutil.which
            found_path = shutil.which(candidate)
            if found_path:
                return (True, found_path, platform_info)

    # Not found
    if IS_WINDOWS:
        install_hint = (
            "BinDiff not found. Please install BinDiff or set BINDIFF_PATH environment variable.\n"
            "Download from: https://www.zynamics.com/bindiff.html\n"
            "Alternatively, set BINDIFF_PATH to the full path of bindiff.exe"
        )
    elif IS_LINUX:
        install_hint = (
            "BinDiff not found. Please install BinDiff or set BINDIFF_PATH environment variable.\n"
            "On Linux, BinDiff may be installed from package manager or from source.\n"
            "Alternatively, set BINDIFF_PATH to the full path of the bindiff executable"
        )
    else:
        install_hint = (
            "BinDiff not found. Please install BinDiff or set BINDIFF_PATH environment variable.\n"
            "Alternatively, set BINDIFF_PATH to the full path of the bindiff executable"
        )

    return (False, install_hint, platform_info)


def _check_bindiff_available() -> Tuple[bool, str, str]:
    """Check if BinDiff is available and return status.

    Returns:
        Tuple of (available, path_or_error, platform_info)
    """
    return _find_bindiff_executable()


# ── Server setup ──────────────────────────────────────────────────────────────

# Detect BinDiff at module load time
_BINDIFF_FOUND, _BINDIFF_PATH_OR_ERROR, _PLATFORM_INFO = _find_bindiff_executable()
BINDIFF_PATH = (
    _BINDIFF_PATH_OR_ERROR
    if _BINDIFF_FOUND
    else os.environ.get("BINDIFF_PATH", "bindiff")
)
DEFAULT_OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "")

mcp = FastMCP("bindiff-analysis")

# Print startup status
if _BINDIFF_FOUND:
    print(f"[*] BinDiff found at: {_BINDIFF_PATH_OR_ERROR}")
    print(f"[*] Platform: {_PLATFORM_INFO}")
else:
    print(f"[!] WARNING: BinDiff executable not found.")
    print(f"[!] Platform: {_PLATFORM_INFO}")
    print(f"[!] {_BINDIFF_PATH_OR_ERROR}")
    print(f"[!] The 'analyze_bindiff' tool will fail until BinDiff is installed.")


# ── BinDiff Availability Check ────────────────────────────────────────────────


@mcp.tool()
def check_bindiff_available() -> Dict[str, Any]:
    """Check if BinDiff executable is available on the system.

    Returns information about BinDiff availability, including platform details
    and installation hints if not found.

    Returns:
        Dict with keys:
            - available: bool indicating if BinDiff was found
            - path: Path to BinDiff executable (if found)
            - platform: Current platform information
            - message: Status message with installation hints (if not found)
    """
    found, path_or_message, platform_info = _find_bindiff_executable()

    if found:
        return {
            "available": True,
            "path": path_or_message,
            "platform": platform_info,
            "message": f"BinDiff found at: {path_or_message}",
        }
    else:
        return {
            "available": False,
            "path": None,
            "platform": platform_info,
            "message": path_or_message,
        }


# ── Version Parsing Utilities ────────────────────────────────────────────────


def _version_tuple(ver: str) -> Tuple[int, ...]:
    """Convert '10.0.26100.3915' to (10, 0, 26100, 3915) for comparison.

    Splits version string by '.' and converts each part to integer.
    Falls back to (0,) if parsing fails.

    Args:
        ver: Version string like '10.0.26100.3915'

    Returns:
        Tuple of integers for version comparison.
    """
    try:
        return tuple(int(x) for x in ver.split("."))
    except ValueError:
        return (0,)


def _extract_version_from_filename(filename: str) -> Optional[str]:
    """Extract version string from Patch Tuesday filename.

    Handles naming convention like:
        certmmc_10.0.26100.7920.dll
        mmcss_10.0.26100.7309.sys
        some_file_1.2.3.4.binexport

    The version is expected to be a 4-part version number (e.g., 10.0.26100.7920)
    embedded in the filename, typically after an underscore and before the extension.

    Args:
        filename: The filename (not full path) to extract version from.

    Returns:
        Version string if found, None otherwise.
    """
    # Remove extension first
    name = Path(filename).stem
    # Also handle .BinExport extension
    if name.lower().endswith(".binexport"):
        name = name[:-9]

    # Pattern: underscore followed by version (4 parts separated by dots)
    # Match: name_10.0.26100.7920 or name_1.2.3.4
    # The version pattern: digits.digits.digits.digits
    pattern = r"_(\d+\.\d+\.\d+\.\d+)(?:_|$|\.)"
    match = re.search(pattern, filename)
    if match:
        return match.group(1)

    # Fallback: try to find any 4-part version in the filename
    pattern2 = r"(\d+\.\d+\.\d+\.\d+)"
    match2 = re.search(pattern2, filename)
    if match2:
        return match2.group(1)

    return None


def _validate_version_order(
    primary_bin: str, secondary_bin: str
) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """Validate that primary_bin is older than secondary_bin based on filename versions.

    Args:
        primary_bin: Path to primary (oldest) BinExport file
        secondary_bin: Path to secondary (newest) BinExport file

    Returns:
        Tuple of (is_valid, message, primary_version, secondary_version)
    """
    primary_name = os.path.basename(primary_bin)
    secondary_name = os.path.basename(secondary_bin)

    primary_ver = _extract_version_from_filename(primary_name)
    secondary_ver = _extract_version_from_filename(secondary_name)

    if primary_ver is None:
        return (
            False,
            f"Could not extract version from primary_bin filename: {primary_name}",
            None,
            None,
        )

    if secondary_ver is None:
        return (
            False,
            f"Could not extract version from secondary_bin filename: {secondary_name}",
            primary_ver,
            None,
        )

    primary_tuple = _version_tuple(primary_ver)
    secondary_tuple = _version_tuple(secondary_ver)

    if primary_tuple >= secondary_tuple:
        return (
            False,
            f"Version order invalid: primary_bin (v{primary_ver}) must be OLDER than "
            f"secondary_bin (v{secondary_ver}). Got primary >= secondary.",
            primary_ver,
            secondary_ver,
        )

    return (True, "Version order validated successfully", primary_ver, secondary_ver)


# ── BinDiff Analysis Functions ────────────────────────────────────────────────


def _run_bindiff_engine(
    primary_bin: str, secondary_bin: str, output_dir: str, verbose: bool = False
) -> Tuple[bool, str, Optional[str]]:
    """Run BinDiff headless comparison.

    Args:
        primary_bin: Path to primary (oldest) BinExport file
        secondary_bin: Path to secondary (newest) BinExport file
        output_dir: Directory for output files
        verbose: If True, print progress messages

    Returns:
        Tuple of (success, message, bindiff_db_path)
    """
    # Setup filenames based on BinDiff's default naming convention
    primary_base = Path(primary_bin).stem
    if primary_base.lower().endswith(".binexport"):
        primary_base = primary_base[:-9]
    secondary_base = Path(secondary_bin).stem
    if secondary_base.lower().endswith(".binexport"):
        secondary_base = secondary_base[:-9]

    bindiff_db = os.path.join(output_dir, f"{primary_base}_vs_{secondary_base}.BinDiff")

    if verbose:
        print(
            f"[*] Comparing {os.path.basename(primary_bin)} vs {os.path.basename(secondary_bin)}..."
        )
        print(f"[*] Output will be saved to: {bindiff_db}")

    # Check if BinDiff is available before running
    found, path_or_error, platform_info = _find_bindiff_executable()
    if not found:
        platform_msg = f"Platform: {platform_info}\n"
        return (
            False,
            f"{platform_msg}BinDiff executable not found.\n{path_or_error}",
            None,
        )

    bindiff_exe = path_or_error

    cmd = [
        bindiff_exe,
        f"--primary={primary_bin}",
        f"--secondary={secondary_bin}",
        f"--output_dir={output_dir}",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            return (
                False,
                f"BinDiff engine failed with return code {result.returncode}: {error_msg}",
                None,
            )
    except subprocess.TimeoutExpired:
        return (False, "BinDiff engine timed out after 5 minutes", None)
    except FileNotFoundError:
        return (
            False,
            f"BinDiff executable not found at '{bindiff_exe}'. "
            f"Platform: {_PLATFORM_INFO}\n"
            "Please ensure BinDiff is installed and in PATH, or set BINDIFF_PATH env var.",
            None,
        )
    except Exception as e:
        return (False, f"Error running BinDiff: {str(e)}", None)

    if not os.path.exists(bindiff_db):
        return (
            False,
            f".BinDiff file was not generated at expected path: {bindiff_db}",
            None,
        )

    return (True, "BinDiff comparison completed successfully", bindiff_db)


def _extract_high_yield_functions(
    bindiff_db: str, similarity_min: float = 0.0, similarity_max: float = 1.0
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """Extract high-yield function differences from BinDiff SQLite database.

    Filters for functions with similarity between similarity_min and similarity_max,
    indicating logic changes (not identical or completely different functions).

    Args:
        bindiff_db: Path to .BinDiff SQLite database
        similarity_min: Minimum similarity threshold (default 0.0, exclude identical)
        similarity_max: Maximum similarity threshold (default 1.0, exclude new/removed)

    Returns:
        Tuple of (success, message, list_of_function_records)
    """
    if not os.path.exists(bindiff_db):
        return (False, f"BinDiff database not found: {bindiff_db}", [])

    functions = []
    conn = None

    try:
        conn = sqlite3.connect(bindiff_db)
        cursor = conn.cursor()

        # Query for functions with similarity between 0 and 1 (logic changes)
        # Lower similarity = more interesting changes
        # Ordered by similarity ascending, confidence descending
        query = """
        SELECT
            address1, name1, address2, name2,
            similarity, confidence,
            basicblocks, edges, instructions
        FROM function
        WHERE similarity > ? AND similarity < ?
        ORDER BY similarity ASC, confidence DESC
        """
        cursor.execute(query, (similarity_min, similarity_max))
        rows = cursor.fetchall()

        for row in rows:
            addr1, name1, addr2, name2, sim, conf, bbs, edges, instr = row
            functions.append(
                {
                    "address1": f"0x{addr1:x}" if addr1 else "N/A",
                    "name1": name1 or "N/A",
                    "address2": f"0x{addr2:x}" if addr2 else "N/A",
                    "name2": name2 or "N/A",
                    "similarity": round(sim, 4) if sim is not None else 0.0,
                    "confidence": round(conf, 4) if conf is not None else 0.0,
                    "basic_blocks": bbs or 0,
                    "edges": edges or 0,
                    "instructions": instr or 0,
                }
            )

        return (True, f"Extracted {len(functions)} high-yield functions", functions)

    except sqlite3.Error as e:
        return (False, f"SQLite error: {str(e)}", [])
    finally:
        if conn:
            conn.close()


def _extract_statistics(bindiff_db: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Extract summary statistics from BinDiff SQLite database.

    Returns counts of identical, changed, and unmatched functions,
    plus aggregate statistics (avg similarity, etc.).

    Args:
        bindiff_db: Path to .BinDiff SQLite database

    Returns:
        Tuple of (success, message, statistics_dict)
    """
    if not os.path.exists(bindiff_db):
        return (False, f"BinDiff database not found: {bindiff_db}", {})

    conn = None
    try:
        conn = sqlite3.connect(bindiff_db)
        cursor = conn.cursor()

        # Total functions matched
        cursor.execute("SELECT COUNT(*) FROM function")
        total = cursor.fetchone()[0]

        # Identical functions (similarity = 1.0)
        cursor.execute("SELECT COUNT(*) FROM function WHERE similarity = 1.0")
        identical = cursor.fetchone()[0]

        # Changed functions (0 < similarity < 1.0) - high yield
        cursor.execute(
            "SELECT COUNT(*) FROM function WHERE similarity > 0 AND similarity < 1.0"
        )
        changed = cursor.fetchone()[0]

        # Unmatched functions (similarity = 0)
        cursor.execute("SELECT COUNT(*) FROM function WHERE similarity = 0")
        unmatched = cursor.fetchone()[0]

        # Aggregate statistics for matched functions (similarity > 0)
        cursor.execute(
            "SELECT AVG(similarity), MIN(similarity), MAX(similarity), AVG(confidence) "
            "FROM function WHERE similarity > 0"
        )
        stats = cursor.fetchone()
        avg_sim, min_sim, max_sim, avg_conf = stats

        # Statistics for changed functions only (0 < sim < 1)
        cursor.execute(
            "SELECT AVG(similarity), AVG(confidence) "
            "FROM function WHERE similarity > 0 AND similarity < 1.0"
        )
        changed_stats = cursor.fetchone()
        changed_avg_sim, changed_avg_conf = changed_stats

        statistics = {
            "total_functions": total,
            "identical_functions": identical,
            "changed_functions": changed,
            "unmatched_functions": unmatched,
            "avg_similarity": round(avg_sim, 4) if avg_sim else 0.0,
            "min_similarity": round(min_sim, 4) if min_sim is not None else 0.0,
            "max_similarity": round(max_sim, 4) if max_sim is not None else 0.0,
            "avg_confidence": round(avg_conf, 4) if avg_conf else 0.0,
            "changed_avg_similarity": round(changed_avg_sim, 4)
            if changed_avg_sim
            else 0.0,
            "changed_avg_confidence": round(changed_avg_conf, 4)
            if changed_avg_conf
            else 0.0,
        }

        return (True, "Statistics extracted successfully", statistics)

    except sqlite3.Error as e:
        return (False, f"SQLite error: {str(e)}", {})
    finally:
        if conn:
            conn.close()


def _format_results_csv(functions: List[Dict[str, Any]]) -> str:
    """Format function results as CSV string.

    Args:
        functions: List of function record dictionaries

    Returns:
        CSV-formatted string with header row
    """
    if not functions:
        return "Addr1,Name1,Addr2,Name2,Sim,Conf,BBs,Edges,Inst\n"

    output = StringIO()
    fieldnames = [
        "address1",
        "name1",
        "address2",
        "name2",
        "similarity",
        "confidence",
        "basic_blocks",
        "edges",
        "instructions",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(functions)
    return output.getvalue()


def _format_statistics_csv(
    statistics: Dict[str, Any], primary_version: str, secondary_version: str
) -> str:
    """Format statistics as CSV string.

    Args:
        statistics: Statistics dictionary from _extract_statistics
        primary_version: Primary binary version string
        secondary_version: Secondary binary version string

    Returns:
        CSV-formatted string with key,value pairs
    """
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["metric", "value"])
    writer.writerow(["primary_version", primary_version or "unknown"])
    writer.writerow(["secondary_version", secondary_version or "unknown"])
    writer.writerow(["total_functions", statistics.get("total_functions", 0)])
    writer.writerow(["identical_functions", statistics.get("identical_functions", 0)])
    writer.writerow(["changed_functions", statistics.get("changed_functions", 0)])
    writer.writerow(["unmatched_functions", statistics.get("unmatched_functions", 0)])
    writer.writerow(["avg_similarity", statistics.get("avg_similarity", 0)])
    writer.writerow(["min_similarity", statistics.get("min_similarity", 0)])
    writer.writerow(["max_similarity", statistics.get("max_similarity", 0)])
    writer.writerow(["avg_confidence", statistics.get("avg_confidence", 0)])
    writer.writerow(
        ["changed_avg_similarity", statistics.get("changed_avg_similarity", 0)]
    )
    writer.writerow(
        ["changed_avg_confidence", statistics.get("changed_avg_confidence", 0)]
    )
    return output.getvalue()


def _write_csv_file(csv_path: str, content: str) -> Tuple[bool, str]:
    """Write CSV content to a file.

    Args:
        csv_path: Path to write the CSV file
        content: CSV content string to write

    Returns:
        Tuple of (success, message)
    """
    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            f.write(content)
        return (True, f"CSV written to: {csv_path}")
    except IOError as e:
        return (False, f"Failed to write CSV: {str(e)}")


# ── MCP Tools ──────────────────────────────────────────────────────────────────


@mcp.tool()
def analyze_bindiff(
    primary_bin: str,
    secondary_bin: str,
    similarity_min: float = 0.0,
    similarity_max: float = 1.0,
    output_csv: bool = False,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Run BinDiff analysis on two BinExport files and extract high-yield function differences.

    IMPORTANT VERSION ORDERING:
        - primary_bin: The OLDEST version (older file version, e.g., before patch)
        - secondary_bin: The NEWEST version (newer file version, e.g., after patch)

        Example:
            primary_bin:   certmmc_10.0.26100.7920.dll.BinExport  (OLDER)
            secondary_bin: certmmc_10.0.26100.8115.dll.BinExport  (NEWER)

        The version number is extracted from filenames and validated to ensure
        correct ordering. This is critical for identifying what was patched.

    BinDiff compares the two binaries and finds functions that changed.
    "High-yield" functions are those with similarity between 0 and 1:
        - similarity = 1.0: Identical functions (no change)
        - similarity = 0.0: Completely different or new/removed functions
        - 0 < similarity < 1: Logic changes (most interesting for vulnerability analysis)

    Args:
        primary_bin: Path to primary (OLDEST) BinExport file. Must be older version.
        secondary_bin: Path to secondary (NEWEST) BinExport file. Must be newer version.
        similarity_min: Minimum similarity threshold (default 0.0). Functions below this
                       are considered new/removed. Keep at 0.0 for most analysis.
        similarity_max: Maximum similarity threshold (default 1.0). Functions at 1.0 are
                       identical. Keep below 1.0 to exclude unchanged functions.
        output_csv: If True, write CSV files to disk alongside the BinDiff database.
        verbose: If True, include progress messages in response.

    Returns:
        Dict with keys:
            - success: bool indicating if analysis succeeded
            - message: Status message
            - primary_version: Version extracted from primary_bin filename
            - secondary_version: Version extracted from secondary_bin filename
            - function_count: Number of high-yield functions found
            - functions: List of function records (if any)
            - statistics: Dict with aggregate statistics
            - bindiff_db: Path to generated .BinDiff database
            - functions_csv_path: Path to functions similarity stats CSV file (if output_csv=True)
            - csv: CSV-formatted function results (if output_csv=True)
            - verbose_messages: List of progress messages (if verbose=True)
    """
    messages = []

    # Validate inputs
    if not os.path.exists(primary_bin):
        return {
            "success": False,
            "message": f"Primary BinExport file not found: {primary_bin}",
            "function_count": 0,
            "functions": [],
        }

    if not os.path.exists(secondary_bin):
        return {
            "success": False,
            "message": f"Secondary BinExport file not found: {secondary_bin}",
            "function_count": 0,
            "functions": [],
        }

    # Validate version ordering
    is_valid, version_msg, primary_ver, secondary_ver = _validate_version_order(
        primary_bin, secondary_bin
    )
    if verbose:
        messages.append(f"[*] Primary version: {primary_ver or 'unknown'}")
        messages.append(f"[*] Secondary version: {secondary_ver or 'unknown'}")

    if not is_valid:
        return {
            "success": False,
            "message": version_msg,
            "primary_version": primary_ver,
            "secondary_version": secondary_ver,
            "function_count": 0,
            "functions": [],
            "verbose_messages": messages if verbose else None,
        }

    if verbose:
        messages.append(f"[+] {version_msg}")

    # Determine output directory
    output_dir = DEFAULT_OUTPUT_DIR or os.path.dirname(os.path.abspath(primary_bin))

    # Run BinDiff
    if verbose:
        messages.append(f"[*] Running BinDiff analysis...")

    success, msg, bindiff_db = _run_bindiff_engine(
        primary_bin, secondary_bin, output_dir, verbose
    )
    if not success:
        return {
            "success": False,
            "message": msg,
            "primary_version": primary_ver,
            "secondary_version": secondary_ver,
            "function_count": 0,
            "functions": [],
            "verbose_messages": messages if verbose else None,
        }

    if verbose:
        messages.append(f"[+] {msg}")

    # Extract high-yield functions
    success, msg, functions = _extract_high_yield_functions(
        bindiff_db, similarity_min, similarity_max
    )
    if not success:
        return {
            "success": False,
            "message": msg,
            "primary_version": primary_ver,
            "secondary_version": secondary_ver,
            "bindiff_db": bindiff_db,
            "function_count": 0,
            "functions": [],
            "verbose_messages": messages if verbose else None,
        }

    if verbose:
        messages.append(f"[+] {msg}")

    # Extract statistics
    success, msg, statistics = _extract_statistics(bindiff_db)
    if not success:
        return {
            "success": False,
            "message": msg,
            "primary_version": primary_ver,
            "secondary_version": secondary_ver,
            "bindiff_db": bindiff_db,
            "function_count": len(functions),
            "functions": functions,
            "verbose_messages": messages if verbose else None,
        }

    if verbose:
        messages.append(f"[+] {msg}")

    result = {
        "success": True,
        "message": f"Analysis complete. Found {len(functions)} high-yield functions.",
        "primary_version": primary_ver,
        "secondary_version": secondary_ver,
        "bindiff_db": bindiff_db,
        "function_count": len(functions),
        "functions": functions,
        "statistics": statistics,
    }

    # Write CSV files to disk if requested
    if output_csv:
        # Generate CSV content
        functions_csv_content = _format_results_csv(functions)

        # Determine output file paths based on bindiff_db location
        output_dir = os.path.dirname(bindiff_db)
        base_name = os.path.basename(bindiff_db).replace(".BinDiff", "")

        functions_csv_path = os.path.join(
            output_dir, f"{base_name}_functions_similarity_stats.csv"
        )

        # Write functions CSV
        success, msg = _write_csv_file(functions_csv_path, functions_csv_content)
        if success:
            result["functions_csv_path"] = functions_csv_path
            if verbose:
                messages.append(f"[+] {msg}")
        else:
            result["functions_csv_error"] = msg
            if verbose:
                messages.append(f"[!] {msg}")

        # Also include CSV content in response for programmatic access
        result["csv"] = functions_csv_content

    if verbose:
        result["verbose_messages"] = messages

    return result


@mcp.tool()
def validate_binexport_versions(primary_bin: str, secondary_bin: str) -> Dict[str, Any]:
    """Validate version ordering of two BinExport files without running analysis.

    Checks that the primary_bin (oldest) filename contains an older version number
    than the secondary_bin (newest) filename.

    Filename convention examples:
        - certmmc_10.0.26100.7920.dll  (version: 10.0.26100.7920)
        - mmcss_10.0.26100.7309.sys   (version: 10.0.26100.7309)

    Args:
        primary_bin: Path or filename of primary (OLDEST) BinExport file
        secondary_bin: Path or filename of secondary (NEWEST) BinExport file

    Returns:
        Dict with keys:
            - valid: bool indicating if version ordering is correct
            - message: Explanation of validation result
            - primary_version: Version extracted from primary_bin
            - secondary_version: Version extracted from secondary_bin
            - primary_is_older: bool indicating if primary < secondary
    """
    primary_name = os.path.basename(primary_bin)
    secondary_name = os.path.basename(secondary_bin)

    primary_ver = _extract_version_from_filename(primary_name)
    secondary_ver = _extract_version_from_filename(secondary_name)

    if primary_ver is None:
        return {
            "valid": False,
            "message": f"Could not extract version from primary filename: {primary_name}",
            "primary_version": None,
            "secondary_version": secondary_ver,
            "primary_is_older": False,
        }

    if secondary_ver is None:
        return {
            "valid": False,
            "message": f"Could not extract version from secondary filename: {secondary_name}",
            "primary_version": primary_ver,
            "secondary_version": None,
            "primary_is_older": False,
        }

    primary_tuple = _version_tuple(primary_ver)
    secondary_tuple = _version_tuple(secondary_ver)
    primary_is_older = primary_tuple < secondary_tuple

    if primary_is_older:
        message = (
            f"VALID: primary_bin (v{primary_ver}) is older than secondary_bin (v{secondary_ver}). "
            f"Correct ordering for patch analysis."
        )
    else:
        message = (
            f"INVALID: primary_bin (v{primary_ver}) is NOT older than secondary_bin (v{secondary_ver}). "
            f"For patch analysis, primary_bin should be the older (pre-patch) version."
        )

    return {
        "valid": primary_is_older,
        "message": message,
        "primary_version": primary_ver,
        "secondary_version": secondary_ver,
        "primary_is_older": primary_is_older,
    }


@mcp.tool()
def get_bindiff_summary(bindiff_db: str) -> Dict[str, Any]:
    """Get summary statistics from an existing BinDiff database.

    Reads the .BinDiff SQLite database and returns statistics about the
    comparison results, including counts of matched, changed, and unmatched
    functions.

    Args:
        bindiff_db: Path to existing .BinDiff SQLite database

    Returns:
        Dict with keys:
            - success: bool indicating if database was read successfully
            - message: Status message
            - total_functions: Total number of function matches in database
            - identical_functions: Functions with similarity = 1.0
            - changed_functions: Functions with 0 < similarity < 1.0
            - unmatched_functions: Functions with similarity = 0.0 or no match
            - statistics: Additional statistics (avg similarity, etc.)
    """
    if not os.path.exists(bindiff_db):
        return {
            "success": False,
            "message": f"BinDiff database not found: {bindiff_db}",
        }

    conn = None
    try:
        conn = sqlite3.connect(bindiff_db)
        cursor = conn.cursor()

        # Total functions
        cursor.execute("SELECT COUNT(*) FROM function")
        total = cursor.fetchone()[0]

        # Identical (similarity = 1.0)
        cursor.execute("SELECT COUNT(*) FROM function WHERE similarity = 1.0")
        identical = cursor.fetchone()[0]

        # Changed (0 < similarity < 1.0)
        cursor.execute(
            "SELECT COUNT(*) FROM function WHERE similarity > 0 AND similarity < 1.0"
        )
        changed = cursor.fetchone()[0]

        # Unmatched (similarity = 0)
        cursor.execute("SELECT COUNT(*) FROM function WHERE similarity = 0")
        unmatched = cursor.fetchone()[0]

        # Statistics
        cursor.execute(
            "SELECT AVG(similarity), MIN(similarity), MAX(similarity), AVG(confidence) "
            "FROM function WHERE similarity > 0"
        )
        stats = cursor.fetchone()
        avg_sim, min_sim, max_sim, avg_conf = stats

        return {
            "success": True,
            "message": f"Summary for {os.path.basename(bindiff_db)}",
            "total_functions": total,
            "identical_functions": identical,
            "changed_functions": changed,
            "unmatched_functions": unmatched,
            "statistics": {
                "avg_similarity": round(avg_sim, 4) if avg_sim else 0,
                "min_similarity": round(min_sim, 4) if min_sim is not None else 0,
                "max_similarity": round(max_sim, 4) if max_sim is not None else 0,
                "avg_confidence": round(avg_conf, 4) if avg_conf else 0,
            },
        }

    except sqlite3.Error as e:
        return {
            "success": False,
            "message": f"SQLite error: {str(e)}",
        }
    finally:
        if conn:
            conn.close()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
