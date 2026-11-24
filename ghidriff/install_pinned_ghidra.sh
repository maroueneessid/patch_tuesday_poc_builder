#!/usr/bin/env bash
# Extract the EXACT Ghidra install used by the pinned ghidra-mcp server to the host,
# so ghidriff can run against a byte-identical Ghidra version (no downloads, no rebuilds).
#
# Rationale (skills/ghidriff-pipeline/SKILL.md Phase 0): DomainFiles written by a NEWER
# Ghidra than the ghidra-mcp server are unreadable by it ("this file was created with a
# newer version of Ghidra, and can not be processed"). Copying the server's own Ghidra
# out of its container works out of the box — no monkey patching, no downloads.
#
# Workspace contract (checked, not machine-specific):
#   <BASE>/diffs/            staged patched/vulnerable binaries per CVE cluster
#   <BASE>/ghidra_projects/  Ghidra projects (mounted as /projects by the MCP server)
#   <BASE>/Analysis/         outputs
# The pin is stored under <BASE>/.ghidra_pin/<version>/ — version-stamped so several
# pinned versions can coexist while "playing with versions".
#
# Usage:
#   ./install_pinned_ghidra.sh [dest_dir] [container]
# Env:
#   DIFFING_BASE_DIR   override workspace root (auto-detected otherwise)
#   GHIDRA_PIN_DIR     override pin destination
#   GHIDRA_MCP_CONTAINER  override server container name
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- workspace autodetection -----------------------------------------------
find_base() {
    local dir="$1"
    for _ in 1 2 3 4 5; do
        if [ -d "${dir}/diffs" ] && [ -d "${dir}/ghidra_projects" ]; then
            echo "${dir}"; return 0
        fi
        local parent; parent="$(dirname "${dir}")"
        [ "${parent}" = "${dir}" ] && break
        dir="${parent}"
    done
    return 1
}
BASE="${DIFFING_BASE_DIR:-$(find_base "${SCRIPT_DIR}" || true)}"
if [ -z "${BASE}" ]; then
    echo "ERROR: workspace root not found. Expected directory contract:" >&2
    echo "       <BASE>/diffs/ + <BASE>/ghidra_projects/ (+ Analysis/)" >&2
    echo "       Set DIFFING_BASE_DIR to your workspace root." >&2
    exit 1
fi

CONTAINER="${2:-${GHIDRA_MCP_CONTAINER:-ghidra_mcp-ghidra-mcp-1}}"

echo "==> [1/4] Checking ghidra-mcp server '${CONTAINER}' is running..."
docker ps --filter "name=${CONTAINER}" --filter status=running --format '{{.Names}}' | grep -q . \
  || { echo "ERROR: ${CONTAINER} is not running (docker compose up -d in mcp_server/ghidra_mcp/)"; exit 1; }

echo "==> [2/4] Reading the server's Ghidra version (this defines the pipeline pin)..."
SERVER_VER=$(docker exec "${CONTAINER}" sh -c "grep -m2 application.version /opt/ghidra/Ghidra/application.properties")
VER_NUM=$(echo "${SERVER_VER}" | sed 's/.*=//')
echo "    server: ${SERVER_VER}   (workspace: ${BASE})"

if [ -n "${1:-}" ]; then
    DEST="$1"                                 # explicit dest wins
elif [ -n "${GHIDRA_PIN_DIR:-}" ]; then
    DEST="${GHIDRA_PIN_DIR}"
elif [ -f "${BASE}/.ghidra_pin/${VER_NUM}/Ghidra/application.properties" ]; then
    DEST="${BASE}/.ghidra_pin/${VER_NUM}"     # already pinned
else
    DEST="${BASE}/.ghidra_pin/${VER_NUM}"     # fresh extract into the workspace
fi

if [ -f "${DEST}/Ghidra/application.properties" ]; then
    DEST_VER=$(grep -m1 application.version "${DEST}/Ghidra/application.properties")
    echo "==> [3/4] Pin already present at ${DEST} (${DEST_VER})"
    if [ "${SERVER_VER}" != "${DEST_VER}" ]; then
        echo "ERROR: pin version differs from the server's (${SERVER_VER} vs ${DEST_VER})"
        echo "       Remove it (or point GHIDRA_PIN_DIR elsewhere) and re-run."
        exit 2
    fi
else
    echo "==> [3/4] Streaming /opt/ghidra out of the container to ${DEST} (~850MB, one-time)..."
    # pre-clean any partial state (incl. a previous docker cp staging dir)
    rm -rf "${DEST}" "$(dirname "${DEST}")/ghidra" 2>/dev/null || true
    mkdir -p "${DEST}"
    if ! docker exec "${CONTAINER}" tar -C /opt -cf - ghidra 2>/dev/null | tar -C "${DEST}" -xf -; then
        echo "    tar streaming unavailable (no tar in container?) — docker cp fallback..."
        rm -rf "${DEST}" 2>/dev/null || true
        mkdir -p "${DEST}"
        docker cp "${CONTAINER}:/opt/ghidra" "$(dirname "${DEST}")"
        cp -a "$(dirname "${DEST}")/ghidra/." "${DEST}/"
        rm -rf "$(dirname "${DEST}")/ghidra"
    fi
    DEST_VER=$(grep -m1 application.version "${DEST}/Ghidra/application.properties")
fi

echo "==> [4/4] Final check..."
if [ "${SERVER_VER}" != "${DEST_VER}" ]; then
    echo "ERROR: extracted version differs from server (${SERVER_VER} vs ${DEST_VER})"
    exit 2
fi

cat <<EOF

Pinned Ghidra ready:  ${DEST}
Version:              ${DEST_VER}

Use in ghidriff runs (run_diff.sh picks this up automatically):
  -v "${DEST}:/ghidra_home" -e GHIDRA_INSTALL_DIR=/ghidra_home
EOF
