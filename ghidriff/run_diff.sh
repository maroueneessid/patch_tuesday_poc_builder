#!/usr/bin/env bash
# Validated ghidriff diff invocation — runs the pipeline exactly as validated on
# 2026-11-19 (CVE-2026-105501 MSI cluster): Ghidra pinned to the ghidra-mcp server's
# version, root user + PYTHONPATH override. Produces the .ghidriff.md/.json outputs
# and the Ghidra project under ghidra_projects/, ready for the ghidra-mcp server.
#
# Workspace contract (auto-detected; no absolute paths baked in):
#   <BASE>/diffs/<CVE_CHAIN>/           staged binaries (2 versions + 2 PDBs)
#   <BASE>/ghidra_projects/             Ghidra projects (server mounts it as /projects)
#   <BASE>/Analysis/<CVE_CHAIN>/ghidriff/   diff outputs
#   <BASE>/.ghidra_pin/<version>/       pinned Ghidra (auto-created via install script)
# BASE is found by walking up from this script's directory; override with DIFFING_BASE_DIR.
#
# Usage:
#   ./run_diff.sh [--check-only] <CVE_CHAIN> <PROJECT_NAME> <old_bin> <new_bin> [extra args...]
#   e.g. ./run_diff.sh CVE-2026-105501_CVE-2026-119398 CVE-2026-105501_MSI \
#            msi_10.0.26100.9711.dll msi_10.0.26100.9974.dll
#
# Env: DIFFING_BASE_DIR, GHIDRA_PIN_DIR, DIFFING_BASE_DIR overrides,
#      GHIDRA_MCP_CONTAINER, GHIDRIFF_IMAGE (default ghcr.io/clearbluejar/ghidriff:latest),
#      GHIDRIFF_TIMEOUT_SEC (default 3600)
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
CHECK_ONLY=0
if [ "${1:-}" = "--check-only" ]; then CHECK_ONLY=1; shift; fi
if [ "$#" -lt 4 ]; then
    echo "usage: $0 [--check-only] <CVE_CHAIN> <PROJECT_NAME> <old_bin> <new_bin> [extra ghidriff args...]"
    exit 1
fi
CVE_CHAIN="$1"; PROJ_NAME="$2"; OLD_BIN="$3"; NEW_BIN="$4"; shift 4

BASE="${DIFFING_BASE_DIR:-$(find_base "${SCRIPT_DIR}" || true)}"
if [ -z "${BASE}" ]; then
    echo "ERROR: workspace root not found. Expected directory contract:" >&2
    echo "       <BASE>/diffs/ + <BASE>/ghidra_projects/ (+ Analysis/)" >&2
    echo "       Set DIFFING_BASE_DIR to your workspace root." >&2
    exit 1
fi
MCP_CONTAINER="${GHIDRA_MCP_CONTAINER:-ghidra_mcp-ghidra-mcp-1}"
GHIDRIFF_IMAGE="${GHIDRIFF_IMAGE:-ghcr.io/clearbluejar/ghidriff:latest}"
TIMEOUT_SEC="${GHIDRIFF_TIMEOUT_SEC:-3600}"

IN_DIR="${BASE}/diffs/${CVE_CHAIN}"
OUT_DIR="${BASE}/Analysis/${CVE_CHAIN}/ghidriff"
PROJ_DIR="${BASE}/ghidra_projects"
PIN_DIR_ROOT="${BASE}/.ghidra_pin"

fail() { echo "STOP: $*" >&2; exit 2; }

echo "==> [1/6] Version gate — server Ghidra vs pinned Ghidra (must be EQUAL)..."
docker ps --filter "name=${MCP_CONTAINER}" --filter status=running --format '{{.Names}}' | grep -q . \
    || fail "ghidra-mcp server '${MCP_CONTAINER}' is not running"
SERVER_GHIDRA=$(docker exec "${MCP_CONTAINER}" sh -c "grep -m2 application.version /opt/ghidra/Ghidra/application.properties")
VER_NUM=$(echo "${SERVER_GHIDRA}" | sed 's/.*=//')

GHIDRA_PIN_DIR="${GHIDRA_PIN_DIR:-}"
if [ -z "${GHIDRA_PIN_DIR}" ]; then
    if [ -f "${PIN_DIR_ROOT}/${VER_NUM}/Ghidra/application.properties" ]; then
        GHIDRA_PIN_DIR="${PIN_DIR_ROOT}/${VER_NUM}"
    else
        # probe any pre-pinned versions inside the workspace
        for d in "${PIN_DIR_ROOT}"/*/Ghidra/application.properties; do
            if [ -f "${d}" ] && grep -q "^application.version=${VER_NUM}\$" "${d}"; then
                GHIDRA_PIN_DIR="$(dirname "$(dirname "${d}")")"; break
            fi
        done
    fi
fi
if [ -n "${GHIDRA_PIN_DIR}" ]; then
    PIN_GHIDRA=$(grep -m2 application.version "${GHIDRA_PIN_DIR}/Ghidra/application.properties")
else
    GHIDRA_PIN_DIR="${PIN_DIR_ROOT}/${VER_NUM}"
    PIN_GHIDRA="(not extracted yet)"
fi
echo "    server: ${SERVER_GHIDRA}"
echo "    pin:    ${PIN_GHIDRA}  [${GHIDRA_PIN_DIR}]"
if [ "${SERVER_GHIDRA}" != "${PIN_GHIDRA}" ]; then
    echo "    -> extracting/verifying via install script..." >&2
    "${SCRIPT_DIR}/install_pinned_ghidra.sh" "${GHIDRA_PIN_DIR}" "${MCP_CONTAINER}" || \
        fail "pin provisioning failed. NEVER monkey-patch — align versions instead."
    PIN_GHIDRA=$(docker exec "${MCP_CONTAINER}" sh -c "grep -m2 application.version /opt/ghidra/Ghidra/application.properties")
    if [ "${SERVER_GHIDRA}" != "${PIN_GHIDRA}" ]; then
        echo "    pin dir:  ${GHIDRA_PIN_DIR}"; fail "pin does not match server after provisioning"
    fi
    PY2=$(grep -m2 application.version "${GHIDRA_PIN_DIR}/Ghidra/application.properties")
    if [ "${SERVER_GHIDRA}" != "${PY2}" ]; then
        echo "    pin dir:  ${GHIDRA_PIN_DIR}"; fail "pin does not match server after provisioning"
    fi
    echo "    pin now matches server."
    PIN_GHIDRA="${PY2}"
fi
[ "${CHECK_ONLY}" = "0" ] || { echo "--check-only: gate passed, stopping here."; exit 0; }

echo "==> [2/6] Staging check..."
for f in "${IN_DIR}/${OLD_BIN}" "${IN_DIR}/${OLD_BIN%.dll}.pdb" \
         "${IN_DIR}/${NEW_BIN}" "${IN_DIR}/${NEW_BIN%.dll}.pdb"; do
    [ -f "${f}" ] || fail "missing staged file: ${f}"
done
mkdir -p "${OUT_DIR}"
PROJ_FULL="${PROJ_NAME}-${OLD_BIN}-${NEW_BIN}"
if [ -e "${PROJ_DIR}/${PROJ_FULL}" ]; then
    echo "    NOTE: existing project dir ${PROJ_FULL} — reuse only works for the SAME"
    echo "          Ghidra version + owner (root). Deleting it to force a clean run."
    rm -rf "${PROJ_DIR}/${PROJ_FULL}"
    sleep 3
fi

echo "==> [3/6] Launching ghidriff (detached, --user root, pinned Ghidra)..."
CONTAINER_STAMP="$(echo "${CVE_CHAIN}" | tr -c 'a-zA-Z0-9' '_' | cut -c1-40)_$(date +%s)"
RUN_NAME="ghidriff_${CONTAINER_STAMP}"
docker rm -f "${RUN_NAME}" >/dev/null 2>&1 || true
MSYS_NO_PATHCONV=1 docker run -d --user root --name "${RUN_NAME}" \
    -v "${IN_DIR}:/ghidriff_in" \
    -v "${PROJ_DIR}:/ghidriff_projects" \
    -v "${OUT_DIR}:/ghidriff_out" \
    -v "${GHIDRA_PIN_DIR}:/ghidra_home" \
    -e GHIDRA_INSTALL_DIR=/ghidra_home \
    -e "PYTHONPATH=/home/vscode/.local/lib/python3.13/site-packages" \
    "${GHIDRIFF_IMAGE}" \
    -o /ghidriff_out -p /ghidriff_projects -n "${PROJ_NAME}" \
    -s /ghidriff_out/symbols -g /ghidriff_out/gzfs \
    --log-path /ghidriff_out/ghidriff.log \
    "/ghidriff_in/${OLD_BIN}" "/ghidriff_in/${NEW_BIN}" "$@"
echo "    container: ${RUN_NAME}  (watch: docker logs -f ${RUN_NAME})"

echo "==> [4/6] Waiting for completion (timeout ${TIMEOUT_SEC}s)..."
elapsed=0
while :; do
    STATUS=$(docker ps -a --filter "name=${RUN_NAME}" --format '{{.Status}}')
    case "${STATUS}" in
        "Exited (0)"*) echo "    ${STATUS}"; break ;;
        Exited*) echo "    ${STATUS}"
                 docker logs --tail 40 "${RUN_NAME}"
                 fail "ghidriff exited non-zero — inspect logs above. Report the error; do not patch."
                 ;;
        *)  if [ "${elapsed}" -ge "${TIMEOUT_SEC}" ]; then
                fail "timed out after ${TIMEOUT_SEC}s (container still: ${STATUS})"
            fi
            sleep 30; elapsed=$((elapsed + 30)) ;;
    esac
done

echo "==> [5/6] Post-run checks..."
PROJ_PRP="${PROJ_DIR}/${PROJ_FULL}/${PROJ_FULL}.rep/project.prp"
grep -q 'NAME="OWNER" TYPE="string" VALUE="root"' "${PROJ_PRP}" \
    || fail "project OWNER is not 'root' (ghidra-mcp would throw NotOwnerException)"
rm -f "${PROJ_DIR}/${PROJ_FULL}"/*.lock "${PROJ_DIR}/${PROJ_FULL}"/*.lock~
ls -la "${OUT_DIR}"
echo "    ghidriff.log program names (for ghidra-mcp load_program_from_project):"
grep "Program: " "${OUT_DIR}/ghidriff.log" | tail -2

cat <<EOF

==> [6/6] DONE. Hand off to ghidra-mcp (skills/ghidra-mcp + ghidriff-pipeline skill):
  open_project(path='/projects/${PROJ_FULL}/${PROJ_FULL}.gpr')
  load_program_from_project(path='/<program>-<hash6>')   # names from the log lines above
  then program='<plain filename>' on all query tools.

Cleanup when reviewed:  docker rm -f ${RUN_NAME}
EOF
