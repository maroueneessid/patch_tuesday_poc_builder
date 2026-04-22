#!/usr/bin/env bash
# Fix Ghidra project ownership in .rep/project.prp files.
# Usage: ./fix_ownership.sh <ghidra_projects_dir> [username]
# If username is omitted, defaults to current user.

set -euo pipefail

PROJECT_DIR="${1:?Usage: $0 <ghidra_projects_dir> [username]}"
USERNAME="${2:-$(whoami)}"

if [ ! -d "$PROJECT_DIR" ]; then
    echo "Not a directory: $PROJECT_DIR" >&2
    exit 1
fi

found=0
while IFS= read -r -d '' prp; do
    sed -i "s/NAME=\"OWNER\" TYPE=\"string\" VALUE=\"[^\"]*\"/NAME=\"OWNER\" TYPE=\"string\" VALUE=\"${USERNAME}\"/" "$prp"
    echo "Patched: $prp -> OWNER=$USERNAME"
    found=1
done < <(find "$PROJECT_DIR" -name "project.prp" -print0)

if [ "$found" -eq 0 ]; then
    echo "No project.prp files found in $PROJECT_DIR"
fi
