#!/bin/bash
set -uo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

ERROR_LOG="$REPORT_DIR/Analysis_Errors.md"
{
    echo "# Analysis Errors"
    echo
    echo "Generated: $(date)"
    echo
} > "$ERROR_LOG"

run() {
    echo "===== $1 ====="
    if "./scripts/$1"; then
        echo "OK: $1"
    else
        STATUS=$?
        echo "WARNING: $1 exited with status $STATUS" >&2
        echo "- $1 exited with status $STATUS" >> "$ERROR_LOG"
    fi
}

run analyze_bundle.sh
run analyze_codesign.sh
run analyze_go.sh
run analyze_macho.sh
run analyze_networkextension.sh
run analyze_security.sh
run ioc.sh
