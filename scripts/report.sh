#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/Security_Report.md"

echo "# Dodo VPN Security Assessment Report" > "$OUT"
echo "" >> "$OUT"
echo "Generated : $(date)" >> "$OUT"
echo "" >> "$OUT"

section() {
    echo "" >> "$OUT"
    echo "---" >> "$OUT"
    echo "" >> "$OUT"
    echo "## $1" >> "$OUT"
    echo "" >> "$OUT"
}

status_ok() {
    echo "- [OK] $1" >> "$OUT"
}

status_warn() {
    echo "- [WARN] $1" >> "$OUT"
}

status_ng() {
    echo "- [NG] $1" >> "$OUT"
}

section "Executive Summary"

[ -f "$REPORT_DIR/Bundle.md" ] && status_ok "Bundle analysis completed" || status_ng "Bundle analysis missing"
[ -f "$REPORT_DIR/CodeSign.md" ] && status_ok "Code signature analysis completed" || status_ng "Code signature analysis missing"
[ -f "$REPORT_DIR/Go.md" ] && status_ok "Go/Fyne analysis completed" || status_warn "Go/Fyne analysis missing"
[ -f "$REPORT_DIR/NetworkExtension.md" ] && status_ok "NetworkExtension analysis completed" || status_warn "NetworkExtension analysis missing"
[ -f "$REPORT_DIR/IOC.md" ] && status_ok "IOC extraction completed" || status_warn "IOC extraction missing"

section "Bundle"

if [ -f "$REPORT_DIR/Bundle.md" ]; then
    APPS=$(grep -c ".app" "$REPORT_DIR/Bundle.md" || true)
    EXT=$(grep -c ".systemextension" "$REPORT_DIR/Bundle.md" || true)
    echo "- App Bundles : $APPS" >> "$OUT"
    echo "- System Extensions : $EXT" >> "$OUT"
fi

section "Team Identifier"

if [ -f "$REPORT_DIR/CodeSign.md" ]; then
    grep TeamIdentifier "$REPORT_DIR/CodeSign.md" | sort -u >> "$OUT" || true
fi

section "Hardened Runtime"

if grep -q Runtime "$REPORT_DIR/CodeSign.md" 2>/dev/null
then
    status_ok "Hardened Runtime flag detected"
else
    status_warn "Runtime flag not detected"
fi

section "Notarization"

if grep -qi accepted "$REPORT_DIR/CodeSign.md" 2>/dev/null
then
    status_ok "Accepted by spctl"
else
    status_warn "spctl acceptance not confirmed"
fi

section "Dangerous APIs"

FOUND=0
SCAN_REPORTS=()
for f in Security.md MachO.md NetworkExtension.md Go.md; do
    if [ -f "$REPORT_DIR/$f" ]; then
        SCAN_REPORTS+=("$REPORT_DIR/$f")
    fi
done

for WORD in \
NSTask \
system \
fork \
exec \
posix_spawn \
NSAppleScript \
SMJobBless \
AuthorizationExecuteWithPrivileges \
ptrace \
task_for_pid \
launchctl
do
    if [ "${#SCAN_REPORTS[@]}" -gt 0 ] && grep -iq "$WORD" "${SCAN_REPORTS[@]}" 2>/dev/null
    then
        status_warn "$WORD detected"
        FOUND=1
    fi
done

if [ "$FOUND" -eq 0 ]; then
    status_ok "No dangerous APIs detected"
fi

section "Go Modules"

if [ -f "$REPORT_DIR/Go.md" ]; then
    grep github.com "$REPORT_DIR/Go.md" | sort -u >> "$OUT" || true
fi

section "NetworkExtension"

if [ -f "$REPORT_DIR/NetworkExtension.md" ]; then
    grep -Ei "PacketTunnel|TunnelProvider|NetworkExtension|openconnect|DTLS|ESP" "$REPORT_DIR/NetworkExtension.md" | sort -u >> "$OUT" || true
fi

section "Entitlements"

for f in CodeSign.md MachO.md NetworkExtension.md; do
    [ -f "$REPORT_DIR/$f" ] || continue
    grep "com.apple.developer" "$REPORT_DIR/$f" 2>/dev/null || true
done | sort -u >> "$OUT"

section "Embedded URLs"

for f in Security.md IOC.md Go.md NetworkExtension.md; do
    [ -f "$REPORT_DIR/$f" ] || continue
    grep -hoE 'https?://[^"'"'"' <>]+' "$REPORT_DIR/$f" 2>/dev/null || true
done | sort -u >> "$OUT"

section "Risk Assessment"

RISK="LOW"

if [ "${#SCAN_REPORTS[@]}" -gt 0 ] && grep -iq "SMJobBless" "${SCAN_REPORTS[@]}" 2>/dev/null
then
    RISK="MEDIUM"
fi

if [ "${#SCAN_REPORTS[@]}" -gt 0 ] && grep -iq "AuthorizationExecuteWithPrivileges" "${SCAN_REPORTS[@]}" 2>/dev/null
then
    RISK="HIGH"
fi

echo "" >> "$OUT"
echo "**Overall Risk : $RISK**" >> "$OUT"

section "Findings"

if grep -Riq "TeamIdentifier" "$REPORT_DIR/CodeSign.md" 2>/dev/null; then
    status_ok "Developer ID team identifier detected"
else
    status_warn "Developer ID team identifier not detected"
fi

if grep -Riq ".systemextension" "$REPORT_DIR/Bundle.md" 2>/dev/null; then
    status_ok "SystemExtension detected"
fi

if grep -Riq "PacketTunnel" "$REPORT_DIR/NetworkExtension.md" 2>/dev/null; then
    status_ok "PacketTunnel architecture detected"
fi

if grep -Riq "openconnect" "$REPORT_DIR" 2>/dev/null
then
    status_ok "OpenConnect library indicators detected"
fi

if grep -Riq "fyne" "$REPORT_DIR" 2>/dev/null
then
    status_ok "Fyne framework indicators detected"
fi

section "Suggested Notes for Apple"

cat >> "$OUT" <<EOF
The application was statically analyzed.

The following observations were made:

- Code signing, notarization, Mach-O metadata, NetworkExtension usage, Go runtime data, and IOC indicators were reviewed.
- No automatically confirmed malicious behavior was identified by this static analysis workflow.
- Detected privileged, process-execution, or networking APIs should be reviewed in context if present in the supporting reports.
- Further investigation may require Apple's internal detection details, such as the triggering executable hash, signature rule, or file path.
EOF

echo ""
echo "Security report generated:"
echo "$OUT"
