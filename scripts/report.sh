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

CONFIRMED_DANGEROUS=0
if [ -f "$REPORT_DIR/Security.md" ]; then
    CONFIRMED_DANGEROUS=$( (grep -E "Confirmed dangerous API reference groups:" "$REPORT_DIR/Security.md" || true) | awk -F: '{gsub(/ /,"",$2); print $2}' | tail -n 1 )
    CONFIRMED_DANGEROUS="${CONFIRMED_DANGEROUS:-0}"
fi

if [ "$CONFIRMED_DANGEROUS" = "0" ]; then
    status_ok "No linked/imported dangerous API references confirmed"
    status_ok "Go runtime and bundled-library string matches are excluded from risk scoring"
else
    status_warn "$CONFIRMED_DANGEROUS linked/imported dangerous API reference group(s) require manual review"
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

if [ "$CONFIRMED_DANGEROUS" != "0" ]
then
    RISK="REVIEW"
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
- No linked/imported dangerous API references were confirmed by the symbol-based security scan when the count is zero.
- Raw string matches from Go runtime, bundled libraries, or diagnostic messages are documented separately and are not treated as proof of API execution.
- The app uses a Packet Tunnel System Extension and libopenconnect indicators, which can be consistent with a VPN client architecture.
- Further investigation may require Apple's internal detection details, such as the triggering executable hash, signature rule, or file path.
EOF

echo ""
echo "Security report generated:"
echo "$OUT"
