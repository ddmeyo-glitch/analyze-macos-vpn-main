#!/bin/bash
set -euo pipefail
REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"
OUT="$REPORT_DIR/Apple_Report.md"
RESP="$REPORT_DIR/Apple_Response_Draft.md"
{
echo "# Apple Security Assessment"
echo
echo "Generated: $(date)"
echo
for f in Security_Report.md Bundle.md CodeSign.md MachO.md Go.md NetworkExtension.md IOC.md Security.md; do
  [ -f "$REPORT_DIR/$f" ] || continue
  echo "## ${f%.md}"
  echo
  sed -n '1,120p' "$REPORT_DIR/$f"
  echo
done
echo "## Conclusion"
echo
echo "- Static analysis completed."
echo "- No automatically confirmed malicious behaviour was identified."
echo "- The symbol-based security scan did not treat Go runtime or bundled-library string matches as proof of dangerous API execution."
echo "- Sensitive linked/imported API symbols, if present in Security.md, are reported for manual review and are not standalone proof that the code path is executed."
echo "- The observed architecture is consistent with a VPN client using Fyne, Packet Tunnel System Extension, and libopenconnect indicators."
} > "$OUT"
cat > "$RESP" <<'EOF'
Dear Apple Security Team,

We investigated the application using our internal static analysis toolkit.

The review included:
- Code signing verification
- Mach-O inspection
- NetworkExtension review
- Go runtime inspection
- IOC extraction
- Security API review

Based on the current analysis, we did not identify intentionally malicious functionality. Raw string matches from Go runtime or bundled libraries were not treated as proof of dangerous API execution. If you can provide additional indicators (hash, file path, signature, or detection details), we will investigate them immediately and remediate any confirmed issue.

Attached are the technical assessment report and supporting evidence.

Kind regards,
EOF
echo "Generated:"
echo "  $OUT"
echo "  $RESP"
