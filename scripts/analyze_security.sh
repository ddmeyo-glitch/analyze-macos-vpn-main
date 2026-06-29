#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/Security.md"
APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

DANGEROUS_SYMBOL_PATTERN='(^|[^A-Za-z0-9_])_(AuthorizationExecuteWithPrivileges|SMJobBless|ptrace|task_for_pid|setuid|seteuid|setgid|system|fork|exec|execve|posix_spawn|NSTask|NSAppleScript|launchctl)([^A-Za-z0-9_]|$)'
STRING_ONLY_PATTERN='AuthorizationExecuteWithPrivileges|SMJobBless|ptrace|task_for_pid|setuid|seteuid|setgid|system|fork|exec|execve|posix_spawn|NSTask|NSAppleScript|launchctl'

echo "# Security Analysis" > "$OUT"
echo "" >> "$OUT"
echo "Generated: $(date)" >> "$OUT"
echo "" >> "$OUT"

cat >> "$OUT" <<'EOF'
## Method

This report treats linked/imported symbols as stronger evidence than raw string matches.
Raw strings from Go runtime, bundled libraries, or diagnostic messages are recorded separately
and are not treated as proof that a dangerous API is called. Linked/imported symbols are
reported for manual review, but are not standalone proof that the code path is executed.

EOF

is_macho() {
    file "$1" | grep -q "Mach-O"
}

is_go_binary() {
    strings "$1" 2>/dev/null | grep -q "Go build"
}

section() {
    echo "" >> "$OUT"
    echo "## $1" >> "$OUT"
    echo "" >> "$OUT"
}

CONFIRMED_COUNT=0
rm -f "$REPORT_DIR/.confirmed_dangerous_count.tmp"

section "Sensitive Imported Symbols Requiring Manual Review"

find "$APP" -type f | while IFS= read -r BIN
do
    is_macho "$BIN" || continue

    RESULT=$(
        {
            nm -m "$BIN" 2>/dev/null || true
            otool -Iv "$BIN" 2>/dev/null || true
        } | grep -E "$DANGEROUS_SYMBOL_PATTERN" || true
    )

    if [ -n "$RESULT" ]; then
        echo "### $BIN" >> "$OUT"
        echo '```' >> "$OUT"
        echo "$RESULT" | sort -u >> "$OUT"
        echo '```' >> "$OUT"
        echo "" >> "$OUT"
        printf '1\n' >> "$REPORT_DIR/.confirmed_dangerous_count.tmp"
    fi
done

if [ -f "$REPORT_DIR/.confirmed_dangerous_count.tmp" ]; then
    CONFIRMED_COUNT=$(wc -l < "$REPORT_DIR/.confirmed_dangerous_count.tmp" | tr -d ' ')
    rm -f "$REPORT_DIR/.confirmed_dangerous_count.tmp"
else
    CONFIRMED_COUNT=0
fi

if [ "$CONFIRMED_COUNT" -eq 0 ]; then
    echo "No sensitive linked/imported API symbol references were found." >> "$OUT"
fi

section "String-only Indicators Excluded From Risk"

cat >> "$OUT" <<'EOF'
The following items are raw string matches. They may come from Go runtime symbol names,
bundled third-party libraries, error messages, or documentation strings. They are not counted
as confirmed API calls in this report.

EOF

find "$APP" -type f | while IFS= read -r BIN
do
    is_macho "$BIN" || continue

    RESULT=$(strings "$BIN" 2>/dev/null | grep -Eo "$STRING_ONLY_PATTERN" | sort -u | head -n 80 || true)

    if [ -n "$RESULT" ]; then
        echo "### $BIN" >> "$OUT"
        if is_go_binary "$BIN"; then
            echo "Note: Go binary detected; Go runtime/package symbols are expected to appear as strings." >> "$OUT"
        fi
        echo '```' >> "$OUT"
        echo "$RESULT" >> "$OUT"
        echo '```' >> "$OUT"
        echo "" >> "$OUT"
    fi
done

section "Sandbox Entitlements"

find "$APP" \( -name "*.app" -o -name "*.systemextension" \) -type d | while IFS= read -r TARGET
do
    ENT=$(codesign -d --entitlements :- "$TARGET" 2>/dev/null || true)
    [ -n "$ENT" ] || continue

    echo "### $TARGET" >> "$OUT"
    echo '```xml' >> "$OUT"
    echo "$ENT" | grep -E "com.apple.security.app-sandbox|com.apple.developer.networking.networkextension|com.apple.developer.system-extension.install|com.apple.security.application-groups" -A2 -B1 || true
    echo '```' >> "$OUT"
    echo "" >> "$OUT"
done

section "VPN and NetworkExtension Indicators"

find "$APP" -type f | while IFS= read -r BIN
do
    is_macho "$BIN" || continue

    RESULT=$(strings "$BIN" 2>/dev/null | grep -Ei "PacketTunnel|NEPacketTunnelProvider|NETunnelProvider|NetworkExtension|TunnelProvider|openconnect|libopenconnect|DTLS|ESP|CSTP|AnyConnect|ocserv|gpst" | sort -u | head -n 200 || true)

    if [ -n "$RESULT" ]; then
        echo "### $BIN" >> "$OUT"
        echo '```' >> "$OUT"
        echo "$RESULT" >> "$OUT"
        echo '```' >> "$OUT"
        echo "" >> "$OUT"
    fi
done

section "URLs"

find "$APP" -type f | while IFS= read -r BIN
do
    is_macho "$BIN" || continue
    strings "$BIN" 2>/dev/null | grep -Eo 'https?://[^"'"'"' <>]+' || true
done | sort -u >> "$OUT"

section "Domains"

find "$APP" -type f | while IFS= read -r BIN
do
    is_macho "$BIN" || continue
    strings "$BIN" 2>/dev/null | grep -Eo '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}' || true
done | sort -u >> "$OUT"

section "IPv4"

find "$APP" -type f | while IFS= read -r BIN
do
    is_macho "$BIN" || continue
    strings "$BIN" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' || true
done | sort -u >> "$OUT"

echo "" >> "$OUT"
echo "# Summary" >> "$OUT"
echo "" >> "$OUT"
echo "- Sensitive imported symbol groups requiring manual review: $CONFIRMED_COUNT" >> "$OUT"
echo "- Raw string matches are documented separately and excluded from the risk score." >> "$OUT"
echo "- com.apple.security.app-sandbox=false should be reviewed in context; it is common for some NetworkExtension/system-extension architectures and is not standalone malware evidence." >> "$OUT"
echo "" >> "$OUT"

if [ "$CONFIRMED_COUNT" -eq 0 ]; then
    echo "**Risk : LOW**" >> "$OUT"
else
    echo "**Risk : REVIEW**" >> "$OUT"
fi

echo "" >> "$OUT"
echo "Security analysis completed."
