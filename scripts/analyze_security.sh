#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/Security.md"

APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

echo "# Security Analysis" > "$OUT"
echo "" >> "$OUT"
echo "Generated: $(date)" >> "$OUT"
echo "" >> "$OUT"

########################################
# Helper
########################################

scan_pattern() {

TITLE="$1"
PATTERN="$2"

echo "" >> "$OUT"
echo "## $TITLE" >> "$OUT"
echo "" >> "$OUT"

FOUND=0

find "$APP" -type f | while IFS= read -r BIN
do
    if file "$BIN" | grep -q "Mach-O"; then

        RESULT=$(strings "$BIN" | grep -E "$PATTERN" || true)

        if [ -n "$RESULT" ]; then

            FOUND=1

            echo "### $BIN" >> "$OUT"
            echo '```' >> "$OUT"
            echo "$RESULT" >> "$OUT"
            echo '```' >> "$OUT"
            echo "" >> "$OUT"

        fi

    fi
done

}

########################################
# Privilege Escalation
########################################

scan_pattern \
"Privilege Escalation" \
"AuthorizationExecuteWithPrivileges|SMJobBless|setuid|seteuid|setgid|task_for_pid|ptrace"

########################################
# Process Execution
########################################

scan_pattern \
"Process Execution" \
"system|fork|exec|execve|posix_spawn|NSTask"

########################################
# Dynamic Loading
########################################

scan_pattern \
"Dynamic Loading" \
"dlopen|dlsym|NSBundle"

########################################
# Shell
########################################

scan_pattern \
"Shell Commands" \
"/bin/sh|/bin/bash|/bin/zsh|osascript|python|perl|ruby"

########################################
# Launch Services
########################################

scan_pattern \
"Launch Services" \
"launchctl|LaunchDaemon|LaunchAgent|SMAppService|SMLoginItem"

########################################
# Network APIs
########################################

scan_pattern \
"Network APIs" \
"NSURLSession|CFNetwork|Network.framework|socket|connect|bind|listen|recv|send"

########################################
# Apple Sensitive APIs
########################################

scan_pattern \
"Apple Sensitive APIs" \
"CGDisplay|IOHID|AXUIElement|Accessibility|ScreenCapture|ScreenRecording|TCC"

########################################
# VPN APIs
########################################

scan_pattern \
"VPN APIs" \
"PacketTunnel|NEPacketTunnelProvider|NETunnelProvider|NetworkExtension|TunnelProvider"

########################################
# OpenConnect
########################################

scan_pattern \
"OpenConnect" \
"openconnect|libopenconnect|DTLS|ESP|CSTP|AnyConnect|ocserv|gpst"

########################################
# Encryption
########################################

scan_pattern \
"Crypto" \
"AES|RSA|ECDSA|SHA256|SHA512|crypto|TLS|SSL"

########################################
# Obfuscation
########################################

scan_pattern \
"Possible Obfuscation" \
"base64|xor|shellcode|payload|decrypt|encrypt"

########################################
# URLs
########################################

echo "" >> "$OUT"
echo "## URLs" >> "$OUT"

find "$APP" -type f | while IFS= read -r BIN
do
    if file "$BIN" | grep -q Mach-O
    then
        strings "$BIN"
    fi
done | \
grep -Eo "https?://[^ ]+" | \
sort -u >> "$OUT" || true

########################################
# Domains
########################################

echo "" >> "$OUT"
echo "## Domains" >> "$OUT"

find "$APP" -type f | while IFS= read -r BIN
do
    if file "$BIN" | grep -q Mach-O
    then
        strings "$BIN"
    fi
done | \
grep -Eo "[A-Za-z0-9.-]+\.[A-Za-z]{2,}" | \
sort -u | \
uniq >> "$OUT" || true

########################################
# IPv4
########################################

echo "" >> "$OUT"
echo "## IPv4" >> "$OUT"

find "$APP" -type f | while IFS= read -r BIN
do
    if file "$BIN" | grep -q Mach-O
    then
        strings "$BIN"
    fi
done | \
grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | \
sort -u >> "$OUT" || true

########################################
# Summary
########################################

echo "" >> "$OUT"
echo "# Summary" >> "$OUT"

COUNT=0

for WORD in \
AuthorizationExecuteWithPrivileges \
SMJobBless \
ptrace \
task_for_pid \
system \
fork \
exec \
NSTask \
launchctl
do

N=$( (grep -R "$WORD" "$OUT" 2>/dev/null || true) | wc -l | tr -d ' ' )

echo "- $WORD : $N" >> "$OUT"

COUNT=$((COUNT+N))

done

echo "" >> "$OUT"

if [ "$COUNT" -eq 0 ]
then
    echo "**Risk : LOW**" >> "$OUT"
elif [ "$COUNT" -lt 5 ]
then
    echo "**Risk : MEDIUM**" >> "$OUT"
else
    echo "**Risk : HIGH**" >> "$OUT"
fi

echo "" >> "$OUT"
echo "Security analysis completed."
