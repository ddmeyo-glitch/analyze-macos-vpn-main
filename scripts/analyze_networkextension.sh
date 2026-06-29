#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/NetworkExtension.md"

APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

echo "# Network Extension Analysis" > "$OUT"
echo "" >> "$OUT"

#########################################################################
# Locate SystemExtension
#########################################################################

EXT=$(find "$APP" -name "*.systemextension" -type d | head -n 1)

if [ -z "$EXT" ]; then
    echo "No SystemExtension found." >> "$OUT"
    exit 0
fi

echo "SystemExtension : $EXT" >> "$OUT"
echo "" >> "$OUT"

#########################################################################
# Info.plist
#########################################################################

echo "## Info.plist" >> "$OUT"
echo "" >> "$OUT"

plutil -convert xml1 -o - \
"$EXT/Contents/Info.plist" >> "$OUT"

#########################################################################
# Bundle Information
#########################################################################

echo "" >> "$OUT"
echo "## Bundle Information" >> "$OUT"

defaults read "$EXT/Contents/Info" \
CFBundleIdentifier 2>/dev/null >> "$OUT" || true

defaults read "$EXT/Contents/Info" \
CFBundleExecutable 2>/dev/null >> "$OUT" || true

defaults read "$EXT/Contents/Info" \
CFBundleVersion 2>/dev/null >> "$OUT" || true

defaults read "$EXT/Contents/Info" \
CFBundleShortVersionString 2>/dev/null >> "$OUT" || true

#########################################################################
# Executable
#########################################################################

EXECUTABLE=$(defaults read "$EXT/Contents/Info" CFBundleExecutable 2>/dev/null || true)
BIN="$EXT/Contents/MacOS/$EXECUTABLE"

echo "" >> "$OUT"
echo "Executable : $BIN" >> "$OUT"

#########################################################################
# Mach-O
#########################################################################

echo "" >> "$OUT"
echo "## file" >> "$OUT"

file "$BIN" >> "$OUT"

echo "" >> "$OUT"
echo "## lipo" >> "$OUT"

lipo -info "$BIN" >> "$OUT" 2>&1 || true

#########################################################################
# Linked Frameworks
#########################################################################

echo "" >> "$OUT"
echo "## Linked Frameworks" >> "$OUT"

otool -L "$BIN" >> "$OUT" 2>&1 || true

#########################################################################
# Load Commands
#########################################################################

echo "" >> "$OUT"
echo "## Load Commands" >> "$OUT"

otool -l "$BIN" >> "$OUT" 2>&1 || true

#########################################################################
# Entitlements
#########################################################################

echo "" >> "$OUT"
echo "## Entitlements" >> "$OUT"

codesign \
-d \
--entitlements :- \
"$BIN" \
>> "$OUT" 2>&1 || true

#########################################################################
# Code Requirements
#########################################################################

echo "" >> "$OUT"
echo "## Requirements" >> "$OUT"

codesign \
-d \
-r- \
"$BIN" \
>> "$OUT" 2>&1 || true

#########################################################################
# Objective-C
#########################################################################

echo "" >> "$OUT"
echo "## Objective-C Classes" >> "$OUT"

otool -ov "$BIN" 2>/dev/null | \
grep "name " >> "$OUT" || true

#########################################################################
# Swift
#########################################################################

echo "" >> "$OUT"
echo "## Swift Symbols" >> "$OUT"

nm "$BIN" | \
swift-demangle 2>/dev/null | \
grep "Swift" >> "$OUT" || true

#########################################################################
# PacketTunnel
#########################################################################

echo "" >> "$OUT"
echo "## PacketTunnel" >> "$OUT"

strings "$BIN" | \
grep -Ei \
"PacketTunnel|TunnelProvider|NetworkExtension|NEPacketTunnelProvider|NETunnelProvider|NWTCPConnection|NWUDPSession" \
>> "$OUT" || true

#########################################################################
# OpenConnect
#########################################################################

echo "" >> "$OUT"
echo "## OpenConnect" >> "$OUT"

strings "$BIN" | \
grep -Ei \
"openconnect|libopenconnect|gpst|ocserv|AnyConnect|ESP|DTLS|CSTP|cookie|vpn" \
>> "$OUT" || true

#########################################################################
# Network API
#########################################################################

echo "" >> "$OUT"
echo "## Network API" >> "$OUT"

strings "$BIN" | \
grep -Ei \
"NSURLSession|CFNetwork|socket|connect|recv|send|bind|listen|Network.framework" \
>> "$OUT" || true

#########################################################################
# Dangerous API
#########################################################################

echo "" >> "$OUT"
echo "## Dangerous API" >> "$OUT"

strings "$BIN" | \
grep -Ei \
"system|exec|fork|posix_spawn|NSTask|NSAppleScript|AuthorizationExecuteWithPrivileges|SMJobBless|launchctl|dlopen|dlsym|ptrace|task_for_pid" \
>> "$OUT" || true

#########################################################################
# URLs
#########################################################################

echo "" >> "$OUT"
echo "## URLs" >> "$OUT"

strings "$BIN" | \
grep -Eo "https?://[^ ]+" | \
sort -u >> "$OUT" || true

#########################################################################
# Hash
#########################################################################

echo "" >> "$OUT"
echo "## SHA256" >> "$OUT"

shasum -a 256 "$BIN" >> "$OUT"

echo "" >> "$OUT"
echo "NetworkExtension analysis completed."
