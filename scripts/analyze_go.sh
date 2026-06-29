#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/Go.md"

APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

echo "# Go / Fyne Analysis" > "$OUT"
echo "" >> "$OUT"

#########################################################################
# Find Go Executable
#########################################################################

BIN=""

while IFS= read -r f
do
    if file "$f" | grep -q Mach-O
    then
        if strings "$f" | grep -q "Go build"
        then
            BIN="$f"
            break
        fi
    fi
done < <(find "$APP" -type f)

if [ -z "$BIN" ]; then
    echo "Go executable not found." >> "$OUT"
    exit 0
fi

echo "Executable : $BIN" >> "$OUT"
echo "" >> "$OUT"

#########################################################################
# file
#########################################################################

echo "## file" >> "$OUT"
file "$BIN" >> "$OUT"

#########################################################################
# Build ID
#########################################################################

echo "" >> "$OUT"
echo "## Go Build ID" >> "$OUT"

go tool buildid "$BIN" >> "$OUT" 2>&1 || true

#########################################################################
# Module Information
#########################################################################

echo "" >> "$OUT"
echo "## go version -m" >> "$OUT"

go version -m "$BIN" >> "$OUT" 2>&1 || true

#########################################################################
# Go Symbols
#########################################################################

echo "" >> "$OUT"
echo "## Exported Symbols" >> "$OUT"

go tool nm "$BIN" | head -1000 >> "$OUT" 2>&1 || true

#########################################################################
# Runtime Version
#########################################################################

echo "" >> "$OUT"
echo "## Runtime Version" >> "$OUT"

strings "$BIN" | \
grep -E "^go1\.[0-9]+" | \
sort -u >> "$OUT" || true

#########################################################################
# Fyne
#########################################################################

echo "" >> "$OUT"
echo "## Fyne" >> "$OUT"

strings "$BIN" | \
grep -Ei "fyne|github.com/fyne-io" | \
sort -u >> "$OUT" || true

#########################################################################
# Modules
#########################################################################

echo "" >> "$OUT"
echo "## Modules" >> "$OUT"

strings "$BIN" | \
grep "github.com/" | \
sort -u >> "$OUT" || true

#########################################################################
# golang.org
#########################################################################

echo "" >> "$OUT"
echo "## golang.org Modules" >> "$OUT"

strings "$BIN" | \
grep "golang.org/" | \
sort -u >> "$OUT" || true

#########################################################################
# CGO
#########################################################################

echo "" >> "$OUT"
echo "## CGO" >> "$OUT"

strings "$BIN" | \
grep -Ei "cgo|libobjc|libSystem|libc\\+\\+" | \
sort -u >> "$OUT" || true

#########################################################################
# Dangerous Packages
#########################################################################

echo "" >> "$OUT"
echo "## Dangerous Packages" >> "$OUT"

strings "$BIN" | \
grep -Ei \
"os/exec|syscall|unsafe|plugin|runtime/debug|reflect|net/http|crypto/tls|crypto/x509" \
| sort -u >> "$OUT" || true

#########################################################################
# Network Packages
#########################################################################

echo "" >> "$OUT"
echo "## Network Packages" >> "$OUT"

strings "$BIN" | \
grep -Ei \
"net/http|net|tls|http2|x509|proxy|dns|udp|tcp" \
| sort -u >> "$OUT" || true

#########################################################################
# URLs
#########################################################################

echo "" >> "$OUT"
echo "## URLs" >> "$OUT"

strings "$BIN" | \
grep -Eo "https?://[^ ]+" | \
sort -u >> "$OUT" || true

#########################################################################
# Apple APIs
#########################################################################

echo "" >> "$OUT"
echo "## Apple APIs" >> "$OUT"

strings "$BIN" | \
grep -Ei \
"CGDisplay|IOHID|NSApplication|NSUserDefaults|NSPasteboard|Accessibility|AXUIElement|TCC|ScreenCapture" \
| sort -u >> "$OUT" || true

#########################################################################
# Security
#########################################################################

echo "" >> "$OUT"
echo "## Security APIs" >> "$OUT"

strings "$BIN" | \
grep -Ei \
"system|fork|exec|posix_spawn|dlopen|dlsym|AuthorizationExecuteWithPrivileges|launchctl|osascript|NSTask" \
| sort -u >> "$OUT" || true

#########################################################################
# Hash
#########################################################################

echo "" >> "$OUT"
echo "## SHA256" >> "$OUT"

shasum -a 256 "$BIN" >> "$OUT"

echo "" >> "$OUT"
echo "Go analysis completed."
