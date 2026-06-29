#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/Go.md"
APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

echo "# Go / Fyne Analysis" > "$OUT"
echo "" >> "$OUT"

BIN=""
DETECTION=""
GO_VERSION_INFO=""

is_macho() {
    file "$1" | grep -q "Mach-O"
}

has_go_metadata() {
    command -v go >/dev/null 2>&1 || return 1
    GO_VERSION_INFO=$(go version -m "$1" 2>/dev/null || true)
    [ -n "$GO_VERSION_INFO" ] || return 1
    echo "$GO_VERSION_INFO" | grep -qi "not a Go executable" && return 1
    return 0
}

has_go_or_fyne_strings() {
    strings "$1" 2>/dev/null | grep -Eiq "(^go1\.[0-9]+|runtime\.buildVersion|github.com/fyne-io|fyne\.io/fyne|FYNE_)"
}

while IFS= read -r f
do
    is_macho "$f" || continue

    if has_go_metadata "$f"; then
        BIN="$f"
        DETECTION="go version -m metadata"
        break
    fi

    if has_go_or_fyne_strings "$f"; then
        BIN="$f"
        DETECTION="Go/Fyne string indicators"
        GO_VERSION_INFO=""
        break
    fi
done < <(find "$APP" -type f)

if [ -z "$BIN" ]; then
    echo "Go executable not found." >> "$OUT"
    echo "" >> "$OUT"
    echo "No Mach-O file matched go version metadata or Go/Fyne string indicators." >> "$OUT"
    exit 0
fi

echo "Executable : $BIN" >> "$OUT"
echo "Detection : $DETECTION" >> "$OUT"
echo "" >> "$OUT"

echo "## file" >> "$OUT"
file "$BIN" >> "$OUT"

echo "" >> "$OUT"
echo "## Go Build ID" >> "$OUT"

if command -v go >/dev/null 2>&1; then
    go tool buildid "$BIN" >> "$OUT" 2>&1 || true
else
    echo "go command not available." >> "$OUT"
fi

echo "" >> "$OUT"
echo "## go version -m" >> "$OUT"

if [ -n "$GO_VERSION_INFO" ]; then
    echo "$GO_VERSION_INFO" >> "$OUT"
elif command -v go >/dev/null 2>&1; then
    go version -m "$BIN" >> "$OUT" 2>&1 || true
else
    echo "go command not available." >> "$OUT"
fi

echo "" >> "$OUT"
echo "## Exported Symbols" >> "$OUT"

if command -v go >/dev/null 2>&1; then
    go tool nm "$BIN" | head -1000 >> "$OUT" 2>&1 || true
else
    nm -g "$BIN" | head -1000 >> "$OUT" 2>&1 || true
fi

echo "" >> "$OUT"
echo "## Runtime Version" >> "$OUT"

strings "$BIN" | grep -E "^go1\.[0-9]+" | sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## Fyne" >> "$OUT"

strings "$BIN" | grep -Ei "fyne|github.com/fyne-io|fyne\.io/fyne|FYNE_" | sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## Modules" >> "$OUT"

strings "$BIN" | grep -E "github.com/|fyne\.io/" | sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## golang.org Modules" >> "$OUT"

strings "$BIN" | grep "golang.org/" | sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## CGO" >> "$OUT"

strings "$BIN" | grep -Ei "cgo|libobjc|libSystem|libc\\+\\+" | sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## Sensitive Packages / APIs (string indicators only)" >> "$OUT"
echo "" >> "$OUT"
echo "These are string indicators and are not proof of execution." >> "$OUT"
echo "" >> "$OUT"

strings "$BIN" | \
grep -Ei "os/exec|syscall|unsafe|plugin|runtime/debug|reflect|net/http|crypto/tls|crypto/x509|posix_spawn|dlopen|dlsym|AuthorizationExecuteWithPrivileges|launchctl|osascript|NSTask" \
| sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## Network Packages" >> "$OUT"

strings "$BIN" | grep -Ei "net/http|net|tls|http2|x509|proxy|dns|udp|tcp" | sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## URLs" >> "$OUT"

strings "$BIN" | grep -Eo 'https?://[^"'"'"' <>]+' | sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## Apple APIs" >> "$OUT"

strings "$BIN" | grep -Ei "CGDisplay|IOHID|NSApplication|NSUserDefaults|NSPasteboard|Accessibility|AXUIElement|TCC|ScreenCapture" | sort -u >> "$OUT" || true

echo "" >> "$OUT"
echo "## SHA256" >> "$OUT"

shasum -a 256 "$BIN" >> "$OUT"

echo "" >> "$OUT"
echo "Go analysis completed."
