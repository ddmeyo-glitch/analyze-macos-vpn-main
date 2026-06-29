#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/Bundle.md"

APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

echo "# Bundle Analysis" > "$OUT"
echo "" >> "$OUT"

echo "App : $APP" >> "$OUT"
echo "" >> "$OUT"

########################################
echo "## Directory Tree" >> "$OUT"
find "$APP" >> "$OUT"

########################################
echo "" >> "$OUT"
echo "## Executables" >> "$OUT"

find "$APP" -type f | while IFS= read -r f
do
    if file "$f" | grep -q Mach-O
    then
        echo "" >> "$OUT"
        echo "$f" >> "$OUT"
        file "$f" >> "$OUT"
    fi
done

########################################
echo "" >> "$OUT"
echo "## Frameworks" >> "$OUT"

find "$APP" -name "*.framework" >> "$OUT"

########################################
echo "" >> "$OUT"
echo "## System Extensions" >> "$OUT"

find "$APP" -name "*.systemextension" >> "$OUT"

########################################
echo "" >> "$OUT"
echo "## Info.plist" >> "$OUT"

find "$APP" -name Info.plist | while IFS= read -r plist
do
    echo "" >> "$OUT"
    echo "### $plist" >> "$OUT"
    plutil -convert xml1 -o - "$plist" >> "$OUT"
done

########################################
echo "" >> "$OUT"
echo "## Bundle IDs" >> "$OUT"

find "$APP" -name Info.plist | while IFS= read -r plist
do
    defaults read "$(dirname "$plist")/Info" CFBundleIdentifier 2>/dev/null || true
done >> "$OUT"

########################################
echo "" >> "$OUT"
echo "## Versions" >> "$OUT"

find "$APP" -name Info.plist | while IFS= read -r plist
do
    echo "$(dirname "$plist")" >> "$OUT"

    defaults read "$(dirname "$plist")/Info" \
        CFBundleShortVersionString 2>/dev/null || true

    defaults read "$(dirname "$plist")/Info" \
        CFBundleVersion 2>/dev/null || true

    echo "" >> "$OUT"
done

########################################
echo "" >> "$OUT"
echo "## SHA256" >> "$OUT"

find "$APP" -type f | while IFS= read -r f
do
    if file "$f" | grep -q Mach-O
    then
        shasum -a 256 "$f"
    fi
done >> "$OUT"

echo ""
echo "Bundle analysis completed."
