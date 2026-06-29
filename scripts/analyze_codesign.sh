#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/CodeSign.md"
APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

echo "# Code Signing Analysis" > "$OUT"
echo "" >> "$OUT"
echo "App : $APP" >> "$OUT"
echo "" >> "$OUT"

if [ -z "$APP" ]; then
    echo "No app bundle found." >> "$OUT"
    exit 1
fi

find_targets() {
    find "$APP" \
        \( \
            -name "*.app" \
            -o -name "*.framework" \
            -o -name "*.systemextension" \
        \)
}

find_targets | while IFS= read -r TARGET
do
    echo "" >> "$OUT"
    echo "==================================================" >> "$OUT"
    echo "$TARGET" >> "$OUT"
    echo "==================================================" >> "$OUT"

    echo "" >> "$OUT"
    echo "## Verify" >> "$OUT"
    codesign --verify --deep --strict --verbose=4 "$TARGET" >> "$OUT" 2>&1 || true

    echo "" >> "$OUT"
    echo "## Display" >> "$OUT"
    codesign -dvvv "$TARGET" >> "$OUT" 2>&1 || true

    echo "" >> "$OUT"
    echo "## Requirements" >> "$OUT"
    codesign -d -r- "$TARGET" >> "$OUT" 2>&1 || true

    echo "" >> "$OUT"
    echo "## Entitlements" >> "$OUT"
    codesign -d --entitlements :- "$TARGET" >> "$OUT" 2>&1 || true

    echo "" >> "$OUT"
    echo "## Authority" >> "$OUT"
    codesign -dvv "$TARGET" 2>&1 | grep Authority >> "$OUT" || true

    echo "" >> "$OUT"
    echo "## Team Identifier" >> "$OUT"
    codesign -dvv "$TARGET" 2>&1 | grep TeamIdentifier >> "$OUT" || true

    echo "" >> "$OUT"
    echo "## Runtime" >> "$OUT"
    codesign -dvv "$TARGET" 2>&1 | grep Runtime >> "$OUT" || true

    echo "" >> "$OUT"
    echo "## Identifier" >> "$OUT"
    codesign -dvv "$TARGET" 2>&1 | grep Identifier >> "$OUT" || true

    echo "" >> "$OUT"
    echo "## Timestamp" >> "$OUT"
    codesign -dvv "$TARGET" 2>&1 | grep Timestamp >> "$OUT" || true

    echo "" >> "$OUT"
    echo "## Executable" >> "$OUT"
    codesign -dvv "$TARGET" 2>&1 | grep Executable >> "$OUT" || true

    echo "" >> "$OUT"
    echo "## CMS Certificate Chain" >> "$OUT"
    codesign -dvv "$TARGET" 2>&1 | grep "^Authority" >> "$OUT" || true

    echo "" >> "$OUT"
    echo "## spctl Assessment" >> "$OUT"
    spctl -a -vv "$TARGET" >> "$OUT" 2>&1 || true

    echo "" >> "$OUT"
    echo "## Notary Status" >> "$OUT"
    spctl -a -vvv "$TARGET" >> "$OUT" 2>&1 || true

    echo "" >> "$OUT"
    echo "## SHA256" >> "$OUT"
    BIN=$(codesign -dvv "$TARGET" 2>&1 | grep Executable= | cut -d= -f2 || true)
    if [ -f "$BIN" ]; then
        shasum -a 256 "$BIN" >> "$OUT"
    fi
done

echo "" >> "$OUT"
echo "# Team Identifier Summary" >> "$OUT"

find_targets | while IFS= read -r TARGET
do
    echo "" >> "$OUT"
    echo "$TARGET" >> "$OUT"
    codesign -dvv "$TARGET" 2>&1 | grep TeamIdentifier >> "$OUT" || true
done

echo "" >> "$OUT"
echo "CodeSign analysis completed."
