#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"
mkdir -p "$REPORT_DIR"

OUT="$REPORT_DIR/MachO.md"

APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

echo "# Mach-O Analysis" > "$OUT"
echo "" >> "$OUT"
echo "Generated: $(date)" >> "$OUT"
echo "" >> "$OUT"

########################################
# Find all Mach-O files
########################################

find "$APP" -type f | while IFS= read -r BIN
do

    if ! file "$BIN" | grep -q "Mach-O"; then
        continue
    fi

    echo "" >> "$OUT"
    echo "===================================================" >> "$OUT"
    echo "$BIN" >> "$OUT"
    echo "===================================================" >> "$OUT"

    ####################################################
    echo "" >> "$OUT"
    echo "## file" >> "$OUT"

    file "$BIN" >> "$OUT"

    ####################################################
    echo "" >> "$OUT"
    echo "## lipo" >> "$OUT"

    lipo -info "$BIN" >> "$OUT" 2>&1 || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Header" >> "$OUT"

    otool -h "$BIN" >> "$OUT" 2>&1 || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Load Commands" >> "$OUT"

    otool -l "$BIN" >> "$OUT" 2>&1 || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Linked Libraries" >> "$OUT"

    otool -L "$BIN" >> "$OUT" 2>&1 || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Imported Symbols" >> "$OUT"

    nm -m "$BIN" >> "$OUT" 2>&1 || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Exported Symbols" >> "$OUT"

    nm -g "$BIN" >> "$OUT" 2>&1 || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Objective-C Metadata" >> "$OUT"

    otool -ov "$BIN" >> "$OUT" 2>&1 || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Code Signature" >> "$OUT"

    codesign -dvvv "$BIN" 2>> "$OUT" || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Entitlements" >> "$OUT"

    codesign \
        -d \
        --entitlements :- \
        "$BIN" \
        2>> "$OUT" || true

    ####################################################
    echo "" >> "$OUT"
    echo "## LC_RPATH" >> "$OUT"

    otool -l "$BIN" | \
        awk '
            /cmd LC_RPATH/ {flag=1}
            flag
            /path/ {print; flag=0}
        ' >> "$OUT" || true

    ####################################################
    echo "" >> "$OUT"
    echo "## LC_BUILD_VERSION" >> "$OUT"

    otool -l "$BIN" | \
        awk '
            /LC_BUILD_VERSION/ {flag=1}
            flag
            /^$/ {flag=0}
        ' >> "$OUT" || true

    ####################################################
    echo "" >> "$OUT"
    echo "## LC_CODE_SIGNATURE" >> "$OUT"

    otool -l "$BIN" | \
        awk '
            /LC_CODE_SIGNATURE/ {flag=1}
            flag
            /^$/ {flag=0}
        ' >> "$OUT" || true

    ####################################################
    echo "" >> "$OUT"
    echo "## Encryption Info" >> "$OUT"

    otool -l "$BIN" | \
        grep -A5 LC_ENCRYPTION_INFO >> "$OUT" || true

    ####################################################
    echo "" >> "$OUT"
    echo "## SHA256" >> "$OUT"

    shasum -a 256 "$BIN" >> "$OUT"

    ####################################################
    echo "" >> "$OUT"
    echo "## Build UUID" >> "$OUT"

    dwarfdump --uuid "$BIN" >> "$OUT" 2>&1 || true

done

####################################################
# Summary
####################################################

echo "" >> "$OUT"
echo "# Summary" >> "$OUT"

echo "" >> "$OUT"

echo "Mach-O files:" >> "$OUT"

find "$APP" -type f | while IFS= read -r BIN
do
    if file "$BIN" | grep -q Mach-O
    then
        echo "- $BIN" >> "$OUT"
    fi
done

echo "" >> "$OUT"
echo "Analysis completed."
