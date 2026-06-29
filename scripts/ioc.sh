#!/bin/bash
set -euo pipefail

REPORT_DIR="${REPORT_DIR:-reports}"

mkdir -p "$REPORT_DIR"

MD="$REPORT_DIR/IOC.md"
CSV="$REPORT_DIR/IOC.csv"
JSON="$REPORT_DIR/IOC.json"
JSON_TMP="$REPORT_DIR/IOC.tsv"

APP="${APP:-$(find . -name "*.app" -type d | head -n 1)}"

##############################################

echo "# Indicators of Compromise" > "$MD"
echo "" >> "$MD"

echo "Generated: $(date)" >> "$MD"
echo "" >> "$MD"

##############################################

echo "Type,Value,Source" > "$CSV"
: > "$JSON_TMP"

##############################################

json_add(){

TYPE="$1"
VALUE="$2"
SRC="$3"

printf '%s\t%s\t%s\n' "$TYPE" "$VALUE" "$SRC" >> "$JSON_TMP"
printf '"%s","%s","%s"\n' \
    "$(printf "%s" "$TYPE" | sed 's/"/""/g')" \
    "$(printf "%s" "$VALUE" | sed 's/"/""/g')" \
    "$(printf "%s" "$SRC" | sed 's/"/""/g')" >> "$CSV"

}

##############################################

md_section(){

echo "" >> "$MD"
echo "## $1" >> "$MD"
echo "" >> "$MD"

}

##############################################

md_section "Executables"

find "$APP" -type f | while IFS= read -r BIN
do

    if ! file "$BIN" | grep -q Mach-O
    then
        continue
    fi

    echo "$BIN" >> "$MD"

done

##############################################

md_section "SHA256"

find "$APP" -type f | while IFS= read -r BIN
do

    if ! file "$BIN" | grep -q Mach-O
    then
        continue
    fi

    HASH=$(shasum -a 256 "$BIN" | awk '{print $1}')

    echo "$HASH  $BIN" >> "$MD"

    json_add SHA256 "$HASH" "$BIN"

done

##############################################

md_section "SHA1"

find "$APP" -type f | while IFS= read -r BIN
do

    if ! file "$BIN" | grep -q Mach-O
    then
        continue
    fi

    HASH=$(shasum "$BIN" | awk '{print $1}')

    echo "$HASH  $BIN" >> "$MD"

    json_add SHA1 "$HASH" "$BIN"

done

##############################################

md_section "MD5"

find "$APP" -type f | while IFS= read -r BIN
do

    if ! file "$BIN" | grep -q Mach-O
    then
        continue
    fi

    HASH=$(md5 -q "$BIN")

    echo "$HASH  $BIN" >> "$MD"

    json_add MD5 "$HASH" "$BIN"

done

##############################################

md_section "UUID"

find "$APP" -type f | while IFS= read -r BIN
do

    if ! file "$BIN" | grep -q Mach-O
    then
        continue
    fi

    dwarfdump --uuid "$BIN" 2>/dev/null | while IFS= read -r L
    do

        echo "$L" >> "$MD"

        UUID=$(echo "$L" | awk '{print $2}')

        json_add UUID "$UUID" "$BIN"

    done || true

done

##############################################

md_section "Bundle Identifier"

find "$APP" -name Info.plist | while IFS= read -r PLIST
do

ID=$(/usr/libexec/PlistBuddy \
-c "Print :CFBundleIdentifier" \
"$PLIST" 2>/dev/null || true)

if [ -n "$ID" ]
then

echo "$ID" >> "$MD"

json_add BundleID "$ID" "$PLIST"

fi

done

##############################################

md_section "Bundle Version"

find "$APP" -name Info.plist | while IFS= read -r PLIST
do

VER=$(/usr/libexec/PlistBuddy \
-c "Print :CFBundleShortVersionString" \
"$PLIST" 2>/dev/null || true)

if [ -n "$VER" ]
then

echo "$VER" >> "$MD"

json_add Version "$VER" "$PLIST"

fi

done

##############################################

md_section "Build Number"

find "$APP" -name Info.plist | while IFS= read -r PLIST
do

VER=$(/usr/libexec/PlistBuddy \
-c "Print :CFBundleVersion" \
"$PLIST" 2>/dev/null || true)

if [ -n "$VER" ]
then

echo "$VER" >> "$MD"

json_add Build "$VER" "$PLIST"

fi

done

##############################################

md_section "Team Identifier"

find "$APP" | while IFS= read -r ITEM
do

TEAM=$(codesign -dvv "$ITEM" 2>&1 | \
grep TeamIdentifier | \
cut -d= -f2 || true)

if [ -n "$TEAM" ]
then

echo "$TEAM  $ITEM" >> "$MD"

json_add TeamID "$TEAM" "$ITEM"

fi

done

##############################################
# URLs
##############################################

md_section "URLs"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    strings "$BIN" | \
    grep -Eo 'https?://[^"'"'"' <>]+' | \
    sort -u | while IFS= read -r URL
    do
        [ -z "$URL" ] && continue

        echo "$URL" >> "$MD"

        json_add URL "$URL" "$BIN"

    done || true

done

##############################################
# Domains
##############################################

md_section "Domains"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    strings "$BIN" | \
    grep -Eo '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}' | \
    sort -u | while IFS= read -r DOMAIN
    do

        echo "$DOMAIN" >> "$MD"

        json_add Domain "$DOMAIN" "$BIN"

    done || true

done

##############################################
# IPv4
##############################################

md_section "IPv4"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    strings "$BIN" | \
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sort -u | while IFS= read -r IP
    do

        echo "$IP" >> "$MD"

        json_add IPv4 "$IP" "$BIN"

    done || true

done

##############################################
# IPv6
##############################################

md_section "IPv6"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    strings "$BIN" | \
    grep -Eio '([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}' | \
    sort -u | while IFS= read -r IP
    do

        echo "$IP" >> "$MD"

        json_add IPv6 "$IP" "$BIN"

    done || true

done

##############################################
# Email
##############################################

md_section "Email"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    strings "$BIN" | \
    grep -Eio '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | \
    sort -u | while IFS= read -r MAIL
    do

        echo "$MAIL" >> "$MD"

        json_add Email "$MAIL" "$BIN"

    done || true

done

##############################################
# Frameworks
##############################################

md_section "Frameworks"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    otool -L "$BIN" 2>/dev/null | \
    grep Framework | while IFS= read -r LINE
    do

        echo "$LINE" >> "$MD"

        json_add Framework "$LINE" "$BIN"

    done || true

done

##############################################
# dylib
##############################################

md_section "Dynamic Libraries"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    otool -L "$BIN" 2>/dev/null | \
    grep dylib | while IFS= read -r LINE
    do

        echo "$LINE" >> "$MD"

        json_add DYLIB "$LINE" "$BIN"

    done || true

done

##############################################
# LC_RPATH
##############################################

md_section "RPATH"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    otool -l "$BIN" 2>/dev/null | \
    awk '
        /LC_RPATH/{f=1}
        f && /path/{
            print $2
            f=0
        }' | while IFS= read -r P
    do

        echo "$P" >> "$MD"

        json_add RPATH "$P" "$BIN"

    done || true

done

##############################################
# Go Version
##############################################

md_section "Go Runtime"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    strings "$BIN" | \
    grep '^go1\.' | \
    sort -u | while IFS= read -r GO
    do

        echo "$GO" >> "$MD"

        json_add Go "$GO" "$BIN"

    done || true

done

##############################################
# Go BuildID
##############################################

md_section "Go BuildID"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    BID=$(go tool buildid "$BIN" 2>/dev/null || true)

    if [ -n "$BID" ]
    then
        echo "$BID" >> "$MD"

        json_add GoBuildID "$BID" "$BIN"
    fi

done

##############################################
# Fyne
##############################################

md_section "Fyne"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    strings "$BIN" | \
    grep 'github.com/fyne-io' | \
    sort -u | while IFS= read -r FYNE
    do

        echo "$FYNE" >> "$MD"

        json_add Fyne "$FYNE" "$BIN"

    done || true

done

##############################################
# OpenConnect
##############################################

md_section "OpenConnect"

find "$APP" -type f | while IFS= read -r BIN
do
    if ! file "$BIN" | grep -q Mach-O; then
        continue
    fi

    strings "$BIN" | \
    grep -Ei 'openconnect|libopenconnect|CSTP|DTLS|ESP' | \
    sort -u | while IFS= read -r OC
    do

        echo "$OC" >> "$MD"

        json_add OpenConnect "$OC" "$BIN"

    done || true

done

##############################################
# JSON END
##############################################

python3 - "$JSON_TMP" "$JSON" <<'PY'
import csv
import json
import sys
from datetime import datetime

tsv_path, json_path = sys.argv[1], sys.argv[2]
items = []

with open(tsv_path, newline="", encoding="utf-8", errors="replace") as f:
    for row in csv.reader(f, delimiter="\t"):
        if len(row) != 3:
            continue
        items.append({"type": row[0], "value": row[1], "source": row[2]})

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(
        {"generated": datetime.utcnow().isoformat(timespec="seconds") + "Z", "ioc": items},
        f,
        ensure_ascii=False,
        indent=2,
    )
    f.write("\n")
PY

##############################################
# Summary
##############################################

md_section "Summary"

echo "| Item | Count |" >> "$MD"
echo "|------|------:|" >> "$MD"

for TYPE in \
SHA256 SHA1 MD5 UUID BundleID Version Build TeamID \
URL Domain IPv4 IPv6 Email Framework DYLIB \
RPATH Go GoBuildID Fyne OpenConnect
do

COUNT=$( (grep "^$TYPE," "$CSV" || true) | wc -l | tr -d ' ' )

echo "| $TYPE | $COUNT |" >> "$MD"

done

echo "" >> "$MD"
echo "IOC generation completed." >> "$MD"

echo "IOC files generated:"
echo "  $MD"
echo "  $CSV"
echo "  $JSON"
