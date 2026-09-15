#!/usr/bin/env bash
# triage.sh — deep forensics extraction pass on a file (image, archive, blob).
# Complements observe.sh: this one actually CARVES and EXTRACTS.
#   ./triage.sh <file>
set -uo pipefail
C_H='\033[1;36m'; C_K='\033[1;33m'; C_R='\033[1;31m'; C_0='\033[0m'
sec(){ printf "\n${C_H}==== %s ====${C_0}\n" "$*"; }
sub(){ printf "${C_K}-- %s --${C_0}\n" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
miss(){ printf "${C_R}(skip: %s not installed)${C_0}\n" "$1"; }

F="${1:-}"; [ -f "$F" ] || { echo "usage: $0 <file>"; exit 1; }
OUT="${F}.triage"; mkdir -p "$OUT"
echo "extraction dir: $OUT"

sec "IDENTITY"; have file && file "$F"; xxd "$F" | head -2

sec "STRINGS DUMP -> $OUT/strings.txt"
{ strings -n 5 "$F"; echo "--- utf16le ---"; strings -e l -n 5 "$F"; } > "$OUT/strings.txt"
wc -l "$OUT/strings.txt"
grep -aiE '(flag|ctf|BHMEA)\{[^}]*\}|BEGIN [A-Z ]*KEY|https?://|password|secret' \
    "$OUT/strings.txt" | sort -u | head -30 || echo "(no obvious hits — read strings.txt)"

sec "METADATA"; have exiftool && exiftool "$F" || miss exiftool

sec "BINWALK CARVE -> $OUT/_binwalk"
if have binwalk; then
    binwalk "$F"
    binwalk -e -C "$OUT" "$F" >/dev/null 2>&1 || binwalk --run-as=root -e -C "$OUT" "$F" >/dev/null 2>&1 || true
    find "$OUT" -path '*_binwalk*' -type f 2>/dev/null | head -20 | sed 's/^/  /'
else miss binwalk; fi

sec "FOREMOST CARVE -> $OUT/_foremost"
if have foremost; then
    foremost -i "$F" -o "$OUT/_foremost" >/dev/null 2>&1 || true
    find "$OUT/_foremost" -type f 2>/dev/null | grep -v audit.txt | sed 's/^/  /' | head -20
else miss foremost; fi

sec "ARCHIVE?"
MT=$(file -b --mime-type "$F" 2>/dev/null)
case "$MT" in
 *zip*) sub "zip listing"; unzip -l "$F" 2>/dev/null | head -30
        echo "  password-protected? try: fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt '$F'"
        echo "  or: zip2john '$F' > hash.txt && john hash.txt";;
 *gzip*|*x-tar*) sub "tar/gz"; tar tzvf "$F" 2>/dev/null | head -20 || tar tvf "$F" 2>/dev/null | head -20;;
 *pdf*) sub "pdf"; have pdfinfo && pdfinfo "$F"; echo "  text: pdftotext '$F' -   |  images: pdfimages -all '$F' out";;
esac

sec "IMAGE STEGO?"
case "$MT" in
 image/png|image/bmp|image/jpeg)
   echo "  -> run: ./stego.sh '$F'   (dedicated stego battery)";;
esac

sec "DONE"
echo "Look through: $OUT/  (strings.txt, _binwalk/, _foremost/)"
