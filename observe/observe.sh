#!/usr/bin/env bash
# observe.sh — universal first-look triage for ANY unknown file.
# Runs the whole "what am I even looking at" battery at once and prints a report.
#
#   ./observe.sh <file>
#
# It NEVER modifies the input. Anything it extracts goes to <file>.observe/.
set -uo pipefail

C_H='\033[1;36m'; C_K='\033[1;33m'; C_G='\033[1;32m'; C_R='\033[1;31m'; C_0='\033[0m'
sec()  { printf "\n${C_H}==== %s ====${C_0}\n" "$*"; }
sub()  { printf "${C_K}-- %s --${C_0}\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
miss() { printf "${C_R}(skip: %s not installed)${C_0}\n" "$1"; }

F="${1:-}"
if [ -z "$F" ] || [ ! -f "$F" ]; then
    echo "usage: $0 <file>"; exit 1
fi
OUT="${F}.observe"; mkdir -p "$OUT"
SIZE=$(wc -c < "$F")

sec "BASICS"
printf "path : %s\n" "$F"
printf "size : %s bytes\n" "$SIZE"
have file && { sub "file(1)"; file "$F"; }
sub "first 32 bytes (magic)"; xxd "$F" | head -2

sec "HASHES"
for h in md5sum sha1sum sha256sum; do
    have "$h" && printf "%-9s %s\n" "${h%sum}:" "$($h "$F" | awk '{print $1}')"
done

sec "STRINGS (flag-ish + interesting)"
# Common flag-format hunt — tweak FLAG regex per event
FLAG='(flag|ctf|FLAG|CTF)\{[^}]*\}|BHMEA\{[^}]*\}'
sub "possible flags (ascii + utf16)"
{ strings -n 6 "$F"; strings -e l -n 6 "$F"; strings -e b -n 6 "$F"; } \
    | grep -aE "$FLAG" | sort -u | head -40 || echo "(none matched — widen FLAG regex in this script)"
sub "urls / hosts / emails / keys"
strings -n 6 "$F" | grep -aiE 'https?://|www\.|@[a-z0-9.-]+\.[a-z]{2,}|BEGIN [A-Z ]*KEY|password|passwd|secret|token' \
    | sort -u | head -30 || true

sec "METADATA"
if have exiftool; then exiftool "$F"; else miss exiftool; fi

sec "EMBEDDED / APPENDED DATA"
if have binwalk; then
    sub "binwalk signature scan"
    binwalk "$F"
    sub "auto-extract → $OUT/_binwalk"
    binwalk --run-as=root -e --directory "$OUT" "$F" >/dev/null 2>&1 \
        || binwalk -e -C "$OUT" "$F" >/dev/null 2>&1 || true
    find "$OUT" -type d -name '_*' 2>/dev/null | sed 's/^/  extracted: /' | head
else miss binwalk; fi
# Data hidden AFTER a valid image/archive end marker is a classic trick:
sub "trailing-data check"
python3 - "$F" <<'PY' 2>/dev/null || echo "(python3 not available)"
import sys
d=open(sys.argv[1],'rb').read()
sig={b'\x89PNG':(b'IEND\xaeB`\x82','PNG'),b'\xff\xd8\xff':(b'\xff\xd9','JPEG'),
     b'GIF8':(b'\x00\x3b','GIF'),b'PK\x03\x04':(None,'ZIP')}
for m,(end,name) in sig.items():
    if d.startswith(m):
        if end:
            i=d.rfind(end)
            if i!=-1 and i+len(end)<len(d):
                extra=len(d)-(i+len(end))
                print(f"  {name}: {extra} bytes AFTER end marker — likely hidden payload!")
            else: print(f"  {name}: no trailing data after end marker")
        else: print(f"  {name}: archive — inspect with unzip -l")
        break
else: print("  (not a recognized image/archive container)")
PY

sec "ENTROPY (packed / encrypted / compressed?)"
python3 - "$F" <<'PY' 2>/dev/null || miss python3
import sys,math,collections
d=open(sys.argv[1],'rb').read()
if not d: print("  empty"); sys.exit()
c=collections.Counter(d); n=len(d)
H=-sum((v/n)*math.log2(v/n) for v in c.values())
print(f"  Shannon entropy: {H:.3f} / 8.0")
if H>7.5:  print("  >7.5  → looks encrypted/compressed/packed")
elif H>6:  print("  6-7.5 → mixed / could be media or lightly encoded")
else:      print("  <6    → looks like plain text / structured data")
PY

sec "TYPE-SPECIFIC HINTS"
MT=$(file -b --mime-type "$F" 2>/dev/null || echo "")
case "$MT" in
  image/png|image/bmp) echo "  → PNG/BMP: run  forensics/scripts/stego.sh '$F'  (zsteg, LSB)";;
  image/jpeg)          echo "  → JPEG: try  steghide extract -sf '$F'  and  stegseek '$F'";;
  audio/*)             echo "  → audio: check spectrogram (Sonic Visualiser / Audacity), LSB, morse";;
  application/zip|application/*zip*) echo "  → zip: unzip -l '$F' ; try fcrackzip / john for password";;
  application/x-dosexec|application/x-executable|application/x-pie-executable|application/x-sharedlib)
        echo "  → binary: run  re/scripts/angr_solver.py '$F'  and open in Ghidra";;
  application/x-pcapng|application/vnd.tcpdump.pcap) echo "  → pcap: run  forensics/scripts/pcap.sh '$F'";;
  text/*)              echo "  → text: check encodings (base64/hex/rot), run misc/scripts helpers";;
  *)                   echo "  → mime: ${MT:-unknown}";;
esac

sec "DONE"
echo "Extracted artifacts (if any): $OUT/"
echo "Next: pick the category folder the hints point to."
