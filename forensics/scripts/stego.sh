#!/usr/bin/env bash
# stego.sh — image steganography battery (PNG/JPG/BMP).
#   ./stego.sh <image> [wordlist]
# Runs every local stego tool at once. For VISUAL analysis use StegSolve /
# aperisolve (see ../references) — bit-plane browsing can't be scripted well.
set -uo pipefail
C_H='\033[1;36m'; C_K='\033[1;33m'; C_R='\033[1;31m'; C_0='\033[0m'
sec(){ printf "\n${C_H}==== %s ====${C_0}\n" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
miss(){ printf "${C_R}(skip: %s not installed)${C_0}\n" "$1"; }

F="${1:-}"; [ -f "$F" ] || { echo "usage: $0 <image> [wordlist]"; exit 1; }
WL="${2:-/usr/share/wordlists/rockyou.txt}"
OUT="${F}.stego"; mkdir -p "$OUT"

sec "IDENTITY + METADATA"; file "$F"; have exiftool && exiftool "$F"

sec "STRINGS (flag hunt)"
strings -n 5 "$F" | grep -aiE '(flag|ctf|BHMEA)\{[^}]*\}' | sort -u | head || echo "(none in ascii)"

sec "APPENDED / EMBEDDED (binwalk)"
have binwalk && { binwalk "$F"; binwalk -e -C "$OUT" "$F" >/dev/null 2>&1 || true; } || miss binwalk

sec "zsteg (PNG/BMP LSB — the big one)"
if have zsteg; then zsteg -a "$F" 2>/dev/null | head -60; else miss zsteg; fi

sec "steghide (JPG/BMP/WAV — needs passphrase)"
if have steghide; then
    echo "-- trying empty passphrase --"
    steghide extract -sf "$F" -p "" -xf "$OUT/steghide_empty.out" 2>&1 | head -3 || true
    [ -f "$OUT/steghide_empty.out" ] && echo "  GOT: $OUT/steghide_empty.out"
else miss steghide; fi

sec "stegseek (fast steghide bruteforce)"
if have stegseek; then
    if [ -f "$WL" ]; then
        stegseek "$F" "$WL" "$OUT/stegseek.out" 2>&1 | tail -6 || true
    else echo "  wordlist not found: $WL (gunzip rockyou or pass one as arg 2)"; fi
else miss stegseek; fi

sec "pngcheck (structure / hidden chunks)"
have pngcheck && pngcheck -vtp7 "$F" 2>&1 | head -30 || echo "(pngcheck not installed: apt install pngcheck)"

sec "LSB extract (naive, python)"
python3 - "$F" "$OUT" <<'PY' 2>/dev/null || echo "(needs python3 + Pillow: pip install pillow)"
import sys
try: from PIL import Image
except Exception: print("  Pillow missing"); sys.exit()
im=Image.open(sys.argv[1]).convert("RGB"); px=list(im.getdata())
bits="".join(str(px[i][ch]&1) for i in range(len(px)) for ch in range(3))
out=bytearray(int(bits[i:i+8],2) for i in range(0,len(bits)-8,8))
frag=bytes(out[:2000])
import re
m=re.findall(rb'[ -~]{4,}', frag)
print("  first printable runs from RGB-LSB (row-major, R,G,B order):")
for s in m[:15]: print("   ",s)
PY

sec "DONE"
echo "Artifacts: $OUT/"
echo "If nothing: open in StegSolve/aperisolve and browse bit planes + do channel diffs."
echo "Audio? check spectrogram in Sonic Visualiser / Audacity."
