#!/usr/bin/env python3
"""
decode.py — recursive "peel the encoding layers" helper.

For the classic "base64 of hex of rot13 of ..." nesting. It repeatedly detects
and decodes the outermost layer until it hits something that looks like a flag
or plain text. Think of it as a tiny offline CyberChef "Magic".

  python3 decode.py "..."          # decode a string argument
  echo "..." | python3 decode.py   # or from stdin
  python3 decode.py -f blob.txt

Not exhaustive — for anything tricky use CyberChef's Magic (crypto/references).
"""
import sys, base64, binascii, codecs, re, argparse
from urllib.parse import unquote

FLAG = re.compile(rb'(flag|ctf|BHMEA)\{[^}]{0,200}\}', re.I)

def looks_text(b):
    if not b: return False
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9,10,13))
    return printable / len(b) > 0.9

def try_layers(b):
    """yield (name, decoded_bytes) for each plausible single-layer decode."""
    s = b.decode("latin-1").strip()
    # base64
    if re.fullmatch(r'[A-Za-z0-9+/=\s]+', s) and len(s.strip()) >= 4:
        try:
            d = base64.b64decode(s + "=" * (-len(s.strip()) % 4), validate=False)
            if d and d != b: yield ("base64", d)
        except Exception: pass
    # base32
    if re.fullmatch(r'[A-Z2-7=\s]+', s) and len(s.strip()) >= 8:
        try:
            d = base64.b32decode(s.strip() + "=" * (-len(s.strip()) % 8))
            if d: yield ("base32", d)
        except Exception: pass
    # hex
    hs = re.sub(r'\s', '', s)
    if re.fullmatch(r'(0x)?[0-9a-fA-F]+', hs) and len(hs) % 2 == 0:
        try:
            d = binascii.unhexlify(hs[2:] if hs.startswith("0x") else hs)
            if d: yield ("hex", d)
        except Exception: pass
    # url-encoding
    if "%" in s:
        d = unquote(s).encode("latin-1", "ignore")
        if d != b: yield ("url", d)
    # rot13 (only if alpha-heavy)
    if sum(c.isalpha() for c in s) > len(s) * 0.5:
        d = codecs.encode(s, "rot_13").encode("latin-1", "ignore")
        if d != b: yield ("rot13", d)
    # base85
    if re.fullmatch(r'[!-u\s]+', s) and len(s.strip()) >= 4:
        try:
            d = base64.a85decode(s.strip())
            if d and looks_text(d): yield ("ascii85", d)
        except Exception: pass

def peel(b, depth=0, trail=None, seen=None):
    trail = trail or []
    seen = seen if seen is not None else set()
    m = FLAG.search(b)
    if m:
        print(f"[+] FLAG after {' -> '.join(trail) or '(no decode)'}: {m.group().decode('latin-1')}")
        return True
    if depth > 12: return False
    for name, d in try_layers(b):
        key = (name, d[:64])
        if key in seen: continue
        seen.add(key)
        newtrail = trail + [name]
        if looks_text(d) and len(d) < 400:
            print(f"    {' -> '.join(newtrail):40s} => {d[:120]!r}")
        if peel(d, depth + 1, newtrail, seen):
            return True
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data", nargs="?")
    ap.add_argument("-f", "--file")
    a = ap.parse_args()
    if a.file:
        raw = open(a.file, "rb").read()
    elif a.data:
        raw = a.data.encode()
    else:
        raw = sys.stdin.buffer.read()
    raw = raw.strip()
    print("[*] peeling layers (showing plausible text results)...")
    if not peel(raw):
        print("[-] no flag found. Try CyberChef Magic, or check for a cipher (classical.py).")

if __name__ == "__main__":
    main()
