#!/usr/bin/env python3
"""
classical.py — quick classical-cipher + encoding helpers.

For the "it's obviously encoded/shifted but which one?" moment. For anything
exotic, dcode.fr auto-solves faster (see ../references).

  python3 classical.py caesar "Uryyb Jbeyq"          # all 26 shifts
  python3 classical.py rot13   "Uryyb"
  python3 classical.py atbash  "Svool"
  python3 classical.py vigenere dec "LXFOPVEFRNHR" --key LEMON
  python3 classical.py vigenere enc "ATTACKATDAWN" --key LEMON
  python3 classical.py morse   "... --- ..."
  python3 classical.py bases   "SGVsbG8="           # try base16/32/64/85 decode
  python3 classical.py freq    "cipher text here"    # letter frequency for substitution
"""
import argparse, base64, binascii, sys
from collections import Counter

def caesar_all(s):
    for k in range(26):
        out = "".join(
            chr((ord(c)-65+k)%26+65) if c.isupper() else
            chr((ord(c)-97+k)%26+97) if c.islower() else c for c in s)
        print(f"  shift {k:2d}: {out}")

def rot13(s):
    import codecs; return codecs.encode(s, "rot_13")

def atbash(s):
    return "".join(
        chr(90-(ord(c)-65)) if c.isupper() else
        chr(122-(ord(c)-97)) if c.islower() else c for c in s)

def vigenere(s, key, dec=True):
    key = [ord(k.lower())-97 for k in key if k.isalpha()]
    out, ki = [], 0
    for c in s:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            k = key[ki % len(key)]
            k = -k if dec else k
            out.append(chr((ord(c)-base+k) % 26 + base)); ki += 1
        else: out.append(c)
    return "".join(out)

MORSE = {
 '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H',
 '..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P',
 '--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
 '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4',
 '.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'}
def morse_decode(s):
    return "".join(MORSE.get(t, "?") for t in s.replace("/", " ").split())

def try_bases(s):
    s = s.strip()
    def show(name, fn):
        try:
            out = fn(s)
            print(f"  {name:8s}: {out!r}")
        except Exception as e:
            print(f"  {name:8s}: (fail: {e})")
    show("base64",  lambda x: base64.b64decode(x + "="*(-len(x)%4)))
    show("base32",  lambda x: base64.b32decode(x + "="*(-len(x)%8)))
    show("base16",  lambda x: base64.b16decode(x, casefold=True))
    show("base85",  lambda x: base64.b85decode(x))
    show("ascii85", lambda x: base64.a85decode(x))
    show("hex",     lambda x: binascii.unhexlify(x.replace(" ", "")))

def freq(s):
    letters = [c.lower() for c in s if c.isalpha()]
    total = len(letters) or 1
    print("  letter frequency (English order: e t a o i n s h r d l ...):")
    for ch, n in Counter(letters).most_common():
        print(f"    {ch}: {n:4d}  {100*n/total:5.1f}%  {'#'*(n*40//total)}")

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("caesar","rot13","atbash","morse","bases","freq"):
        p = sub.add_parser(name); p.add_argument("text")
    v = sub.add_parser("vigenere"); v.add_argument("mode", choices=["enc","dec"])
    v.add_argument("text"); v.add_argument("--key", required=True)
    a = ap.parse_args()

    if a.cmd == "caesar": caesar_all(a.text)
    elif a.cmd == "rot13": print(rot13(a.text))
    elif a.cmd == "atbash": print(atbash(a.text))
    elif a.cmd == "morse": print(morse_decode(a.text))
    elif a.cmd == "bases": try_bases(a.text)
    elif a.cmd == "freq": freq(a.text)
    elif a.cmd == "vigenere": print(vigenere(a.text, a.key, dec=(a.mode=="dec")))

if __name__ == "__main__":
    main()
