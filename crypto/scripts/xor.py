#!/usr/bin/env python3
"""
xor.py — XOR toolkit (single-byte brute, repeating-key crack, known-plaintext).

Input can be hex, base64, or raw (from a file). Examples:

  # Single-byte XOR brute force, ranked by English-likeness
  python3 xor.py brute --hex 1b37373331363f...
  python3 xor.py brute -f cipher.bin

  # Repeating-key XOR (Vigenere-on-bytes): auto-detect key size and crack
  python3 xor.py repeating -f cipher.bin
  python3 xor.py repeating -f cipher.bin --keysize 5

  # Recover key from known plaintext crib (e.g. you know it starts with "flag{")
  python3 xor.py known --hex <cipherhex> --crib 'flag{'

  # Just XOR two things together
  python3 xor.py apply --hex <hex> --key 'mykey'
  python3 xor.py apply --hex <hex> --keyhex 41
"""
import argparse, base64, sys, itertools

def read_data(a):
    if a.file:  return open(a.file, "rb").read()
    if a.hex:   return bytes.fromhex(a.hex.replace(" ", "").replace("\n", ""))
    if a.b64:   return base64.b64decode(a.b64)
    if a.text is not None: return a.text.encode()
    sys.exit("no input: use -f/--hex/--b64/--text")

def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# English scoring: printable ratio + common-letter frequency
FREQ = {c: f for c, f in zip("etaoinshrdlcumwfgypbvkjxqz ",
        [12.7,9.1,8.2,7.5,7.0,6.7,6.3,6.1,6.0,4.3,4.0,2.8,2.8,2.4,2.4,2.2,2.0,
         2.0,1.9,1.5,1.0,0.8,0.15,0.15,0.10,0.07,18.0])}
def score(bs):
    if not bs: return -1e9
    s, printable = 0.0, 0
    for b in bs:
        ch = chr(b)
        if 32 <= b < 127 or b in (9, 10, 13): printable += 1
        s += FREQ.get(ch.lower(), 0.0)
    return s * (printable / len(bs)) ** 3   # heavily penalize non-printable

def brute_single(data, top=5):
    res = []
    for k in range(256):
        pt = xor_bytes(data, bytes([k]))
        res.append((score(pt), k, pt))
    res.sort(reverse=True, key=lambda x: x[0])
    print(f"[*] top {top} single-byte keys:")
    for sc, k, pt in res[:top]:
        preview = pt[:80].decode("latin-1")
        print(f"  key=0x{k:02x} ({chr(k) if 32<=k<127 else '.'})  score={sc:6.1f}  {preview!r}")
    return res[0]

def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def guess_keysizes(data, lo=2, hi=40, n=3):
    scores = []
    hi = min(hi, len(data) // 4)
    for ks in range(lo, hi + 1):
        blocks = [data[i*ks:(i+1)*ks] for i in range(4)]
        d = (hamming(blocks[0], blocks[1]) + hamming(blocks[1], blocks[2]) +
             hamming(blocks[2], blocks[3])) / 3 / ks
        scores.append((d, ks))
    scores.sort()
    return [ks for _, ks in scores[:n]]

def crack_repeating(data, keysize):
    key = bytearray()
    for i in range(keysize):
        col = data[i::keysize]
        best = brute_col(col)
        key.append(best)
    return bytes(key)

def brute_col(col):
    best_k, best_s = 0, -1e9
    for k in range(256):
        s = score(xor_bytes(col, bytes([k])))
        if s > best_s: best_s, best_k = s, k
    return best_k

def main():
    ap = argparse.ArgumentParser(description="XOR toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    def io(p):
        p.add_argument("-f", "--file"); p.add_argument("--hex")
        p.add_argument("--b64"); p.add_argument("--text")

    b = sub.add_parser("brute"); io(b); b.add_argument("--top", type=int, default=6)
    r = sub.add_parser("repeating"); io(r)
    r.add_argument("--keysize", type=int, help="force key size instead of auto-detect")
    k = sub.add_parser("known"); io(k); k.add_argument("--crib", required=True)
    ap2 = sub.add_parser("apply"); io(ap2)
    ap2.add_argument("--key"); ap2.add_argument("--keyhex")

    a = ap.parse_args()
    data = read_data(a)

    if a.cmd == "brute":
        brute_single(data, a.top)

    elif a.cmd == "repeating":
        sizes = [a.keysize] if a.keysize else guess_keysizes(data)
        print(f"[*] candidate key sizes: {sizes}")
        for ks in sizes:
            key = crack_repeating(data, ks)
            pt = xor_bytes(data, key)
            print(f"\n[+] keysize={ks} key={key!r} (hex {key.hex()})")
            print(pt[:300].decode("latin-1"))

    elif a.cmd == "known":
        crib = a.crib.encode()
        print(f"[*] key fragment from crib {crib!r} at offset 0:")
        frag = bytes(data[i] ^ crib[i] for i in range(min(len(crib), len(data))))
        print(f"  key fragment = {frag!r}  (hex {frag.hex()})")
        print("  (slide the crib to other offsets if the key repeats)")

    elif a.cmd == "apply":
        if a.keyhex: key = bytes.fromhex(a.keyhex)
        elif a.key:  key = a.key.encode()
        else: sys.exit("apply needs --key or --keyhex")
        out = xor_bytes(data, key)
        sys.stdout.buffer.write(out)

if __name__ == "__main__":
    main()
