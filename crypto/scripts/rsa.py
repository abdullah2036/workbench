#!/usr/bin/env python3
"""
rsa.py — RSA multi-attack solver for CTF.

Feed it whatever you have (n, e, c, and optionally p/q/d/phi) and it tries a
battery of the classic attacks in order, stopping when it recovers the message.

Examples
--------
  # Full auto: give n, e, c and let it try everything
  python3 rsa.py -n 143 -e 7 -c 42

  # From a params file (lines like  n = 0x..  /  e=65537  /  c: 12345)
  python3 rsa.py -f params.txt

  # Common modulus (same n, two e's, two c's)
  python3 rsa.py -n N --common e1 c1 e2 c2

  # You already factored it (or know a factor)
  python3 rsa.py -n N -e E -c C -p P

Attacks tried in auto mode:
  1. Given factors / d / phi         -> direct decrypt
  2. factordb.com lookup             (needs internet; --no-net to skip)
  3. Fermat factorization            (p, q close together)
  4. Small-e / cube-root             (c == m^e, no padding, m^e < n^k boundary)
  5. Wiener's attack                 (small private exponent d)
  6. sympy factorint                 (small / smooth n)

Deps: sympy (required for a couple attacks), pycryptodome optional, requests optional.
"""
import argparse, sys, re, math

try:
    from sympy import integer_nthroot, factorint, isprime
    HAVE_SYMPY = True
except Exception:
    HAVE_SYMPY = False

def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def invmod(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1: raise ValueError("no inverse (gcd != 1)")
    return x % m

def iroot(x, n):
    """integer nth root, returns (root, is_exact)."""
    if HAVE_SYMPY:
        r, exact = integer_nthroot(x, n)
        return int(r), bool(exact)
    if x < 0: raise ValueError
    lo, hi = 0, 1 << ((x.bit_length() // n) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n < x: lo = mid + 1
        else: hi = mid
    return lo, lo ** n == x

def to_bytes(m):
    if m <= 0: return b""
    return m.to_bytes((m.bit_length() + 7) // 8, "big")

def show(m, label="RECOVERED m"):
    b = to_bytes(m)
    print(f"\n[+] {label} (int) = {m}")
    print(f"[+] {label} (hex) = {b.hex()}")
    try:
        print(f"[+] {label} (bytes) = {b!r}")
        print(f"[+] {label} (utf8) = {b.decode('utf-8','replace')}")
    except Exception:
        pass

# ---------- attacks ----------
def decrypt_with_factors(n, e, c, p=None, q=None, d=None, phi=None):
    if d is None:
        if phi is None:
            if p and q: phi = (p - 1) * (q - 1)
            elif p and n % p == 0: q = n // p; phi = (p - 1) * (q - 1)
            elif q and n % q == 0: p = n // q; phi = (p - 1) * (q - 1)
            else: return None
        d = invmod(e, phi)
    return pow(c, d, n)

def factordb(n, timeout=8):
    try:
        import requests
    except Exception:
        print("[-] factordb: requests not installed, skipping"); return None
    try:
        r = requests.get("http://factordb.com/api", params={"query": str(n)}, timeout=timeout)
        js = r.json()
        factors = []
        for base, cnt in js.get("factors", []):
            factors += [int(base)] * int(cnt)
        factors = [f for f in factors if f != 1]
        if len(factors) >= 2 and math.prod(factors) == n:
            print(f"[+] factordb factored n into {len(factors)} factors")
            return factors
        print("[-] factordb: not fully factored (status %s)" % js.get("status"))
    except Exception as ex:
        print(f"[-] factordb error: {ex}")
    return None

def fermat(n, max_iter=1_000_000):
    a, _ = iroot(n, 2)
    a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b, exact = iroot(b2, 2)
        if exact:
            return (a - b, a + b)
        a += 1
    return None

def small_e_root(n, e, c):
    # c == m^e with no modular wrap (small m, small e). Try plain and +k*n.
    for k in range(0, 20000):
        r, exact = iroot(c + k * n, e)
        if exact:
            return r
    return None

def wiener(n, e):
    # continued-fraction convergents of e/n -> candidate d
    def cf(a, b):
        while b:
            q = a // b; yield q; a, b = b, a - q * b
    def convergents(seq):
        n0, n1, d0, d1 = 0, 1, 1, 0
        for q in seq:
            n0, n1 = n1, q * n1 + n0
            d0, d1 = d1, q * d1 + d0
            yield n0, d0
    for k, d in convergents(cf(e, n)):
        if k == 0: continue
        if (e * d - 1) % k != 0: continue
        phi = (e * d - 1) // k
        # solve x^2 - (n - phi + 1)x + n = 0 ; roots are p,q
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0: continue
        s, exact = iroot(disc, 2)
        if exact and (b + s) % 2 == 0:
            return d
    return None

def common_modulus(n, e1, c1, e2, c2):
    g, a, b = egcd(e1, e2)
    if g != 1:
        print("[-] common modulus needs gcd(e1,e2)==1"); return None
    m = 1
    if a < 0: c1 = invmod(c1, n); a = -a
    if b < 0: c2 = invmod(c2, n); b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n

# ---------- driver ----------
def parse_int(s):
    s = s.strip().replace("_", "")
    if s.lower().startswith("0x"): return int(s, 16)
    if re.fullmatch(r"[0-9a-fA-F]+", s) and (len(s) % 2 == 0) and not s.isdigit():
        return int(s, 16)
    return int(s)

def parse_file(path):
    vals = {}
    txt = open(path).read()
    for key in ("n", "e", "c", "p", "q", "d", "phi"):
        m = re.search(rf"\b{key}\b\s*[:=]\s*([0-9a-fA-Fx_]+)", txt)
        if m: vals[key] = parse_int(m.group(1))
    return vals

def auto(n, e, c, p=None, q=None, d=None, phi=None, use_net=True):
    if any(v is not None for v in (p, q, d, phi)):
        print("[*] trying direct decrypt with supplied factor/d/phi")
        m = decrypt_with_factors(n, e, c, p, q, d, phi)
        if m: show(m); return m
    if use_net:
        print("[*] querying factordb...")
        fs = factordb(n)
        if fs and len(fs) == 2:
            m = decrypt_with_factors(n, e, c, p=fs[0], q=fs[1])
            if m: show(m, "via factordb"); return m
    print("[*] Fermat factorization (close primes)...")
    fr = fermat(n, max_iter=200000)
    if fr:
        print(f"[+] Fermat: p={fr[0]}\n            q={fr[1]}")
        m = decrypt_with_factors(n, e, c, p=fr[0], q=fr[1])
        if m: show(m, "via Fermat"); return m
    if e <= 11:
        print(f"[*] small-e cube/root attack (e={e})...")
        r = small_e_root(n, e, c)
        if r is not None: show(r, "via small-e root"); return r
    print("[*] Wiener's attack (small d)...")
    d2 = wiener(n, e)
    if d2:
        print(f"[+] Wiener recovered d={d2}")
        show(pow(c, d2, n), "via Wiener"); return pow(c, d2, n)
    if HAVE_SYMPY and n.bit_length() <= 90:
        print("[*] sympy factorint (small n)...")
        fac = factorint(n)
        if len(fac) >= 2:
            ps = []
            for pr, k in fac.items(): ps += [pr] * k
            m = decrypt_with_factors(n, e, c, p=ps[0], q=n // ps[0])
            if m: show(m, "via sympy"); return m
    print("\n[-] No attack succeeded automatically.")
    print("    Ideas: check for many-primes (RsaCtfTool), partial-key/Coppersmith (sage),")
    print("    LSB/parity oracle (interactive -> crypto/scripts/oracle.py), or Hastad broadcast.")
    print("    Try:  python3 ~/tools/RsaCtfTool/RsaCtfTool.py -n %d -e %d --uncipher %d" % (n, e, c))
    return None

def main():
    ap = argparse.ArgumentParser(description="RSA multi-attack solver")
    ap.add_argument("-n"); ap.add_argument("-e"); ap.add_argument("-c")
    ap.add_argument("-p"); ap.add_argument("-q"); ap.add_argument("-d"); ap.add_argument("--phi")
    ap.add_argument("-f", "--file", help="params file (n=.. e=.. c=..)")
    ap.add_argument("--common", nargs=4, metavar=("e1","c1","e2","c2"),
                    help="common-modulus attack: needs -n and these 4")
    ap.add_argument("--no-net", action="store_true", help="skip factordb / internet")
    a = ap.parse_args()

    vals = parse_file(a.file) if a.file else {}
    def g(k, cli):
        if cli is not None: return parse_int(cli)
        return vals.get(k)

    n = g("n", a.n)
    if a.common:
        if n is None: ap.error("--common needs -n")
        e1, c1, e2, c2 = (parse_int(x) for x in a.common)
        m = common_modulus(n, e1, c1, e2, c2)
        if m: show(m, "via common modulus")
        return
    e = g("e", a.e); c = g("c", a.c)
    p = g("p", a.p); q = g("q", a.q); d = g("d", a.d); phi = g("phi", a.phi)
    if n is None or e is None or c is None:
        ap.error("need at least n, e, c (via flags or -f file)")
    auto(n, e, c, p, q, d, phi, use_net=not a.no_net)

if __name__ == "__main__":
    main()
