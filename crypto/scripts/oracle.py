#!/usr/bin/env python3
"""
oracle.py — pwntools templates for INTERACTIVE crypto challenges.

Most "hard" crypto challenges are a network service that leaks one bit / one byte
at a time. The win is a tight send/recv loop. This file is a copy-paste starting
point for the three most common oracle attacks. Uncomment the one you need and
wire up `query()` to the actual service protocol.

  python3 oracle.py         # runs whichever main() you enable below

Docs: pwntools -> https://docs.pwntools.com
"""
from pwn import *   # noqa
context.log_level = "info"

HOST, PORT = "CHALLENGE.HOST", 1337   # <-- edit

def conn():
    # return process("./chal")        # local binary
    return remote(HOST, PORT)         # remote service

# ---------------------------------------------------------------------------
# 1) PADDING ORACLE (CBC). The server tells you (somehow) whether padding is
#    valid. Recovers plaintext with ~256 queries per byte, no key needed.
# ---------------------------------------------------------------------------
def padding_oracle():
    BS = 16  # block size

    def valid_padding(iv_and_ct: bytes) -> bool:
        io = conn()
        # ---- EDIT: send the ciphertext, read whether padding was OK ----
        io.sendlineafter(b"ct: ", iv_and_ct.hex().encode())
        resp = io.recvline()
        io.close()
        return b"OK" in resp        # or b"padding" not in resp, etc.

    def decrypt_block(prev: bytes, cur: bytes) -> bytes:
        inter = bytearray(BS)       # intermediate state D_k(cur)
        recovered = bytearray(BS)
        for pad in range(1, BS + 1):
            idx = BS - pad
            for guess in range(256):
                forged = bytearray(BS)
                for j in range(idx + 1, BS):
                    forged[j] = inter[j] ^ pad
                forged[idx] = guess
                if valid_padding(bytes(forged) + cur):
                    # avoid false positive on the very first byte
                    if pad == 1:
                        forged[idx - 1] ^= 1
                        if not valid_padding(bytes(forged) + cur):
                            continue
                    inter[idx] = guess ^ pad
                    recovered[idx] = inter[idx] ^ prev[idx]
                    break
        return bytes(recovered)

    ct = bytes.fromhex("EDIT_FULL_CIPHERTEXT_INCLUDING_IV_HEX")
    blocks = [ct[i:i+BS] for i in range(0, len(ct), BS)]
    pt = b""
    for i in range(1, len(blocks)):
        pt += decrypt_block(blocks[i-1], blocks[i])
        log.info("recovered so far: %r", pt)
    log.success("plaintext = %r", pt)

# ---------------------------------------------------------------------------
# 2) BYTE-AT-A-TIME ECB DECRYPTION. Server encrypts  AES-ECB(your_input||SECRET).
#    Leak SECRET one byte at a time by aligning it to a block boundary.
# ---------------------------------------------------------------------------
def ecb_byte_at_a_time():
    def encrypt(data: bytes) -> bytes:
        io = conn()
        io.sendlineafter(b"input: ", data.hex().encode())  # <-- EDIT protocol
        out = bytes.fromhex(io.recvline().strip().decode())
        io.close()
        return out

    BS = 16
    known = b""
    # find secret length roughly by watching ciphertext grow (optional)
    for _ in range(128):
        pad_len = (BS - (len(known) + 1)) % BS
        prefix = b"A" * pad_len
        target_block = (len(prefix) + len(known)) // BS
        target = encrypt(prefix)[target_block*BS:(target_block+1)*BS]
        found = None
        for b in range(256):
            guess = prefix + known + bytes([b])
            blk = encrypt(guess)[target_block*BS:(target_block+1)*BS]
            if blk == target:
                found = b; break
        if found is None: break
        known += bytes([found])
        log.info("secret so far: %r", known)
    log.success("SECRET = %r", known)

# ---------------------------------------------------------------------------
# 3) RSA LSB / PARITY ORACLE. Server decrypts and leaks the least-significant
#    bit of the plaintext. Binary-search the message in ~log2(n) queries.
# ---------------------------------------------------------------------------
def rsa_lsb_oracle():
    from decimal import Decimal, getcontext
    N = 0  # <-- edit
    E = 65537
    C = 0  # <-- edit

    def lsb(ciphertext: int) -> int:
        io = conn()
        io.sendlineafter(b"c: ", str(ciphertext).encode())  # <-- EDIT
        bit = int(io.recvline().strip())
        io.close()
        return bit

    getcontext().prec = N.bit_length() + 10
    lo, hi = Decimal(0), Decimal(N)
    mult = pow(2, E, N)
    c = C
    for i in range(N.bit_length()):
        c = (c * mult) % N
        if lsb(c) == 0:
            hi = (lo + hi) / 2
        else:
            lo = (lo + hi) / 2
        log.info("bit %d", i)
    from math import floor
    log.success("m = %d", int(floor(hi)))

if __name__ == "__main__":
    log.warning("Edit HOST/PORT and enable ONE attack below, then re-run.")
    # padding_oracle()
    # ecb_byte_at_a_time()
    # rsa_lsb_oracle()
