# setup/

`install-kali-extras.sh` bootstraps a fresh Kali VM with everything the workbench
assumes but Kali doesn't ship (or ships too old).

```bash
chmod +x setup/install-kali-extras.sh
./setup/install-kali-extras.sh
```

## What it installs

| Tool | Why |
|---|---|
| **pwntools** | Remote-oracle interaction (crypto/pwn). The single most useful CTF lib. |
| **pycryptodome, sympy, gmpy2** | Crypto math (RSA, number theory, big ints). |
| **z3-solver, angr** | Symbolic execution — solve RE constraints without manual reversing. |
| **volatility3** | Memory-dump forensics (`vol`). |
| **zsteg, stegseek** | PNG/BMP LSB stego + fast steghide bruteforce. |
| **RsaCtfTool** | Grab-bag of ~20 automated RSA attacks (cloned to `~/tools`). |
| **Ghidra, pwndbg, radare2** | Reverse engineering. |
| **sagemath** | Heavy crypto (lattices, ECC, discrete log). |
| **john, hashcat, rockyou** | Password / hash cracking. |
| **tshark, exiftool, binwalk, foremost, sleuthkit** | Forensics staples (some already in Kali). |

It's safe to re-run — it skips things already present. If you're **offline**, the
apt packages still install from the Kali mirror if configured, but the GitHub
clones (RsaCtfTool, pwndbg) and stegseek `.deb` will fail — grab those ahead of
time on a connected machine.

### Verify afterwards (open a new shell first)

```bash
python3 -c 'import pwn, Crypto, angr; print("py libs OK")'
vol -h
zsteg --help && stegseek --help
python3 ~/tools/RsaCtfTool/RsaCtfTool.py --help
```
