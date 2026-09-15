#!/usr/bin/env bash
# install-kali-extras.sh
# Installs the CTF tooling that Kali either ships without, or ships in a version
# that isn't enough. Safe to re-run (idempotent-ish). Run on the Kali VM.
#
#   chmod +x setup/install-kali-extras.sh && ./setup/install-kali-extras.sh
#
set -uo pipefail

log()  { printf '\n\033[1;36m[*] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

log "Updating apt and installing base packages"
$SUDO apt-get update -y
$SUDO apt-get install -y \
    python3 python3-pip python3-venv pipx git build-essential \
    binwalk foremost exiftool steghide sleuthkit \
    tshark wireshark-common \
    gdb ltrace strace radare2 \
    sagemath \
    qpdf poppler-utils \
    john hashcat \
    ruby ruby-dev \
    default-jre \
    2>/dev/null || warn "some apt packages failed — check names on your Kali version"

log "Ensuring pipx path is set up"
pipx ensurepath >/dev/null 2>&1 || true

# --- Python CTF libs (user install so no root needed) ---
log "Installing Python libraries (pwntools, pycryptodome, sympy, gmpy2, angr, volatility3, requests)"
python3 -m pip install --user --upgrade \
    pwntools pycryptodome sympy gmpy2 requests \
    z3-solver angr volatility3 \
    2>&1 | tail -3

# --- zsteg (Ruby gem, PNG/BMP LSB stego) ---
if ! command -v zsteg >/dev/null 2>&1; then
    log "Installing zsteg (Ruby gem)"
    $SUDO gem install zsteg 2>&1 | tail -2 || warn "zsteg install failed"
else ok "zsteg already present"; fi

# --- stegseek (fast steghide bruteforce) ---
if ! command -v stegseek >/dev/null 2>&1; then
    log "Installing stegseek"
    STEGSEEK_URL="https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb"
    tmp="$(mktemp -d)"
    if wget -q "$STEGSEEK_URL" -O "$tmp/stegseek.deb"; then
        $SUDO apt-get install -y "$tmp/stegseek.deb" || warn "stegseek .deb failed"
    else warn "could not download stegseek (offline?) — grab it manually later"; fi
    rm -rf "$tmp"
else ok "stegseek already present"; fi

# --- RsaCtfTool (grab-bag of RSA attacks) ---
RSACTF_DIR="$HOME/tools/RsaCtfTool"
if [ ! -d "$RSACTF_DIR" ]; then
    log "Cloning RsaCtfTool into ~/tools/RsaCtfTool"
    mkdir -p "$HOME/tools"
    if git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool.git "$RSACTF_DIR"; then
        python3 -m pip install --user -r "$RSACTF_DIR/requirements.txt" 2>&1 | tail -2 || true
        ok "RsaCtfTool ready: python3 $RSACTF_DIR/RsaCtfTool.py --help"
    else warn "RsaCtfTool clone failed (offline?)"; fi
else ok "RsaCtfTool already cloned"; fi

# --- Ghidra (via apt if available, else note) ---
if ! command -v ghidra >/dev/null 2>&1 && [ ! -d /opt/ghidra ]; then
    log "Installing Ghidra"
    $SUDO apt-get install -y ghidra 2>/dev/null && ok "Ghidra installed via apt" \
        || warn "Ghidra not in apt — download from https://ghidra-sre.org and unzip to /opt/ghidra"
else ok "Ghidra already present"; fi

# --- pwndbg (better gdb for RE/pwn) ---
if [ ! -d "$HOME/tools/pwndbg" ]; then
    log "Installing pwndbg"
    if git clone --depth 1 https://github.com/pwndbg/pwndbg "$HOME/tools/pwndbg"; then
        ( cd "$HOME/tools/pwndbg" && ./setup.sh ) 2>&1 | tail -3 || warn "pwndbg setup failed"
    else warn "pwndbg clone failed (offline?)"; fi
else ok "pwndbg already cloned"; fi

# --- rockyou wordlist (Kali ships it gzipped) ---
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    log "Decompressing rockyou.txt"
    $SUDO gunzip -k /usr/share/wordlists/rockyou.txt.gz && ok "rockyou.txt ready"
fi

log "Done. Open a NEW shell so pipx/PATH changes take effect."
echo
echo "  Quick checks:"
echo "    python3 -c 'import pwn, Crypto, angr; print(\"py libs OK\")'"
echo "    zsteg --help ; stegseek --help ; vol -h"
echo "    python3 ~/tools/RsaCtfTool/RsaCtfTool.py --help"
