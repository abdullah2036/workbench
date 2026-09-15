# misc/references

General-purpose resources that don't belong to one category.

## Multi-tools

- **CyberChef** — https://gchq.github.io/CyberChef/ — encoding/decoding/crypto
  chains + **Magic** auto-detect. The most-used tool in CTF, full stop.
- **Chepy** — https://github.com/securisec/chepy — CyberChef as a Python
  library/CLI (scriptable, offline). `pip install chepy`.

## Identify "what is this?"

- **CyberChef Magic** — paste blob, it guesses the encoding chain.
- **cipher_identifier / Boxentriq** — https://www.boxentriq.com/code-breaking
- **hashID / hash-identifier** — `hashid <hash>` (local).
- **File signatures** — https://en.wikipedia.org/wiki/List_of_file_signatures

## Esoteric / fun encodings (Misc challenges love these)

- **Brainfuck / Ook / Malbolge etc.** — https://www.dcode.fr/brainfuck-language
  and https://tio.run/ (run almost any esolang online).
- **Whitespace** — https://vii5ard.github.io/whitespace/
- **QR / barcodes** — `zbarimg image.png` (local) · https://zxing.org/w/decode
  · broken QR: rebuild in https://merricx.github.io/qrazybox/
- **Magic eye / stereogram, ASCII art, emoji ciphers** — dcode.fr has solvers.

## Learn / practice (do reps before December)

- **CTFtime** — https://ctftime.org/ — event calendar + **writeups archive**
  (search past challenges by category — this is how you build pattern recognition).
- **picoCTF** — https://picoctf.org/ — best beginner ramp, all categories, free.
- **pwn.college** — https://pwn.college/ — structured, deep (RE/pwn heavy).
- **CryptoHack** — https://cryptohack.org/ — crypto specifically, excellent.
- **OverTheWire** — https://overthewire.org/wargames/ — Linux + basics.
- **Awesome CTF** — https://github.com/apsdehal/awesome-ctf — huge curated tool list.

## Offline prep checklist (if the venue is air-gapped)

Clone/download ahead of time:
- [ ] CyberChef single-file build
- [ ] PayloadsAllTheThings, HackTricks, SecLists
- [ ] RsaCtfTool, angr examples
- [ ] rockyou.txt + a few SecLists wordlists
- [ ] StegSolve.jar, dnSpy, JD-GUI
- [ ] This repo :)
