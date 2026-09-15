# crypto/references

Online tools that beat local scripts for certain tasks. **Grab offline copies
where noted if the venue is air-gapped.**

## Swiss-army

- **CyberChef** — https://gchq.github.io/CyberChef/
  The "cyber swiss army knife". Chain operations (From Base64 → Gunzip → XOR →
  ...). Use the **Magic** operation (wand icon) to auto-detect encodings/ciphers.
  *Offline:* download the single-file build from the GitHub releases
  (`gchq/CyberChef`) — it runs from a local `.html` with no internet.

- **dcode.fr** — https://www.dcode.fr/en
  Auto-solves classical ciphers (Vigenère without key, substitution, rail fence,
  Playfair, book ciphers, etc.). The "Cipher Identifier" page is the fastest way
  to answer "what cipher is this?".

## RSA / number theory

- **FactorDB** — http://factordb.com/  — is this modulus already factored?
  (`rsa.py` queries it automatically unless `--no-net`.)
- **RsaCtfTool** — https://github.com/RsaCtfTool/RsaCtfTool  (installed to
  `~/tools` by setup). ~20 automated attacks; the fallback when `rsa.py` gives up.
- **Alpertron ECM** — https://www.alpertron.com.ar/ECM.HTM  — factor mid-size
  integers (elliptic-curve method) right in the browser.
- **SageMath** — https://www.sagemath.org/  (installed). For lattices/Coppersmith,
  ECC, discrete log. Use **SageMathCell** (https://sagecell.sagemath.org/) if you
  didn't install it locally.

## Hashes & passwords

- **CrackStation** — https://crackstation.net/  — lookup for unsalted hashes.
- **hashes.com** — https://hashes.com/en/decrypt/hash  — identify + lookup.
- Local: `hashid`/`hashcat --identify`, then `john` / `hashcat` with rockyou.

## Substitution / word puzzles

- **quipqiup** — https://quipqiup.com/  — auto-solve monoalphabetic substitution
  and cryptograms from frequency + dictionary.
- **Boxentriq** — https://www.boxentriq.com/code-breaking  — cipher identifier +
  many solvers, good for the weird ones.

## When to reach for what

| You have… | Reach for |
|---|---|
| n, e, c | `rsa.py` → RsaCtfTool → Alpertron/Sage |
| "looks encoded" | CyberChef Magic |
| shifted/classical text | dcode Cipher Identifier / `classical.py` |
| a hash | hashid → CrackStation → john/hashcat |
| a cryptogram | quipqiup |
| lattice / ECC / weird math | SageMath |
