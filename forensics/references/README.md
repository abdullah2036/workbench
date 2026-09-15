# forensics/references

## Visual / interactive (can't be scripted well — use these)

- **Aperi'Solve** — https://www.aperisolve.com/
  Upload an image; it runs zsteg, steghide, binwalk, exiftool, outguess AND shows
  every bit-plane and channel at once. Best first stop for image stego. *(online)*
- **StegSolve** (jar) — https://github.com/zardus/ctf-tools (or Google "stegsolve.jar")
  Browse bit planes, XOR channels, do image arithmetic. Offline. Run:
  `java -jar stegsolve.jar`.
- **StegOnline** — https://georgeom.net/StegOnline/  — browser bit-plane browser.

## Audio

- **Sonic Visualiser** — https://www.sonicvisualiser.org/  — open audio, add a
  **spectrogram** layer. Flags/text/morse are frequently drawn in the spectrogram.
- **Audacity** — spectrogram view + can decode slow-scan / DTMF / morse by ear.

## File identification & repair

- **CyberChef** — https://gchq.github.io/CyberChef/ — "Detect File Type",
  "Extract Files", magic-byte fixing.
- **Hex editor** — `wxHexEditor` / `hexedit` / online https://hexed.it — manually
  fix broken magic bytes (a corrupted PNG header is a classic; the correct one is
  `89 50 4E 47 0D 0A 1A 0A`).
- **File signatures table** — https://en.wikipedia.org/wiki/List_of_file_signatures

## Disk & memory

- **Autopsy / Sleuth Kit** — https://www.sleuthkit.org/ — disk-image browsing,
  deleted-file recovery (GUI: `autopsy`).
- **Volatility 3** — https://github.com/volatilityfoundation/volatility3 — memory
  forensics (`mem.sh` wraps the common plugins). Cheat sheet:
  https://blog.onfvp.com/post/volatility-cheatsheet/

## PDF / documents

- **PDF tools** — `peepdf`, `pdf-parser.py`, `pdfid` (Didier Stevens suite):
  https://blog.didierstevens.com/programs/pdf-tools/
- **oletools** — https://github.com/decalage2/oletools — macros in Office docs.

## Quick decision table

| Artifact | Start with |
|---|---|
| image | `stego.sh` → Aperi'Solve → StegSolve |
| audio | Sonic Visualiser spectrogram |
| pcap | `pcap.sh` → Wireshark Follow Stream |
| USB pcap | `usb_hid.py` |
| memory dump | `mem.sh` (Volatility 3) |
| disk image | Autopsy / `mmls` + `fls` + `icat` |
| broken/unknown file | `observe.sh` → fix magic bytes in hex editor |
