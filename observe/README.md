# observe/

**Always start here.** `observe.sh` is the "what am I even looking at?" tool. It
runs the whole first-look battery in one shot so you never forget a step under
time pressure, and so you have **structured facts to hand to AI** instead of a
blind prompt.

```bash
chmod +x observe/observe.sh
./observe/observe.sh ./mystery_file
```

## What it reports

1. **Basics** — `file(1)` type, size, magic bytes (hexdump of first 32 bytes).
2. **Hashes** — md5/sha1/sha256 (paste into search / Google / your notes).
3. **Strings** — hunts for flag formats (ascii **and** UTF-16 LE/BE), plus URLs,
   keys, "password/secret/token".
4. **Metadata** — full `exiftool` dump (flags hide in EXIF comments constantly).
5. **Embedded/appended data** — `binwalk` scan + auto-extract, **plus a check for
   data hidden *after* a PNG/JPEG/GIF end marker or inside a ZIP** (a top-5
   forensics trick).
6. **Entropy** — tells you if it's encrypted/compressed/packed (>7.5) vs text.
7. **Type-specific next step** — points you at the right category script.

It **never modifies the input**. Extracted files go to `<file>.observe/`.

## Tuning the flag regex

The default matches `flag{...}`, `ctf{...}`, `BHMEA{...}`. **Before the event,
edit the `FLAG=` line** in `observe.sh` to match the finals' actual flag format —
it makes the strings hunt far more useful.

## Typical flow

```bash
./observe/observe.sh ./chal
# report says: "PNG, 2100 bytes AFTER end marker — likely hidden payload!"
./forensics/scripts/stego.sh ./chal    # follow the hint
```
