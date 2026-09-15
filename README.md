# CTF Workbench

A personal, offline-first CTF toolkit built for the **Black Hat MEA finals**.
The philosophy: **don't rebuild what Kali already does well — automate the glue,
the triage, and the tedious loops so you go from "weird file" to "iterating on a
solve" in seconds.**

> You are the team's tooling + first-pass-triage person. Every challenge starts
> here: run `observe`, read the report, route it to the right category folder.

---

## The golden loop

CTF is not about intelligence, it's about **iteration speed**:

```
observe  →  hypothesize  →  test  →  observe again
```

If a step in that loop is slow or manual, that's the thing to automate. Every
tool here exists to shorten one turn of that loop.

## How to use AI without it running in circles

1. Run `observe`/`triage` first. Get **structured facts**.
2. Paste the *facts* into the AI and ask for **candidate techniques**, not a full
   solve. ("Given this entropy, these strings, this file type — what are the top
   5 things this could be?")
3. Keep `notes/<challenge>.md` updated with what you **already tried** so the AI
   (and your teammates) stop repeating dead ends.
4. Use AI to write throwaway scripts fast — that's where it's genuinely strong.

---

## Layout

| Folder | What's in it |
|---|---|
| [`setup/`](setup/) | One script to install everything Kali is missing |
| [`observe/`](observe/) | `observe.sh` — universal first-look triage for ANY file |
| [`crypto/`](crypto/) | RSA multi-attack, XOR tools, oracle template + references |
| [`forensics/`](forensics/) | Auto-triage, pcap/USB extraction, stego battery, memory + references |
| [`re/`](re/) | angr symbolic-execution solver, Ghidra headless, gdb setup + references |
| [`web/`](web/) | OOB collector server, CSS-injection exfil generator + references |
| [`misc/`](misc/) | Encoding/format helpers, wordlists notes + references |
| [`notes/`](notes/) | Per-challenge triage notes + shared "already tried" log |

Each category has a **`scripts/`** folder (things you run) and a
**`references/`** folder (curated online tools + how to use them, for when a
web tool beats a local one — and for when you're allowed internet at the venue).

---

## First-time setup (on the Kali VM)

```bash
git clone https://github.com/abdullah2036/workbench.git
cd workbench
chmod +x setup/install-kali-extras.sh
./setup/install-kali-extras.sh        # installs the gaps: sage, angr, volatility3, stegseek, etc.
chmod +x observe/observe.sh forensics/scripts/*.sh re/scripts/*.sh
```

## Quick start on a new challenge

```bash
./observe/observe.sh ./challenge_file        # what am I even looking at?
# then jump to the right category:
python3 crypto/scripts/rsa.py --help
./forensics/scripts/triage.sh ./image.png
python3 re/scripts/angr_solver.py ./crackme
python3 web/scripts/collector.py             # start the callback listener
```

---

## ⚠️ Venue rules

Confirm whether the finals allow internet / external AI. If **offline**, the
`references/` online tools won't be reachable — lean on the local scripts and
pull offline copies of the cheat-sheets you care about ahead of time. Everything
in `scripts/` is built to work with no internet.
