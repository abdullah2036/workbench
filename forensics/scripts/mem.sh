#!/usr/bin/env bash
# mem.sh — memory-dump triage with Volatility 3.
#   ./mem.sh <memory.raw>
# Runs the plugins you almost always want first. vol3 auto-detects the profile.
set -uo pipefail
C_H='\033[1;36m'; C_K='\033[1;33m'; C_0='\033[0m'
sec(){ printf "\n${C_H}==== %s ====${C_0}\n" "$*"; }

F="${1:-}"; [ -f "$F" ] || { echo "usage: $0 <memory.raw>"; exit 1; }
VOL="vol"; command -v vol >/dev/null 2>&1 || VOL="python3 -m volatility3"
OUT="${F}.vol"; mkdir -p "$OUT"

run(){ # run <plugin> [args...]
  local name="$1"; shift
  echo "  \$ $VOL -f <mem> $name $*"
  $VOL -f "$F" "$@" 2>/dev/null | tee "$OUT/${name//./_}.txt" | head -40
}

sec "IMAGE INFO (OS + suggested plugins)"
$VOL -f "$F" windows.info 2>/dev/null | head -25 || echo "(if this errors, it may be a Linux/Mac dump — use linux.* / mac.* plugins)"

sec "PROCESS LIST"; run windows.pslist windows.pslist
sec "PROCESS TREE";  run windows.pstree windows.pstree
sec "COMMAND LINES (what was run — flags love to hide here)"; run windows.cmdline windows.cmdline
sec "NETWORK CONNECTIONS"; run windows.netscan windows.netscan
sec "HASHES (dump SAM)"; run windows.hashdump windows.hashdump

sec "FILE SCAN (grep for interesting names -> $OUT/filescan.txt)"
$VOL -f "$F" windows.filescan 2>/dev/null > "$OUT/filescan.txt"
grep -iE 'flag|secret|password|\.txt|\.png|\.zip|desktop|readme' "$OUT/filescan.txt" | head -30
echo "  (full list: $OUT/filescan.txt — dump one with:)"
echo "    $VOL -f '$F' windows.dumpfiles --viraddr <ADDR>"

sec "NEXT STEPS"
cat <<'EOF'
  Common follow-ups:
    windows.dumpfiles --pid <PID>           # dump a process's files
    windows.memmap --pid <PID> --dump       # dump a process's memory
    windows.registry.printkey --key '...'   # registry values
    windows.clipboard                        # clipboard contents
    windows.screenshots                      # GDI screenshots (great for flags)
  Then run strings on any dump and grep for the flag.
EOF
