#!/usr/bin/env bash
# pcap.sh — network capture triage with tshark.
#   ./pcap.sh <capture.pcap[ng]>
# Gives you the shape of the traffic and auto-extracts the usual loot.
set -uo pipefail
C_H='\033[1;36m'; C_K='\033[1;33m'; C_0='\033[0m'
sec(){ printf "\n${C_H}==== %s ====${C_0}\n" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

F="${1:-}"; [ -f "$F" ] || { echo "usage: $0 <capture.pcap>"; exit 1; }
have tshark || { echo "tshark not installed (apt install tshark)"; exit 1; }
OUT="${F}.pcap_out"; mkdir -p "$OUT"

sec "PROTOCOL HIERARCHY (what's in here?)"
tshark -r "$F" -q -z io,phs 2>/dev/null | head -40

sec "CONVERSATIONS (top talkers)"
tshark -r "$F" -q -z conv,tcp 2>/dev/null | head -20

sec "DNS QUERIES (exfil often hides here)"
tshark -r "$F" -Y dns.flags.response==0 -T fields -e dns.qry.name 2>/dev/null | sort -u | head -40

sec "HTTP REQUESTS"
tshark -r "$F" -Y http.request -T fields -e http.request.method -e http.host -e http.request.uri 2>/dev/null | head -40

sec "CLEARTEXT CREDS (http/ftp/telnet basic)"
tshark -r "$F" -Y 'http.authorization || ftp.request.command=="USER" || ftp.request.command=="PASS" || telnet' \
    -T fields -e frame.number -e http.authorization -e ftp.request.command -e ftp.request.arg 2>/dev/null | head -30

sec "FLAG HUNT across all packet bytes"
tshark -r "$F" -T fields -e data.text -e text 2>/dev/null | grep -aoiE '(flag|ctf|BHMEA)\{[^}]*\}' | sort -u | head
strings "$F" | grep -aoiE '(flag|ctf|BHMEA)\{[^}]*\}' | sort -u | head

sec "EXPORT OBJECTS (files transferred) -> $OUT/objects_*"
for proto in http smb tftp ftp-data imf; do
    tshark -r "$F" --export-objects "$proto,$OUT/objects_$proto" >/dev/null 2>&1 || true
done
find "$OUT" -type f 2>/dev/null | sed 's/^/  /' | head -30

sec "USB TRAFFIC?"
if tshark -r "$F" -Y 'usb.capdata' -T fields -e usb.capdata 2>/dev/null | grep -q .; then
    echo "  USB capdata present -> decode keystrokes with:"
    echo "    python3 usb_hid.py '$F'"
fi

sec "DONE"
echo "Exported files: $OUT/   |  Open interactively: wireshark '$F'"
echo "Tip: in Wireshark, right-click a packet -> Follow -> TCP Stream."
