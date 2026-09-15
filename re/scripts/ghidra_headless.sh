#!/usr/bin/env bash
# ghidra_headless.sh — decompile a binary to C from the command line (no GUI).
# Great for grepping the decompiler output, or feeding clean pseudo-C to AI.
#
#   ./ghidra_headless.sh <binary> [output.c]
#
# Requires Ghidra installed (setup script, or /opt/ghidra). Set GHIDRA_HOME if
# it's somewhere else.
set -uo pipefail

BIN="${1:-}"; [ -f "$BIN" ] || { echo "usage: $0 <binary> [output.c]"; exit 1; }
OUTC="${2:-${BIN}.decompiled.c}"

# locate Ghidra
GHIDRA_HOME="${GHIDRA_HOME:-}"
if [ -z "$GHIDRA_HOME" ]; then
    for d in /opt/ghidra /opt/ghidra* /usr/share/ghidra "$HOME/ghidra"*; do
        [ -f "$d/support/analyzeHeadless" ] && GHIDRA_HOME="$d" && break
    done
fi
HEADLESS=""
if [ -n "$GHIDRA_HOME" ] && [ -f "$GHIDRA_HOME/support/analyzeHeadless" ]; then
    HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
elif command -v analyzeHeadless >/dev/null 2>&1; then
    HEADLESS="analyzeHeadless"
else
    echo "Ghidra not found. Set GHIDRA_HOME=/path/to/ghidra (dir with support/analyzeHeadless)."
    exit 1
fi

# postScript that dumps every function's decompiled C
PROJ="$(mktemp -d)"
SCRIPTDIR="$(mktemp -d)"
cat > "$SCRIPTDIR/DumpDecomp.java" <<'JAVA'
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
public class DumpDecomp extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            DecompileResults r = d.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted())
                println(r.getDecompiledFunction().getC());
        }
    }
}
JAVA

echo "[*] Decompiling $BIN with Ghidra headless (this can take a minute)..."
"$HEADLESS" "$PROJ" tmpproj \
    -import "$BIN" \
    -scriptPath "$SCRIPTDIR" \
    -postScript DumpDecomp.java \
    -deleteProject 2>/dev/null \
    | sed -n '/^\(void\|int\|undefined\|char\|long\|ulong\|uint\|bool\|double\|float\).*(/,/^}/p' \
    > "$OUTC" || true

# fallback: if the sed filter caught nothing, keep raw output
if [ ! -s "$OUTC" ]; then
    "$HEADLESS" "$PROJ" tmpproj2 -import "$BIN" -scriptPath "$SCRIPTDIR" \
        -postScript DumpDecomp.java -deleteProject 2>/dev/null > "$OUTC" || true
fi

rm -rf "$PROJ" "$SCRIPTDIR"
echo "[+] Decompiled C -> $OUTC"
echo "    grep -n 'strcmp\\|memcmp\\|flag\\|password\\|xor' '$OUTC'"
