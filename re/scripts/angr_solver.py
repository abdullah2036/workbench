#!/usr/bin/env python3
"""
angr_solver.py — solve crackmes with symbolic execution instead of manual RE.

The idea: instead of reversing a flag-checking function by hand, let angr explore
all paths and find the input that reaches "Correct!" (and avoids "Wrong!").
This is the single biggest force-multiplier a programmer has in RE.

Common usages
-------------
  # Auto: find the path that prints the success string, avoid the failure string
  python3 angr_solver.py ./crackme --find "Correct" --avoid "Wrong"

  # Give the exact addresses instead (from Ghidra/objdump) — more reliable
  python3 angr_solver.py ./crackme --find 0x401337 --avoid 0x401300

  # Flag is read from stdin, known length
  python3 angr_solver.py ./crackme --find "Correct" --stdin 32

  # Flag is argv[1] of known length
  python3 angr_solver.py ./crackme --find "Correct" --arg 24

Install: pip install angr   (done by setup/install-kali-extras.sh)

When angr struggles (heavy loops, hashing, huge state space): fall back to
Ghidra to read the check, or z3 to model just the constraint. Symbolic execution
is a tool, not magic — but on typical crackmes it wins in seconds.
"""
import argparse, sys, logging

def main():
    ap = argparse.ArgumentParser(description="angr crackme solver")
    ap.add_argument("binary")
    ap.add_argument("--find", required=True,
                    help="success: a string it prints, or a 0x address to reach")
    ap.add_argument("--avoid", default=None,
                    help="failure: a string, or 0x address(es) comma-separated")
    ap.add_argument("--stdin", type=int, metavar="N",
                    help="model N symbolic bytes on stdin")
    ap.add_argument("--arg", type=int, metavar="N",
                    help="model argv[1] as N symbolic bytes")
    ap.add_argument("--base", default=None, help="load base addr (e.g. 0x400000)")
    ap.add_argument("--charset", default="printable",
                    choices=["printable", "any", "alnum"],
                    help="constrain symbolic input bytes")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    try:
        import angr, claripy
    except Exception:
        sys.exit("angr not installed. Run setup/install-kali-extras.sh or: pip install angr")

    if not a.verbose:
        for n in ("angr", "cle", "pyvex", "claripy"):
            logging.getLogger(n).setLevel(logging.ERROR)

    load_opts = {}
    if a.base:
        load_opts = {"main_opts": {"base_addr": int(a.base, 16)}}
    proj = angr.Project(a.binary, auto_load_libs=False, **load_opts)

    # ---- build state with symbolic input ----
    sym_bytes = None
    if a.arg is not None:
        flag = claripy.BVS("arg", a.arg * 8)
        sym_bytes = flag
        state = proj.factory.full_init_state(
            args=[a.binary, flag], add_options=angr.options.unicorn)
    elif a.stdin is not None:
        flag = claripy.BVS("stdin", a.stdin * 8)
        sym_bytes = flag
        state = proj.factory.full_init_state(
            stdin=flag, add_options=angr.options.unicorn)
    else:
        # default: symbolic stdin of 64 bytes
        flag = claripy.BVS("stdin", 64 * 8)
        sym_bytes = flag
        state = proj.factory.full_init_state(
            stdin=flag, add_options=angr.options.unicorn)

    # constrain each byte to a sensible charset (speeds solving, avoids junk)
    if sym_bytes is not None and a.charset != "any":
        for i in range(len(sym_bytes) // 8):
            byte = sym_bytes.get_byte(i)
            if a.charset == "printable":
                state.solver.add(byte >= 0x20, byte <= 0x7e)
            elif a.charset == "alnum":
                state.solver.add(claripy.Or(
                    claripy.And(byte >= 0x30, byte <= 0x39),
                    claripy.And(byte >= 0x41, byte <= 0x5a),
                    claripy.And(byte >= 0x61, byte <= 0x7a)))

    simgr = proj.factory.simulation_manager(state)

    def as_target(spec):
        return int(spec, 16) if spec.lower().startswith("0x") else spec.encode()

    find = as_target(a.find)
    avoid = None
    if a.avoid:
        avoid = [as_target(x) for x in a.avoid.split(",")]

    # If find/avoid are strings, match on stdout; if ints, on address.
    if isinstance(find, bytes):
        def is_success(st): return find in st.posix.dumps(1)
        def is_fail(st):
            return avoid and any(x in st.posix.dumps(1) for x in avoid if isinstance(x, bytes))
        print(f"[*] exploring for stdout containing {find!r} ...")
        simgr.explore(find=is_success, avoid=is_fail if avoid else None)
    else:
        print(f"[*] exploring for address {hex(find)} ...")
        simgr.explore(find=find, avoid=avoid)

    if simgr.found:
        found = simgr.found[0]
        sol = found.solver.eval(sym_bytes, cast_to=bytes)
        # also try to read whatever it dumped from stdin/argv
        print("\n[+] SOLUTION FOUND")
        print(f"    bytes : {sol!r}")
        try:
            print(f"    text  : {sol.rstrip(chr(0).encode()).decode('latin-1')}")
        except Exception:
            pass
        out = found.posix.dumps(1)
        if out:
            print(f"    stdout: {out[:200]!r}")
    else:
        print("\n[-] No satisfying path found.")
        print("    Try: give exact --find/--avoid addresses from Ghidra,")
        print("         adjust --stdin/--arg length, or --charset any.")
        print("    Deadended:", len(simgr.deadended), "Active:", len(simgr.active))

if __name__ == "__main__":
    main()
