# re/references

## Decompilers / disassemblers

- **Ghidra** — https://ghidra-sre.org/ — free, excellent decompiler. GUI for
  reading; `ghidra_headless.sh` for dumping C to grep or feed to AI.
- **Dogbolt (Decompiler Explorer)** — https://dogbolt.org/ — upload a binary, see
  Ghidra + Hex-Rays + Binary Ninja + angr decompilation **side by side** in the
  browser. Fastest way to get readable pseudo-C without local setup. *(online)*
- **Compiler Explorer (godbolt)** — https://godbolt.org/ — the reverse: write C,
  see the asm. Great for "what does this asm pattern mean?".
- **radare2 / rizin + Cutter** — https://cutter.re/ — free GUI over r2.

## Symbolic / automated

- **angr** — https://angr.io/ — `angr_solver.py` wraps it. Docs + examples:
  https://docs.angr.io/ and https://github.com/angr/angr-doc/tree/master/examples
- **z3** — https://github.com/Z3Prover/z3 — model a single check as constraints
  and solve. Perfect when angr's state space is too big but the logic is simple.

## Dynamic analysis (gdb)

Install pwndbg (setup script). Quick reference:

```
gdb ./binary
  b *0x401234        # breakpoint at address
  b main             # breakpoint at symbol
  run   / r          # start
  c                  # continue
  ni / si            # step over / into (one instruction)
  x/20i $rip         # show next 20 instructions
  x/s  0x4040a0      # read string at address
  x/8xg $rsp         # 8 quad-words at stack pointer
  info registers     # all registers
  p $rax             # print a register
  set $rax = 1       # change a register
  telescope $rsp     # (pwndbg) smart stack view
  vmmap              # (pwndbg) memory map
```

- **strace / ltrace** — `ltrace ./bin` shows libc calls (`strcmp`, `memcmp` with
  the compared strings — sometimes that's the whole flag).

## Language-specific

| Target | Tool |
|---|---|
| .NET (C#) | **dnSpy** / **ILSpy** / **dotPeek** — near-perfect decompile + debug |
| Java `.class`/`.jar` | **JD-GUI**, **CFR**, **procyon** |
| Python `.pyc` | **decompyle3**, **uncompyle6**, **pycdc** |
| PyInstaller `.exe` | **pyinstxtractor** then decompile the `.pyc` |
| Go binary | `GoReSym`, IDA Go plugin (Go strips symbols oddly) |
| packed (UPX) | `upx -d binary` first |
| WASM | `wasm2wat`, `wabt`, https://webassembly.github.io/wabt/demo/wasm2wat/ |

## Workflow

1. `observe.sh` → confirm it's a binary, note arch/type.
2. `strings` + `ltrace` for the cheap win (hardcoded compare).
3. `ghidra_headless.sh` or Dogbolt → read the check function.
4. If it's an input→check crackme: `angr_solver.py`.
5. If angr chokes: model the specific constraint in z3, or read + solve by hand.
