---
title: "Reverse Engineering a Crackme: Static, Dynamic, and Patching"
date: "2024-12-04"
excerpt: "A long-form walkthrough: from strings and imports to a patched branch and a clean keygen."
featured: "/images/test2.jpg"
tags:
  - reverse-engineering
  - crackme
  - static-analysis
  - x86
---

## Scope and ethics

This walkthrough uses a toy crackme. Only analyze software you own or have explicit permission to test.

## First look: metadata and hints

Start with cheap wins:

```bash
file crackme
strings -n 6 crackme | head -n 40
readelf -h crackme
readelf -s crackme | head -n 40
checksec --file=crackme
```

If the binary is stripped, symbols are gone but not the logic.

## Build a hypothesis

Look for:

- usage text, error messages, or format strings
- references to strcmp, memcmp, or crypto routines
- suspicious constants (magic numbers, hashes)

A common flow is: parse input -> transform -> compare -> win/fail.

## Static analysis in Ghidra

Open the binary, identify main, and follow calls. The compare is often a short basic block:

```asm
call    strcmp
test    eax, eax
jne     fail
```

The conditional jump is your first target. If you understand the compare, you can build a keygen. If you only want a bypass, a single byte patch can flip the branch.

### Example C source (recovered)

```c
int check(char *input) {
    uint32_t h = 0x1337;
    for (size_t i = 0; i < strlen(input); i++) {
        h = (h << 5) + h + (uint8_t)input[i];
    }
    return h == 0x6f6f6f;
}
```

## Dynamic analysis in gdb

Confirm control flow and watch values:

```bash
gdb -q ./crackme
(gdb) break *0x4011a3
(gdb) run
(gdb) x/16i $rip-8
(gdb) info registers
```

If the compare depends on a hash, dump it before the branch and reproduce it offline.

## Patch the branch

Assume `jne` at offset 0x11a3. Change `0x75` to `0x74` (jne -> je):

```bash
printf '\\x74' | dd of=crackme bs=1 seek=$((0x11a3)) conv=notrunc
```

This bypasses the check for a lab binary. For a real reverse engineering task, prefer understanding and documenting the algorithm.

## Build a keygen

If the hash is simple, you can brute force. If it is linear, you can invert. For the sample hash above, a Python brute force might work for short inputs:

```python
import string

def h(s):
    v = 0x1337
    for ch in s:
        v = (v << 5) + v + ord(ch)
        v &= 0xffffffff
    return v

target = 0x006f6f6f
alphabet = string.ascii_letters + string.digits

for a in alphabet:
    for b in alphabet:
        s = a + b + "X"
        if h(s) == target:
            print(s)
            raise SystemExit
```

## Visual control flow map

```
main
  -> parse_args
  -> read_input
  -> check_key
       -> transform
       -> compare
  -> win
```

## Stripped binaries and position-independent code

When symbols are gone and PIE is enabled, focus on patterns:

- function prologues (push rbp; mov rbp, rsp)
- cross-references to strings
- imports in the PLT/GOT

In gdb, use `info proc mappings` and set breakpoints on PLT stubs like `strcmp@plt`.

## Video reference (placeholder link)

[![Reverse engineering talk](https://img.youtube.com/vi/dQw4w9WgXcQ/0.jpg)](https://www.youtube.com/watch?v=dQw4w9WgXcQ)

## Tooling cheat sheet

| Task | Tool | Why |
| --- | --- | --- |
| Strings and symbols | strings, nm | Quick hints |
| Disassembly | objdump, Ghidra | Control flow |
| Debugging | gdb, lldb | Runtime state |
| Patching | radare2, hexedit | Quick edits |

## Anti-reversing tricks you might see

- Opaque predicates to confuse the graph
- Self-modifying code
- Timing checks that detect single stepping
- Packed sections that require unpacking

## Checklist

- [x] Identify compare branch
- [x] Confirm values at runtime
- [ ] Reconstruct transform function
- [ ] Build a keygen or solver
- [ ] Document the algorithm

## Links

- [Ghidra](https://ghidra-sre.org/)
- [radare2](https://rada.re/n/)
- [GDB manual](https://sourceware.org/gdb/current/onlinedocs/gdb/)
