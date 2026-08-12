---
title: OSED
---

# OSED

EXP-301 Windows user-mode exploit development notes for controlled lab binaries.
Reduce uncertainty in this order: reproduce, control, constrain, redirect, then
stabilize.

## Binary triage

```powershell
# Record hashes, signature, architecture, and mitigation context
Get-FileHash .\target.exe -Algorithm SHA256
Get-AuthenticodeSignature .\target.exe
dumpbin /headers .\target.exe | Select-String 'machine|DLL characteristics'
```

```bash
# Inspect PE headers and printable clues from Linux
file target.exe
objdump -x target.exe | less
strings -a -n 6 target.exe | less
```

Record the exact binary hash, OS build, debugger configuration, input vector,
crash conditions, and whether behavior is deterministic.

## WinDbg essentials

```text
# Load symbols, list modules, and inspect mitigations
.symfix
.reload
lm
!dh target.exe -f

# Inspect registers, stack, instructions, and exception state
r
dd esp L20
db esp L80
u eip-20 L40
!analyze -v
.exr -1
.ecxr

# Set execution and access breakpoints
bp module!function
ba w4 ADDRESS
bl
g
```

## Offset and bad-character work

```bash
# Generate and resolve a unique cyclic pattern
python -c 'from pwn import *; print(cyclic(2000).decode())' > pattern.txt
python -c 'from pwn import *; print(cyclic_find(0x61616174))'

# Generate a byte array for controlled comparison
python -c 'import sys; sys.stdout.buffer.write(bytes(range(1,256)))' > bytes.bin
```

Confirm offsets from the crashing register using the target's byte order. Remove
suspected bad characters cumulatively and regenerate the comparison buffer.

## Minimal exploit harness

```python
# Build the input in named regions and verify its exact length
import struct

offset = 0
padding = b"A" * offset
redirect = struct.pack("<I", 0x41414141)
sled = b""
payload = b""
tail = b"C" * 32

buf = padding + redirect + sled + payload + tail
print(f"length={len(buf)}")
open("crash.bin", "wb").write(buf)
```

Keep transport code outside the layout builder. Assert lengths and forbidden
bytes before each run.

## Stack and SEH control

```text
# Inspect the current exception registration chain
!exchain

# Search a loaded module for a candidate instruction sequence
s -b MODULE_START MODULE_END 5f c3

# Verify memory protection and module bounds around an address
!address ADDRESS
lmv m MODULE
```

For SEH, document the offset to next-SEH, offset to handler, chosen redirection,
available landing area, and how the exception is triggered. Recheck SafeSEH,
ASLR, and bad characters for the actual module.

## Egghunters and staged layout

```text
# Search process memory for a repeated marker during debugging
s -a 0 L?80000000 "w00tw00t"

# Inspect the candidate region before transferring control
db ADDRESS L80
u ADDRESS L20
```

Choose a tag absent from the application, place the tagged payload in a stable
buffer, and debug the hunter as a loop rather than treating it as opaque bytes.

## DEP and ROP

```bash
# Inventory imported APIs and candidate ROP instructions
objdump -p target.exe | sed -n '/Import Table/,$p'
ROPgadget --binary target.exe --only 'ret|pop|push|mov|xchg'
```

```text
# Confirm stack alignment and each ROP transition
dd esp L40
u poi(esp) L5
t
r
```

Write the chain as state transitions: desired register value, gadget side
effects, stack consumption, forbidden bytes, and final calling convention.
Validate one gadget at a time.

## ASLR and information disclosure

```text
# Compare module bases across clean process launches
lm

# Inspect PE mitigation flags for the selected module
!dh MODULE_BASE -f
```

Avoid fixed addresses until a non-randomized module or a reproducible disclosure
has been demonstrated in the lab.

## References

- [Official EXP-301 syllabus](https://www.offsec.com/documentation/EXP301-syllabus.pdf)
- [Official OSED FAQ](https://help.offsec.com/hc/en-us/articles/49001669093908-OSED-Windows-User-Mode-Exploit-Development-EXP-301-FAQ)
- [nop-tech OSED notes](https://github.com/nop-tech/OSED)
- [mrtouch93 OSED notes](https://github.com/mrtouch93/OSED-Notes)
