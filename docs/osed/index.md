---
title: OSED
---

# OSED

## Variables

### Bash

```bash
export BINARY='target.exe'
```

### PowerShell

```powershell
$env:BINARY = '.\target.exe'
```

## Debugger reference

| Command | Purpose |
| --- | --- |
| `r` | Registers |
| `k` | Call stack |
| `lm` | Loaded modules |
| `!analyze -v` | Exception analysis |
| `.ecxr` | Exception context |
| `!address ADDRESS` | Memory-region information |
| `bl` | Breakpoints |

## Binary

```powershell
Get-FileHash $env:BINARY -Algorithm SHA256
Get-AuthenticodeSignature $env:BINARY
dumpbin /headers $env:BINARY | Select-String 'machine|DLL characteristics'
```

```bash
file "$BINARY"
objdump -x "$BINARY" | less
strings -a -n 6 "$BINARY" | less
```

Record the binary hash, OS build, architecture, and debugger version.

## WinDbg

```text
.symfix
.reload
lm
!dh target.exe -f

r
dd esp L20
db esp L80
u eip-20 L40
!analyze -v
.exr -1
.ecxr

bp module!function
ba w4 ADDRESS
bl
g
```

## Input layout

```bash
python -c 'from pwn import *; print(cyclic(2000).decode())' > pattern.txt
python -c 'from pwn import *; print(cyclic_find(0x61616174))'

python -c 'import sys; sys.stdout.buffer.write(bytes(range(1,256)))' > bytes.bin
```

Record byte order and any input transformations.

## Buffer layout

```python
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

Check lengths and byte constraints before each run.

## Stack and SEH

```text
!exchain

s -b MODULE_START MODULE_END 5f c3

!address ADDRESS
lmv m MODULE
```

## Memory markers

```text
s -a 0 L?80000000 "w00tw00t"

db ADDRESS L80
u ADDRESS L20
```

## DEP and ROP

```bash
objdump -p target.exe | sed -n '/Import Table/,$p'
ROPgadget --binary target.exe --only 'ret|pop|push|mov|xchg'
```

```text
dd esp L40
u poi(esp) L5
t
r
```

## ASLR

```text
lm

!dh MODULE_BASE -f
```

Compare module bases across clean process launches.

## References

- [EXP-301 course](https://www.offsec.com/courses/exp-301/)
