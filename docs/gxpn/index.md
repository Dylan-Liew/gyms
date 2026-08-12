---
title: GXPN
---

# GXPN

SEC660/GXPN advanced penetration-testing and exploit-development notes for
authorized labs. Separate protocol behavior, memory corruption, mitigations, and
post-exploitation context so a failure in one layer does not contaminate the rest.

## Lab baseline

```bash
# Record target binary, libraries, platform, and mitigations
sha256sum target
file target
ldd target
checksec --file=target

# Capture toolchain versions for reproducibility
python --version
gcc --version | head -1
gdb --version | head -1
```

## Advanced network analysis

```bash
# Enumerate services and capture exact versions
nmap -Pn -sS -sV -O -p- --reason -oA scans/full 192.0.2.50

# Extract TCP conversations and protocol errors from a capture
tshark -r protocol.pcapng -q -z conv,tcp
tshark -r protocol.pcapng -Y 'tcp.analysis.flags' -T fields -e frame.number -e ip.src -e ip.dst -e tcp.analysis.flags

# Replay a saved HTTP request and show byte-level response differences
curl --path-as-is -skv --data-binary @request.bin https://target.example/ -o response.bin
xxd response.bin | head
```

## Scapy packet workbench

```python
# Send a single scoped TCP SYN and inspect the response
from scapy.all import IP, TCP, sr1

target = "192.0.2.50"
packet = IP(dst=target) / TCP(dport=443, flags="S", seq=1000)
answer = sr1(packet, timeout=2, verbose=False)
answer.show() if answer else print("no response")
```

Always constrain interface, destination, protocol, count, timeout, and expected
response. Save generated packets to PCAP before scaling a test.

## Cryptographic implementation checks

```bash
# Enumerate negotiated TLS parameters and certificate details
openssl s_client -connect target.example:443 -servername target.example -showcerts </dev/null
openssl x509 -in certificate.pem -noout -text

# Compare file hashes and HMAC behavior with explicit algorithms
openssl dgst -sha256 message.bin
openssl dgst -sha256 -hmac 'LAB_KEY' message.bin

# Inspect supported TLS ciphers without modifying the service
nmap -Pn -p443 --script ssl-enum-ciphers target.example
```

Ask whether the weakness is in algorithm choice, mode, nonce/IV reuse, randomness,
key derivation, verification order, padding, serialization, or key management.

## Fuzzing preparation

```bash
# Compile an instrumented target with sanitizers
clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer parser.c -o parser-asan

# Minimize and verify a seed corpus
afl-cmin -i seeds -o seeds-min -- ./parser-asan @@
for f in seeds-min/*; do timeout 2 ./parser-asan "$f" >/dev/null; done

# Start a bounded AFL++ campaign
afl-fuzz -i seeds-min -o findings -- ./parser-asan @@
```

One seed should represent one useful grammar feature. Deduplicate crashes by
root cause, not merely by filename or signal.

## Crash triage

```bash
# Reproduce a crash under GDB with deterministic input
gdb -q --args ./target findings/default/crashes/CRASH

# Generate and resolve cyclic offsets
python -c 'from pwn import *; print(cyclic(1000).decode())' > pattern.txt
python -c 'from pwn import *; print(cyclic_find(0x6161616c))'

# Review the crash under AddressSanitizer
ASAN_OPTIONS=abort_on_error=1:symbolize=1 ./parser-asan crash.bin
```

```text
# Inspect fault context and surrounding memory in GDB
info registers
x/20i $pc-20
x/40gx $sp
bt
vmmap
```

## Pwntools harness

```python
# Keep local, remote, and debugger modes in one reproducible harness
from pwn import *

context.binary = elf = ELF("./target", checksec=True)
context.log_level = "info"

def start():
    if args.REMOTE:
        return remote("192.0.2.50", 31337)
    if args.GDB:
        return gdb.debug(elf.path, gdbscript="break main\ncontinue")
    return process(elf.path)

io = start()
io.sendlineafter(b"> ", b"STATUS")
print(io.recvline(timeout=2))
```

## ROP and mitigation work

```bash
# Inventory symbols, relocations, and candidate gadgets
readelf -Ws target | less
readelf -r target
ROPgadget --binary target --only 'pop|ret|leave|syscall'
ropper --file target --search 'pop rdi; ret'

# Inspect library identity and offsets
sha256sum libc.so.6
readelf -Ws libc.so.6 | rg ' system@@| puts@@'
```

Write a chain as explicit machine state: register target, gadget address, side
effects, stack alignment, calling convention, and next instruction. Recalculate
from the exact binary and library supplied by the lab.

## Windows exploit-development checks

```text
# Inspect modules, exception state, stack, and PE mitigations in WinDbg
lm
!analyze -v
.ecxr
r
dd esp L30
!dh MODULE_BASE -f
!exchain
```

Confirm architecture, bad characters, SafeSEH, DEP, ASLR, CFG, and module
stability before selecting a redirection strategy.

## Post-exploitation context

```bash
# Record identity, network context, mounts, capabilities, and namespaces
id
ip -br address
ip route
findmnt
getcap -r / 2>/dev/null
lsns

# Enumerate local services and container context
ss -lntup
systemctl --type=service --state=running
test -f /.dockerenv && echo 'container marker present'
```

Post-exploitation is a decision point, not an automatic collection step. Tie
each action to the lab objective and minimize changes to the target.

## References

- [Official SANS SEC660/GXPN course page](https://www.sans.org/cyber-security-courses/advanced-penetration-testing-exploits-ethical-hacking)
- [pwntools documentation](https://docs.pwntools.com/)
- [AFL++ documentation](https://aflplus.plus/docs/)
