---
title: OSIR
---

# OSIR

IR-200 incident-response notes. Preserve what is volatile, document every action,
and make containment decisions with the incident lead: a fast change that erases
evidence can make recovery slower.

## Case initialization

```bash
# Create a predictable case layout and timestamp the start in UTC
export CASE=IR-2026-001
mkdir -p "$CASE"/{notes,raw,processed,exports,hashes}
date -u +'%Y-%m-%dT%H:%M:%SZ' | tee "$CASE/notes/started.txt"

# Record responder tooling versions
uname -a > "$CASE/notes/responder-host.txt"
sha256sum tools/* > "$CASE/hashes/tools.sha256"
```

Record who requested the response, authority, scope, systems, time window,
business owner, evidence location, communication channel, and decision log.

## Order of volatility

Collect only what is necessary and authorized, usually:

1. system time and logged-on users;
2. processes, command lines, handles, and memory;
3. network connections, routes, ARP, and DNS cache;
4. temporary files and runtime state;
5. persistent disk, centralized logs, and backups.

## Windows volatile triage

```powershell
# Capture time, identity, sessions, processes, sockets, routes, and DNS cache
Get-Date -Format o
whoami /all
quser
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine
Get-NetTCPConnection
Get-NetRoute
Get-DnsClientCache

# Export core event logs without clearing them
wevtutil epl Security C:\IR\Security.evtx
wevtutil epl System C:\IR\System.evtx
wevtutil epl 'Microsoft-Windows-Sysmon/Operational' C:\IR\Sysmon.evtx

# Hash collected artifacts
Get-FileHash C:\IR\* -Algorithm SHA256
```

## Linux volatile triage

```bash
# Capture host, session, process, network, and loaded-module state
date -u +'%Y-%m-%dT%H:%M:%SZ'
hostnamectl
w
last -Faiwx | head -100
ps auxfww
ss -plantue
ip route
ip neigh
lsmod

# Export a bounded journal and hash the result
journalctl --utc --since '2026-08-05 00:00:00' -o short-iso > raw/journal.log
sha256sum raw/journal.log
```

## Disk acquisition and verification

```bash
# Identify devices before imaging and capture source metadata
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,SERIAL,MODEL
sudo blockdev --getro /dev/sdX

# Acquire to an approved destination while hashing the image
sudo dcfldd if=/dev/sdX of=/evidence/host01.img hash=sha256 hashlog=/evidence/host01.sha256

# Verify a working copy before analysis
sha256sum /evidence/host01.img
```

Never infer a device name. Confirm serial, size, write protection, destination
capacity, and chain-of-custody fields before acquisition.

## Timeline construction

```bash
# Build a Plaso timeline from a verified image
log2timeline.py processed/host01.plaso raw/host01.img

# Export a bounded, normalized timeline
psort.py -o l2tcsv -w exports/timeline.csv processed/host01.plaso 'date > TIMESTAMP("2026-08-05 00:00:00") AND date < TIMESTAMP("2026-08-06 00:00:00")'

# Sort simple filesystem timestamps in UTC for a fast secondary view
find mounted-image -xdev -printf '%T@ %TY-%Tm-%TdT%TTZ %u %m %s %p\n' 2>/dev/null | sort -n
```

Correlate filesystem, authentication, process, network, identity-provider, EDR,
mail, proxy, and cloud events on a single UTC timeline.

## Memory analysis

```bash
# Identify the Windows image and enumerate process/network artifacts
python vol.py -f raw/memory.raw windows.info
python vol.py -f raw/memory.raw windows.pslist
python vol.py -f raw/memory.raw windows.pstree
python vol.py -f raw/memory.raw windows.netscan
python vol.py -f raw/memory.raw windows.cmdline

# Scan process memory with supplied YARA rules
python vol.py -f raw/memory.raw windows.vadyarascan --yara-file rules/triage.yar
```

## Indicator extraction

```bash
# Identify, hash, and extract strings from a copied artifact
file processed/suspicious.bin
sha256sum processed/suspicious.bin
strings -a -n 6 processed/suspicious.bin > exports/suspicious.strings

# Run YARA recursively and preserve match metadata
yara -rs rules/index.yar processed/ | tee exports/yara-matches.txt
```

Tag each indicator as observed, derived, reported, or hypothesized. Record first
seen, last seen, source, confidence, scope, and known benign explanations.

## Containment and recovery gates

After explicit authorization, choose the narrowest reversible control: isolate a
host, disable a token, block an indicator, stop a service, or segment a subnet.
Before acting, record expected benefit, operational impact, evidence risk,
rollback owner, and validation test.

```powershell
# Capture current firewall state before an approved isolation change
Get-NetFirewallProfile
Get-NetFirewallRule -Enabled True | Export-Clixml C:\IR\firewall-before.xml
```

Recovery is not merely “service is up.” Validate patched root cause, clean
credentials, persistence removal, restored monitoring, business functionality,
and an agreed heightened-monitoring window.

## References

- [Official IR-200 syllabus](https://manage.offsec.com/app/uploads/2026/03/IR-200_Syllabus.pdf)
- [NIST SP 800-61 incident response guidance](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Volatility 3 documentation](https://volatility3.readthedocs.io/)
