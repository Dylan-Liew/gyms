---
title: OSIR
---

# OSIR

## Variables

### Bash

```bash
export CASE="$PWD/osir-case"
export IMAGE="$CASE/raw/host01.img"
export MEMORY="$CASE/raw/memory.raw"
export START='2026-01-01 00:00:00 UTC'
export END='2026-01-01 06:00:00 UTC'
mkdir -p "$CASE"/{notes,raw,processed,exports,hashes}
```

### PowerShell

```powershell
$env:CASE_DIR = 'C:\Cases\osir'
New-Item -ItemType Directory -Force $env:CASE_DIR | Out-Null
```

## Collection order

| Order | Evidence |
| --- | --- |
| 1 | Clock, logged-on users, processes, memory |
| 2 | Connections, routes, neighbors, DNS cache |
| 3 | Temporary files and runtime state |
| 4 | Disk, local logs, configuration |
| 5 | Central logs, cloud records, backups |

Record source, collector, collection time, time zone, hashes, and custody transfers.

## Case

```bash
date -u +'%Y-%m-%dT%H:%M:%SZ' | tee "$CASE/notes/started.txt"
uname -a > "$CASE/notes/responder-host.txt"
```

## Windows

### Volatile state

```powershell
Get-Date -Format o
whoami /all
quser
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine
Get-NetTCPConnection
Get-NetRoute
Get-DnsClientCache
```

### Logs

```powershell
wevtutil epl Security "$env:CASE_DIR\Security.evtx"
wevtutil epl System "$env:CASE_DIR\System.evtx"
wevtutil epl Microsoft-Windows-Sysmon/Operational "$env:CASE_DIR\Sysmon.evtx"
Get-FileHash "$env:CASE_DIR\*.evtx" -Algorithm SHA256
```

## Linux

```bash
date -u +'%Y-%m-%dT%H:%M:%SZ'
hostnamectl
w
last -Faiwx | head -100
ps auxfww
ss -plantue
ip route
ip neigh
lsmod
journalctl --utc --since "$START" --until "$END" -o short-iso > "$CASE/raw/journal.log"
sha256sum "$CASE/raw/journal.log"
```

## Disk

```bash
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,SERIAL,MODEL
sudo blockdev --getro /dev/sdX
sudo dcfldd if=/dev/sdX of="$IMAGE" hash=sha256 hashlog="$CASE/hashes/host01.sha256"
sha256sum "$IMAGE"
```

Replace `/dev/sdX` only after checking source serial, write protection, destination capacity, and custody details. The output image must be a new file.

## Timeline

```bash
log2timeline.py "$CASE/processed/host01.plaso" "$IMAGE"
psort.py -o l2tcsv -w "$CASE/exports/timeline.csv" "$CASE/processed/host01.plaso"
```

Preserve original timestamps and record time zone and clock skew when correlating sources.

## Memory

```bash
vol -f "$MEMORY" windows.info
vol -f "$MEMORY" windows.pslist
vol -f "$MEMORY" windows.pstree
vol -f "$MEMORY" windows.netscan
vol -f "$MEMORY" windows.cmdline
vol -f "$MEMORY" windows.vadyarascan --yara-file rules/triage.yar
```

Memory YARA scanning requires `yara-python` or `yara-x` in the Volatility environment.

## Indicators

```bash
file "$CASE/processed/suspicious.bin"
sha256sum "$CASE/processed/suspicious.bin"
strings -a -n 6 "$CASE/processed/suspicious.bin" > "$CASE/exports/suspicious.strings"
yara -rs rules/index.yar "$CASE/processed" | tee "$CASE/exports/yara-matches.txt"
```

Record first seen, last seen, source, confidence, affected hosts, and benign explanations.

## Recovery

```powershell
Get-NetFirewallProfile
Get-NetFirewallRule -Enabled True | Export-Clixml "$env:CASE_DIR\firewall-before.xml"
```

Confirm root-cause remediation, credential rotation, persistence removal, service health, and restored monitoring. Record each containment change and its rollback.

## References

- [IR-200 course](https://www.offsec.com/courses/ir-200/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Volatility 3](https://volatility3.readthedocs.io/en/stable/)
