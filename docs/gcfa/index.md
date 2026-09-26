---
title: GCFA
---

# GCFA

## Variables

### Bash

```bash
export CASE="$PWD/gcfa-case"
export IMAGE="$PWD/evidence.E01"
export MEMORY="$PWD/memory.raw"
export MOUNT="$CASE/evidence/ewf"
export RAW="$MOUNT/ewf1"
mkdir -p "$MOUNT" "$CASE"/{working,exports,notes}
```

### PowerShell

```powershell
$env:CASE_DIR = 'C:\Cases\gcfa'
$Start = [datetime]'2026-01-01T00:00:00Z'
$End = [datetime]'2026-01-01T06:00:00Z'
New-Item -ItemType Directory -Force $env:CASE_DIR | Out-Null
```

## Artifacts

| Source | Use |
| --- | --- |
| `$MFT`, `$UsnJrnl`, `$LogFile` | File metadata and filesystem changes |
| Prefetch | Execution context |
| Amcache, Shimcache | Program inventory and presence; corroborate execution |
| LNK, Jump Lists | File access and user activity |
| Registry hives and transaction logs | Configuration, accounts, persistence |
| EVTX | Authentication, processes, services, tasks |
| Memory | Processes, modules, connections, injected regions |

## Evidence

```bash
date -u +%FT%TZ | tee "$CASE/notes/start-time.txt"
sha256sum "$IMAGE" | tee "$CASE/notes/image.sha256"
ewfverify "$IMAGE"
ewfmount "$IMAGE" "$MOUNT"
```

Preserve all EWF segments and acquisition hashes. Record source, custodian, time zone, and transformations; analyze a verified working copy.

## Filesystem

### Partition

```bash
mmls "$RAW"
export OFFSET='2048' # replace with the filesystem start sector from mmls
fsstat -o "$OFFSET" "$RAW"
fls -r -o "$OFFSET" -m C: "$RAW" > "$CASE/working/bodyfile.txt"
mactime -b "$CASE/working/bodyfile.txt" -z UTC -d > "$CASE/exports/filesystem-timeline.csv"
```

### Recover a file

```bash
export INODE='42' # replace with the metadata address from fls
icat -o "$OFFSET" "$RAW" "$INODE" > "$CASE/exports/recovered.bin"
sha256sum "$CASE/exports/recovered.bin"
```

## Windows

### Volatile state

```powershell
Get-Date -Format o
whoami /all
Get-NetTCPConnection | Sort-Object State,RemoteAddress
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine
Get-CimInstance Win32_Service | Where-Object State -eq Running
Get-ScheduledTask | Where-Object State -ne Disabled
```

### Export logs

```powershell
wevtutil epl Security "$env:CASE_DIR\Security.evtx"
wevtutil epl System "$env:CASE_DIR\System.evtx"
wevtutil epl Microsoft-Windows-PowerShell/Operational "$env:CASE_DIR\PowerShell.evtx"
wevtutil epl Microsoft-Windows-TaskScheduler/Operational "$env:CASE_DIR\TaskScheduler.evtx"
Get-FileHash "$env:CASE_DIR\*.evtx" -Algorithm SHA256
```

## Registry

```bash
rip.pl -r NTUSER.DAT -a > "$CASE/exports/ntuser.txt"
rip.pl -r SYSTEM -a > "$CASE/exports/system.txt"
rip.pl -r SOFTWARE -a > "$CASE/exports/software.txt"
```

Replay transaction logs into a working copy before parsing; RegRipper does not replay them. Resolve the active control set from `SYSTEM\Select`.

## Events

```powershell
Get-WinEvent -FilterHashtable @{
  Path="$env:CASE_DIR\Security.evtx"; Id=4624,4625,4688,4698
  StartTime=$Start; EndTime=$End
} | Select-Object TimeCreated,Id,MachineName,Message |
  Export-Csv "$env:CASE_DIR\security-events.csv" -NoTypeInformation
```

Correlate logon type, account, source address, process, and timestamp. Event availability depends on audit policy and retention.

## Memory

```bash
vol -f "$MEMORY" windows.info
vol -f "$MEMORY" windows.pslist
vol -f "$MEMORY" windows.pstree
vol -f "$MEMORY" windows.psscan
vol -f "$MEMORY" windows.netscan
vol -f "$MEMORY" windows.cmdline
vol -f "$MEMORY" windows.dlllist
vol -f "$MEMORY" windows.malware.malfind
```

Compare active and scanned process views. Validate suspicious regions with ancestry, modules, network activity, and disk evidence.

## Timeline

```bash
log2timeline.py "$CASE/working/timeline.plaso" "$RAW"
psort.py -o l2tcsv -w "$CASE/exports/super-timeline.csv" "$CASE/working/timeline.plaso"
```

Record source time zone, clock skew, tool version, and timestamp conversions. Separate observed events from interpretation.

## Findings

| Field | Record |
| --- | --- |
| Evidence | Source, hash, tool, command |
| Time | Original timestamp, zone, normalized UTC |
| Observation | What the artifact directly establishes |
| Interpretation | Explanation, alternatives, confidence |
| Scope | Affected hosts, identities, coverage gaps |

## References

- [GCFA certification](https://www.giac.org/certifications/certified-forensic-analyst-gcfa/)
- [FOR508 course](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)
- [Volatility 3](https://volatility3.readthedocs.io/en/stable/)
- [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/docs.php)
- [RegRipper](https://github.com/keydet89/RegRipper3.0)
