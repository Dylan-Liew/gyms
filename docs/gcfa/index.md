---
title: GCFA
---

# GCFA

FOR508/GCFA incident-response, threat-hunting, and digital-forensics notes.
Preserve evidence first, build a defensible timeline, and separate observed
facts from analyst interpretation.

## Case workspace

```bash
# Create a case structure without modifying the evidence source
mkdir -p case/{evidence,working,exports,notes,tools}
date -u +%FT%TZ | tee case/notes/start-time.txt
uname -a | tee case/notes/analyst-system.txt

# Record hashes before analysis and work from a verified copy
sha256sum evidence.E01 | tee case/notes/evidence.sha256
ewfverify evidence.E01
ewfmount evidence.E01 case/evidence/ewf
```

Document the source, acquisition time, time zone, custodian, tool versions,
hashes, and every transformation. Mount forensic images read-only and export
derived artifacts into `working/` rather than writing beside the evidence.

## Rapid triage

Answer these questions before deep analysis:

1. Which hosts and identities are affected?
2. What is the earliest confirmed malicious activity?
3. Which execution, persistence, credential-access, and lateral-movement
   artifacts exist?
4. What data or systems could the actor access?
5. Which evidence would change containment or scoping decisions?

```powershell
# Capture volatile Windows context during an authorized live response
Get-Date -Format o
whoami /all
Get-NetTCPConnection | Sort-Object State,RemoteAddress
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine
Get-CimInstance Win32_Service | Where-Object State -eq Running
Get-ScheduledTask | Where-Object State -ne Disabled
```

Collect volatile data before disk artifacts when shutdown or isolation would
destroy useful state. Record the command, acquisition host, output path, and
hash for each collection.

## Filesystem and NTFS artifacts

```bash
# Inspect the mounted filesystem and produce body-file timeline input
mmls case/evidence/ewf/ewf1
fsstat case/evidence/ewf/ewf1
fls -r -m C: case/evidence/ewf/ewf1 > case/working/bodyfile.txt
mactime -b case/working/bodyfile.txt -d > case/exports/filesystem-timeline.csv

# Recover an item by metadata address without changing the image
icat case/evidence/ewf/ewf1 <metadata-address> > case/exports/recovered.bin
sha256sum case/exports/recovered.bin
```

Correlate `$MFT`, `$UsnJrnl`, `$LogFile`, recycle-bin records, link files,
Jump Lists, Prefetch, and browser/download artifacts. A timestamp is one clue;
confirm it with an independent artifact before assigning intent.

## Windows execution and persistence

Prioritize:

- Prefetch and Amcache for program execution context;
- Shimcache as presence or execution-supporting evidence, not standalone proof;
- UserAssist, BAM/DAM, SRUM, link files, and Jump Lists;
- services, scheduled tasks, WMI subscriptions, startup folders, and Run keys;
- PowerShell history and operational logs;
- antivirus, EDR, and application-specific telemetry.

```powershell
# Export high-value event channels without clearing or altering them
wevtutil epl Security C:\Evidence\Security.evtx
wevtutil epl System C:\Evidence\System.evtx
wevtutil epl Microsoft-Windows-PowerShell/Operational C:\Evidence\PowerShell.evtx
wevtutil epl Microsoft-Windows-TaskScheduler/Operational C:\Evidence\TaskScheduler.evtx
Get-FileHash C:\Evidence\*.evtx -Algorithm SHA256
```

## Registry analysis

Preserve the relevant hives and transaction logs together. Common sources
include `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, and
`UsrClass.dat`.

```bash
# Parse registry hives from a working copy
regripper -r NTUSER.DAT -f ntuser > case/exports/ntuser.txt
regripper -r SYSTEM -f system > case/exports/system.txt
regripper -r SOFTWARE -f software > case/exports/software.txt
```

Use the active control set from `SYSTEM\Select`; do not assume `ControlSet001`.
Correlate persistence values with the referenced file, its metadata, execution
artifacts, and surrounding event records.

## Event-log hunting

```bash
# Convert EVTX records for repeatable filtering
evtx_dump Security.evtx --format jsonl > case/working/security.jsonl

# Review common authentication and process-creation events
jq -c 'select(.Event.System.EventID == 4624 or
              .Event.System.EventID == 4625 or
              .Event.System.EventID == 4688)' \
  case/working/security.jsonl > case/exports/auth-process-events.jsonl
```

Useful event IDs vary by audit policy and Windows version. Build hypotheses
from fields such as logon type, source address, account, process, parent process,
command line, service name, task path, and channel—not from an event ID alone.

## Memory forensics

```bash
# Identify available Volatility 3 symbols and establish process/network context
python3 vol.py -f memory.raw windows.info
python3 vol.py -f memory.raw windows.pslist
python3 vol.py -f memory.raw windows.pstree
python3 vol.py -f memory.raw windows.psscan
python3 vol.py -f memory.raw windows.netscan
python3 vol.py -f memory.raw windows.cmdline
python3 vol.py -f memory.raw windows.dlllist --pid <PID>
python3 vol.py -f memory.raw windows.malfind --pid <PID>
```

Compare active and scanned process views, then investigate unusual ancestry,
session, start time, command line, handles, modules, network endpoints, and
memory regions. `malfind` output is a lead requiring validation, not an automatic
malware verdict.

## Timeline normalization

```bash
# Build a Plaso timeline and export a reviewable subset
log2timeline.py case/working/timeline.plaso case/evidence/ewf/ewf1
psort.py -o l2tcsv -w case/exports/super-timeline.csv case/working/timeline.plaso
```

Keep original timestamps and add a normalized UTC field. Record the host time
zone, daylight-saving rules, clock skew, collection time, and any timestamp
conversion performed by the tool.

Use a compact working timeline:

| Time (UTC) | Host/user | Source | Observed event | Interpretation | Confidence |
| --- | --- | --- | --- | --- | --- |
| `2026-01-01T00:00:00Z` | `WS01/alice` | Security 4688 | Encoded PowerShell launched | Possible execution | Medium |

## Enterprise hunting and scoping

Turn confirmed host artifacts into narrow, explainable hunt logic:

- exact hashes, paths, domains, addresses, certificates, and service names;
- parent-child process relationships and command-line fragments;
- account use by host, source, logon type, and time window;
- persistence mechanisms and remote-execution artifacts;
- evidence of staging, archive creation, cloud access, or exfiltration.

Search for behavior as well as brittle indicators. Record query coverage,
retention gaps, false-positive assumptions, and the last verified clean or
compromised time for every scoped host.

## Findings and reporting

For each finding, preserve:

- the question being answered;
- evidence source and cryptographic hash;
- exact tool and command;
- relevant timestamps and time zone;
- observed facts;
- interpretation and alternatives;
- confidence and limitations;
- containment or collection follow-up.

## References

- [GIAC Certified Forensic Analyst](https://www.giac.org/certifications/certified-forensic-analyst-gcfa/)
- [SANS FOR508](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)
- [Volatility 3 documentation](https://volatility3.readthedocs.io/)
- [The Sleuth Kit documentation](https://www.sleuthkit.org/sleuthkit/docs.php)
