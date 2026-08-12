---
title: OSDA
---

# OSDA

SOC-200 defensive-analysis notes. Start with a question and a time range, preserve
raw evidence, normalize timestamps to UTC, then pivot across endpoint, identity,
and network data.

## Triage frame

- What alert or observation started the investigation?
- Which host, user, address, process, and time range are in scope?
- What is confirmed, assumed, or still unknown?
- Which data source can falsify the leading explanation?
- Is containment authorized, and what evidence could it destroy?

## Windows event collection

```powershell
# Export high-value logs before filtering them
wevtutil epl Security evidence/Security.evtx
wevtutil epl System evidence/System.evtx
wevtutil epl 'Microsoft-Windows-PowerShell/Operational' evidence/PowerShell.evtx

# Query failed and successful logons in a bounded UTC window
$start = [datetime]'2026-08-05T00:00:00Z'
$ids = 4624,4625,4648,4672
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids; StartTime=$start} |
  Select-Object TimeCreated,Id,MachineName,Message

# Query common Sysmon process, network, and file events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,11} |
  Select-Object TimeCreated,Id,Message
```

High-value correlations include 4624/4625 logons, 4648 explicit credentials,
4672 special privileges, 4688 process creation, 4698 tasks, 7045 services, and
Sysmon process/network/file events.

## Windows host state

```powershell
# Capture process ancestry clues, sockets, services, and scheduled tasks
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine
Get-NetTCPConnection | Sort-Object State,RemoteAddress
Get-CimInstance Win32_Service | Select Name,State,StartMode,StartName,PathName
Get-ScheduledTask | Select TaskPath,TaskName,State

# List recently changed executable and script files
Get-ChildItem C:\Users,C:\ProgramData -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object LastWriteTimeUtc -gt $start |
  Select LastWriteTimeUtc,Length,FullName
```

## Linux evidence

```bash
# Export journal entries for an exact UTC interval
journalctl --utc --since '2026-08-05 00:00:00' --until '2026-08-05 06:00:00' -o short-iso > evidence/journal.log

# Review authentication, privilege, service, and scheduler activity
rg -ni 'failed|accepted|sudo|session opened|useradd|cron|systemd' /var/log/auth.log /var/log/secure evidence/journal.log

# Capture processes, sockets, services, timers, and recent files
ps auxfww
ss -plantue
systemctl --type=service --state=running
systemctl list-timers --all
find /tmp /var/tmp /dev/shm -type f -printf '%TY-%Tm-%TdT%TTZ %u %m %s %p\n' 2>/dev/null | sort
```

## PCAP and network telemetry

```bash
# Summarize conversations, DNS, HTTP, and TLS server names
tshark -r traffic.pcapng -q -z conv,tcp
tshark -r traffic.pcapng -Y dns -T fields -e frame.time_epoch -e ip.src -e dns.qry.name
tshark -r traffic.pcapng -Y http.request -T fields -e ip.src -e http.host -e http.request.uri
tshark -r traffic.pcapng -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name

# Generate Zeek logs and inspect high-signal records
mkdir -p zeek-out
cd zeek-out && zeek -r ../traffic.pcapng
zeek-cut ts id.orig_h id.resp_h query < dns.log | head
```

Look for rare destinations, new domains, periodicity, unusual ports, long
sessions, protocol/port mismatches, and endpoint events that share the same time.

## Suricata and rule validation

```bash
# Run Suricata offline and keep output separate
suricata -r traffic.pcapng -S rules/local.rules -l suricata-out

# Summarize alerts by signature and endpoint pair
jq -r 'select(.event_type=="alert") | [.timestamp,.src_ip,.dest_ip,.alert.signature] | @tsv' suricata-out/eve.json
```

## Elastic/KQL pivots

```text
# Find PowerShell process creation with encoded or hidden arguments
event.code:1 and process.name:powershell.exe and
  process.command_line:(*-enc* or *encodedcommand* or *hidden*)

# Find successful network logons followed by a privileged token
event.code:(4624 or 4672) and host.name:"HOST01"

# Find outbound traffic from uncommon process paths
event.code:3 and process.executable:(C\:\\Users\\* or C\:\\ProgramData\\*)
```

Export the exact query, index pattern, timezone, result count, and representative
events. A screenshot without its query is weak evidence.

## File and indicator handling

```bash
# Hash evidence and identify files without executing them
sha256sum evidence/* > evidence/SHA256SUMS
file suspicious.bin
strings -a -n 6 suspicious.bin | head -200

# Scan a copy with supplied YARA rules
yara -rs rules/index.yar suspicious.bin
```

## References

- [Official SOC-200 syllabus](https://manage.offsec.com/app/uploads/2026/03/SOC-200_Syllabus.pdf)
- [deletehead SOC-200/OSDA notes](https://github.com/deletehead/SOC-200-OSDA)
- [MITRE ATT&CK](https://attack.mitre.org/)
