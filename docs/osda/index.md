---
title: OSDA
---

# OSDA

## Variables

### Bash

```bash
export CASE="$PWD/osda-case"
export PCAP="$PWD/traffic.pcapng"
export SAMPLE="$PWD/suspicious.bin"
export START='2026-01-01 00:00:00 UTC'
export END='2026-01-01 06:00:00 UTC'
mkdir -p "$CASE"/{raw,exports,zeek,suricata}
```

### PowerShell

```powershell
$env:CASE_DIR = 'C:\Cases\osda'
$Start = [datetime]'2026-01-01T00:00:00Z'
$End = [datetime]'2026-01-01T06:00:00Z'
New-Item -ItemType Directory -Force $env:CASE_DIR | Out-Null
```

## Event IDs

| Channel | ID | Event |
| --- | --- | --- |
| Security | 4624 / 4625 | Successful / failed logon |
| Security | 4648 / 4672 | Explicit credentials / special privileges |
| Security | 4688 | Process creation |
| Security | 4698 / 4702 | Scheduled task created / updated |
| System | 7045 | Service installed |
| Sysmon | 1 / 3 / 11 | Process / network / file creation |

## Windows

### Logs

```powershell
wevtutil epl Security "$env:CASE_DIR\Security.evtx"
wevtutil epl System "$env:CASE_DIR\System.evtx"
wevtutil epl Microsoft-Windows-PowerShell/Operational "$env:CASE_DIR\PowerShell.evtx"

Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4624,4625,4648,4672,4688
  StartTime=$Start; EndTime=$End
} | Select-Object TimeCreated,Id,MachineName,Message

Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,11
  StartTime=$Start; EndTime=$End
} | Select-Object TimeCreated,Id,MachineName,Message
```

### Host

```powershell
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine
Get-NetTCPConnection | Sort-Object State,RemoteAddress
Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,PathName
Get-ScheduledTask | Select-Object TaskPath,TaskName,State
Get-ChildItem C:\Users,C:\ProgramData -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTimeUtc -ge $Start.ToUniversalTime() -and $_.LastWriteTimeUtc -le $End.ToUniversalTime() } |
  Select-Object LastWriteTimeUtc,Length,FullName
```

## Linux

```bash
journalctl --utc --since "$START" --until "$END" -o short-iso > "$CASE/raw/journal.log"
rg -ni 'failed|accepted|sudo|session opened|useradd|cron|systemd' "$CASE/raw/journal.log"
ps auxfww
ss -plantue
systemctl --type=service --state=running
systemctl list-timers --all
```

## Network

### PCAP

```bash
tshark -r "$PCAP" -q -z conv,tcp
tshark -r "$PCAP" -Y dns -T fields -e frame.time_epoch -e ip.src -e dns.qry.name
tshark -r "$PCAP" -Y http.request -T fields -e ip.src -e http.host -e http.request.uri
tshark -r "$PCAP" -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name
```

### Zeek

```bash
(cd "$CASE/zeek" && zeek -r "$PCAP")
zeek-cut ts id.orig_h id.resp_h query < "$CASE/zeek/dns.log" | head
```

### Suricata

```bash
suricata -r "$PCAP" -S rules/local.rules -l "$CASE/suricata"
jq -r 'select(.event_type=="alert") | [.timestamp,.src_ip,.dest_ip,.alert.signature] | @tsv' "$CASE/suricata/eve.json"
```

## KQL

```text
event.code:4688 and process.name:"powershell.exe"
event.code:(4624 or 4672) and host.name:"HOST01"
event.code:3 and process.name:("powershell.exe" or "wscript.exe" or "mshta.exe")
```

Set the time range in the SIEM. Correlate by host, account, logon ID, and timestamp; a filter alone does not establish an event sequence.

## Files

```bash
sha256sum "$SAMPLE"
file "$SAMPLE"
strings -a -n 6 "$SAMPLE" | head -200
yara -rs rules/index.yar "$SAMPLE"
find "$CASE/raw" -type f -exec sha256sum {} + > "$CASE/exports/SHA256SUMS"
```

## References

- [SOC-200 course](https://www.offsec.com/courses/soc-200/)
- [Windows event queries](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)
- [Suricata command options](https://docs.suricata.io/en/latest/command-line-options.html)
