---
title: OSTH
---

# OSTH

## Variables

### Bash

```bash
export CASE="$PWD/osth-case"
export ZEEK="$PWD/zeek"
export PCAP="$PWD/hunt.pcapng"
export IP='192.0.2.50'
export START='2026-01-01 00:00:00 UTC'
export END='2026-01-01 06:00:00 UTC'
mkdir -p "$CASE"/{exports,suricata}
```

### PowerShell

```powershell
$Start = [datetime]'2026-01-01T00:00:00Z'
$End = [datetime]'2026-01-01T06:00:00Z'
```

## Data sources

| Source | Useful fields |
| --- | --- |
| Process events | Host, parent, child, account, command line |
| Authentication | Source, destination, account, logon type |
| DNS | Client, query, answer, timestamp |
| Connections | Endpoints, duration, bytes, state |
| Files | Path, hash, writer, creation time |
| Persistence | Service, task, startup entry, account |

## Scope

Record hypothesis, hosts, identities, UTC window, required telemetry, and stopping condition. Check retention, clock skew, and sensor coverage before interpreting absent events.

```bash
for log in "$ZEEK"/*.log; do
  printf '%s\n' "$log"
  zeek-cut ts < "$log" | sort -n | sed -n '1p;$p'
done
```

## Windows

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
  StartTime=$Start; EndTime=$End
} | Where-Object Message -Match 'powershell|rundll32|regsvr32|mshta|wscript|cscript' |
  Select-Object TimeCreated,Id,MachineName,Message

Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4698,4702
  StartTime=$Start; EndTime=$End
} | Select-Object TimeCreated,Id,MachineName,Message

Get-WinEvent -FilterHashtable @{
  LogName='System'; Id=7045
  StartTime=$Start; EndTime=$End
} | Select-Object TimeCreated,Id,MachineName,Message
```

## Linux

```bash
journalctl --utc --since "$START" --until "$END" -o short-iso |
  rg -i '/tmp/|/var/tmp/|/dev/shm/'
find /tmp /var/tmp /dev/shm -type f -perm /111 -printf '%T@ %u %m %s %p\n' 2>/dev/null | sort -n
systemctl list-timers --all
systemctl list-unit-files --type=service
find /root/.ssh /home -path '*/.ssh/authorized_keys' -type f -ls 2>/dev/null
```

## Zeek

### DNS and connections

```bash
zeek-cut query < "$ZEEK/dns.log" | sort | uniq -c | sort -n | head -50
zeek-cut id.orig_h id.resp_h id.resp_p service < "$ZEEK/conn.log" |
  sort | uniq -c | sort -n | head -100
zeek-cut ts tx_hosts rx_hosts mime_type sha256 < "$ZEEK/files.log" | head -100
```

### Long or large connections

```bash
zeek-cut ts id.orig_h id.resp_h duration orig_bytes resp_bytes < "$ZEEK/conn.log" |
  awk '$4 > 600 || $5 > 10000000 || $6 > 10000000'
```

Thresholds are starting points. Compare with the host role, normal traffic, and endpoint evidence; file hashes depend on enabled Zeek analyzers.

## PCAP

```bash
tshark -r "$PCAP" -Y 'dns.flags.response == 0' -T fields -e frame.time_epoch -e ip.src -e dns.qry.name
tshark -r "$PCAP" -Y http.request -T fields -e ip.src -e http.host -e http.request.uri
tshark -r "$PCAP" -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name
tshark -r "$PCAP" -Y "ip.dst == $IP && tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e frame.time_epoch |
  awk 'NR>1{print $1-p}{p=$1}'
```

Repeated intervals alone do not prove beaconing; inspect retransmissions and correlate with the initiating process.

## Detection

### Suricata

```bash
suricata -T -S rules/local.rules -l "$CASE/suricata"
suricata -r "$PCAP" -S rules/local.rules -l "$CASE/suricata"
```

### Sigma

```bash
sigma convert -t lucene -p ecs_windows rules/windows/process_creation.yml
```

The target backend and processing pipeline must be installed. Validate field mappings against the destination index.

## KQL

```text
winlog.provider_name:"Microsoft-Windows-Sysmon" and event.code:1 and
  process.name:("powershell.exe" or "mshta.exe" or "wscript.exe") and
  not process.parent.name:("explorer.exe" or "cmd.exe")

event.code:4624 and winlog.logon.type:(3 or 10)

winlog.provider_name:"Microsoft-Windows-Sysmon" and event.code:11 and
  file.extension:("exe" or "dll" or "ps1" or "js")
```

Set the time range separately. Correlate results by host, account, process, and time; retain the query and coverage limits with each finding.

## References

- [TH-200 course](https://www.offsec.com/courses/th-200/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma](https://sigmahq.io/docs/)
- [Zeek](https://docs.zeek.org/)
