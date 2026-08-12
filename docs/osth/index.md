---
title: OSTH
---

# OSTH

TH-200 threat-hunting notes. A hunt is a testable hypothesis over known data,
not an unbounded search for “anything suspicious.”

## Hunt worksheet

Write these before querying:

- hypothesis and attacker behavior;
- scoped identities, assets, and UTC window;
- required data sources and coverage gaps;
- observable fields and expected benign patterns;
- query sequence and stopping condition;
- findings, confidence, and detection opportunity.

## Data coverage

```bash
# Inventory Zeek logs and their time span
for f in zeek/*.log; do zeek-cut ts < "$f" 2>/dev/null | sed -n '1p;$p'; done

# Inspect a sample Elastic event for available fields
curl -s 'http://localhost:9200/logs-*/_search?size=1' -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' | jq .
```

Before drawing conclusions, verify clock skew, retention, sensor health,
endpoint coverage, NAT/proxy effects, and whether the field is parsed or raw.

## Windows behavior

```powershell
# Hunt process creation for interpreters and unusual command lines
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object Message -Match 'powershell|rundll32|regsvr32|mshta|wscript|cscript' |
  Select-Object TimeCreated,Id,Message

# Hunt persistence-related task and service events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698,4702} |
  Select-Object TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated,Id,Message
```

Pivot from a suspicious process to parent, user, logon ID, hash, signature,
network destination, sibling hosts, and preceding file creation.

## Linux behavior

```bash
# Hunt execution from temporary or shared-memory paths
journalctl --utc -o short-iso | rg -i '/tmp/|/var/tmp/|/dev/shm/'

# Find recently created executables in common staging paths
find /tmp /var/tmp /dev/shm -type f -perm /111 -printf '%TY-%Tm-%TdT%TTZ %u %m %s %p\n' 2>/dev/null

# Review new users, keys, cron entries, timers, and services
rg -n '^[^#].*' /etc/passwd /etc/cron* 2>/dev/null
find /root/.ssh /home -path '*/.ssh/authorized_keys' -type f -ls 2>/dev/null
systemctl list-timers --all
systemctl list-unit-files --type=service
```

## Network hunting with Zeek

```bash
# Find rare DNS names by query count
zeek-cut query < dns.log | sort | uniq -c | sort -n | head -50

# Find uncommon outbound destinations and ports
zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log |
  sort | uniq -c | sort -n | head -100

# Review downloads and file hashes
zeek-cut ts tx_hosts rx_hosts mime_type sha256 < files.log | head -100

# Identify long or high-volume connections
zeek-cut ts id.orig_h id.resp_h duration orig_bytes resp_bytes < conn.log |
  awk '$4 > 600 || $5 > 10000000 || $6 > 10000000'
```

## PCAP pivots

```bash
# Extract DNS, HTTP, and TLS naming evidence
tshark -r hunt.pcapng -Y dns.flags.response==0 -T fields -e frame.time_epoch -e ip.src -e dns.qry.name
tshark -r hunt.pcapng -Y http.request -T fields -e ip.src -e http.host -e http.request.uri
tshark -r hunt.pcapng -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name

# Measure beacon-like connection intervals for one stream
tshark -r hunt.pcapng -Y 'ip.dst==192.0.2.50 && tcp.flags.syn==1' -T fields -e frame.time_epoch | awk 'NR>1{print $1-p}{p=$1}'
```

Periodicity alone is not malicious. Add process, asset role, domain age,
destination prevalence, transfer volume, and business context.

## Suricata and Sigma

```bash
# Validate local network rules against an offline capture
suricata -T -S rules/local.rules
suricata -r hunt.pcapng -S rules/local.rules -l suricata-out

# Convert a Sigma rule for the target SIEM backend
sigma convert -t lucene -p ecs_windows rules/windows/process_creation.yml

# Validate the local Sigma collection
sigma check rules/
```

## Elastic/KQL patterns

```text
# Suspicious script interpreter with an uncommon parent
event.code:1 and process.name:(powershell.exe or wscript.exe or mshta.exe) and
  not process.parent.name:(explorer.exe or cmd.exe)

# Remote logon followed by privileged activity on the same host
event.code:(4624 or 4672) and winlog.logon.type:(3 or 10)

# Executable written to a user-writable path
event.code:11 and file.path:(C\:\\Users\\* or C\:\\ProgramData\\*) and
  file.extension:(exe or dll or ps1 or js)
```

## Behavior-first hunt ideas

- interpreter spawned by document, browser, archive tool, or service;
- new service/task followed by outbound traffic;
- remote logon followed by privilege assignment and share access;
- credential access followed by ticket or authentication anomalies;
- rare DNS plus periodic low-volume connections;
- execution from temporary paths across more than one host;
- administrative tooling used by a new user, host, or time of day.

## References

- [Official TH-200 syllabus](https://manage.offsec.com/app/uploads/2026/03/TH-200_Syllabus.pdf)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma rule specification](https://sigmahq.io/docs/)
- [Zeek documentation](https://docs.zeek.org/)
