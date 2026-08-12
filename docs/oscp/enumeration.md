## Enumeration

### TCP discovery

```bash
# Scan every TCP port quickly without relying on ping discovery
sudo nmap -Pn -n -p- --min-rate 2000 --open "$IP" -oA scans/tcp-all
```

```bash
# Use a TCP connect scan when SYN scanning is unavailable or tunneled
nmap -Pn -n -sT -p- --open "$IP" -oA scans/tcp-connect
```

```bash
# Extract open ports and run focused scripts and version detection
ports=$(awk -F'Ports: ' '/Ports:/{print $2}' scans/tcp-all.gnmap \
  | tr ',' '\n' | awk -F/ '$2 == "open" {gsub(/ /, "", $1); print $1}' \
  | paste -sd,)
sudo nmap -Pn -n -sC -sV -p "$ports" "$IP" -oA scans/tcp-services
```

```bash
# Review safe scripts, then request exhaustive version probes
nmap --script-help 'safe and discovery' | less
sudo nmap -Pn -n -sV --version-all -p "$ports" "$IP" -oA scans/tcp-versions
```

### UDP discovery

```bash
# Check common UDP services before expanding to a full UDP scan
sudo nmap -Pn -n -sU --top-ports 50 --open "$IP" -oA scans/udp-top
sudo nmap -Pn -n -sU -sV -p 53,69,111,123,137,161,500,4500 "$IP" -oA scans/udp-focus
```

```bash
# Validate likely UDP services with their native protocols
dig @"$IP" version.bind chaos txt
snmpwalk -v2c -c public -t 2 -r 1 "$IP" 1.3.6.1.2.1.1
rpcinfo -p "$IP"
```

### Quick network checks

```bash
# Perform quick connectivity and application-response checks
ping -c 2 "$IP"
traceroute -n "$IP"
nc -nv "$IP" "$PORT"
curl -kI --max-time 10 "$URL"
```

```bash
# Discover live hosts on a directly attached lab network
sudo arp-scan --localnet
sudo nmap -sn -n 192.0.2.0/24 -oA scans/host-discovery
```

```bash
# Inspect IPv6 addressing and scan a confirmed IPv6 target
ip -6 addr
ip -6 route
sudo nmap -6 -Pn -sV '<ipv6-address>'
```

### Build the attack-surface table

| Port | Service | Product/version | Access | Finding | Next action |
| --- | --- | --- | --- | --- | --- |
| 80 | HTTP | Apache/PHP | Public | Redirects to hostname | Add hostname and enumerate vhosts |
| 445 | SMB | Windows | Guest denied | Domain name disclosed | Test known credentials |

```bash
# Convert and search saved scan output without rescanning the target
xsltproc scans/tcp-services.xml -o scans/tcp-services.html
rg -n 'open|Service Info|Subject Alternative Name' scans/
grep '/open/' scans/tcp-all.gnmap
```

### High-value correlations

- A hostname in an HTTP redirect implies DNS or `/etc/hosts` work.
- A certificate may reveal internal names or additional applications.
- SMB, LDAP, Kerberos, and DNS together usually indicate Active Directory.
- RPC and NFS together warrant export and UID-mapping checks.
- Database ports become more valuable after application credentials are found.
- A service bound only to localhost may become reachable after a foothold or
  pivot.

### Minimal service checklist

```text
21       FTP: anonymous login, files, write access
22       SSH: banner, usernames, recovered keys or passwords
25/465   SMTP: users, relay behavior, application mail flow
53       DNS: names, records, zone transfer
80/443   HTTP: hostnames, routes, parameters, files, authentication
111/2049 RPC/NFS: exports, permissions, UID mapping
135/139/445 Windows/SMB: domain, users, shares, permissions
161      SNMP: system, processes, software, network, credentials
389/636  LDAP: naming context, users, groups, ACLs
1433     MSSQL: credentials, roles, linked servers, command execution
3306     MySQL: credentials, databases, file privileges
3389     RDP: domain, valid credentials, restricted administration
5985/5986 WinRM: authenticated PowerShell access
```

### Troubleshooting

- Empty script output does not mean the service has no useful behavior.
- Retry HTTP by IP and hostname, over both HTTP and HTTPS.
- Distinguish connection failure, authentication failure, and authorization
  failure.
- Preserve raw output; condensed notes often omit the clue needed later.
- If a port behaves differently through Nmap, test it with the native client.
- Compare results from Kali with results obtained from a pivot host.
- Confirm whether a timeout is caused by routing, filtering, TLS, or the
  application protocol.
