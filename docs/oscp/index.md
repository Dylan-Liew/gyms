---
title: OSCP
---

# OSCP

Compact field notes for the exam. Set the variables once, follow the workflow,
and open a command sheet only when a discovered service or attack path needs it.

## Setup

```bash
export IP='192.168.50.20'
export PORT='80'
export URL="http://$IP:$PORT"
export LHOST="$(ip -4 -o addr show tun0 | awk '{print $4}' | cut -d/ -f1)"
export LPORT='4444'
mkdir -p "$IP"/{scans,loot,files}
cd "$IP"
```

Add credentials only when found:

```bash
export RUSER='pete' PASS='Nexus123!' DOMAIN='corp.com'
```

## Workflow

1. Run [recon](scans/recon.md); record every port, hostname, and technology.
2. Open the matching service sheet and enumerate it fully.
3. Search versions, defaults, exposed files, and reused credentials.
4. Get a shell, stabilize it, and collect local context.
5. Enumerate privilege escalation before trying exploits blindly.
6. Reuse credentials and map trust for lateral movement.
7. Save proof, commands, and screenshots as soon as they work.

## Enumeration

| Ports | Sheet |
| --- | --- |
| 21 | [FTP](scans/ftp.md) |
| 22 | [SSH](scans/ssh.md) |
| 25, 110, 143, 465, 587, 993, 995 | [Mail](scans/mail.md) |
| 53 | [DNS](scans/dns.md) |
| 80, 443 | [HTTP](exploits/http.md) |
| 111, 2049 | [NFS](scans/nfs.md) |
| 139, 445 | [SMB](scans/smb.md) |
| 161/UDP | [SNMP](scans/snmp.md) |
| 1433, 3306, 5432, 6379 | [Databases](scans/sql.md) |
| 3389, 5985, 5986 | [RDP and WinRM](scans/remote.md) |
| 53, 88, 135, 139, 389, 445, 464, 636, 3268 | [Active Directory](exploits/ad.md) |

## Access and escalation

- [Exploit search and compilation](exploits/search.md)
- [Shells and listeners](exploits/shells.md)
- [Linux privilege escalation](exploits/linux.md)
- [Windows privilege escalation](exploits/windows.md)
- [Tunnelling and pivoting](exploits/tunnels.md)
- [Metasploit](exploits/msf.md)

## Loot

- [Passwords and hashes](loot/passwords.md)
- [File transfers](loot/transfers.md)

## Quick ports

`21 FTP · 22 SSH · 25 SMTP · 53 DNS · 80/443 HTTP/S · 88 Kerberos · 110 POP3 · 111/2049 NFS · 135 MSRPC · 139/445 SMB · 143 IMAP · 161/UDP SNMP · 389/636 LDAP/S · 1433 MSSQL · 3306 MySQL · 3389 RDP · 5432 PostgreSQL · 5985/5986 WinRM · 6379 Redis`
