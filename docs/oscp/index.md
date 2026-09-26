---
title: OSCP
---

# OSCP

## Variables

```bash
export IP='192.168.50.20'
export PORT='80'
export URL="http://$IP:$PORT"
export LHOST="$(ip -4 -o addr show tun0 | awk '{print $4}' | cut -d/ -f1)"
export LPORT='4444'
export DOMAIN='corp.com'
export RUSER='pete'
export PASS='Nexus123!'
```

## Ports

| Port | Protocol | Service |
| ---: | --- | --- |
| 21 | TCP | FTP |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25, 465, 587 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 69 | UDP | TFTP |
| 80, 443 | TCP | HTTP/S |
| 88 | TCP/UDP | Kerberos |
| 110, 995 | TCP | POP3/S |
| 111, 2049 | TCP/UDP | RPC/NFS |
| 123 | UDP | NTP |
| 135 | TCP | MSRPC |
| 137 | UDP | NetBIOS |
| 139, 445 | TCP | SMB |
| 143, 993 | TCP | IMAP/S |
| 161 | UDP | SNMP |
| 389, 636 | TCP | LDAP/S |
| 464 | TCP/UDP | Kerberos password change |
| 1433 | TCP | MSSQL |
| 3268, 3269 | TCP | Global Catalog |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |
| 5432 | TCP | PostgreSQL |
| 5985, 5986 | TCP | WinRM |
| 6379 | TCP | Redis |

--8<-- "docs/gyms/oscp/scans/recon.md"
--8<-- "docs/gyms/oscp/scans/ftp.md"
--8<-- "docs/gyms/oscp/scans/ssh.md"
--8<-- "docs/gyms/oscp/scans/dns.md"
--8<-- "docs/gyms/oscp/scans/mail.md"
--8<-- "docs/gyms/oscp/scans/smb.md"
--8<-- "docs/gyms/oscp/scans/nfs.md"
--8<-- "docs/gyms/oscp/scans/snmp.md"
--8<-- "docs/gyms/oscp/scans/sql.md"
--8<-- "docs/gyms/oscp/scans/remote.md"

--8<-- "docs/gyms/oscp/exploits/search.md"
--8<-- "docs/gyms/oscp/exploits/shells.md"
--8<-- "docs/gyms/oscp/exploits/http.md"
--8<-- "docs/gyms/oscp/exploits/linux.md"
--8<-- "docs/gyms/oscp/exploits/windows.md"
--8<-- "docs/gyms/oscp/exploits/ad.md"
--8<-- "docs/gyms/oscp/exploits/tunnels.md"
--8<-- "docs/gyms/oscp/exploits/msf.md"

--8<-- "docs/gyms/oscp/loot/passwords.md"
--8<-- "docs/gyms/oscp/loot/transfers.md"
