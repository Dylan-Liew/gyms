## DNS — 53

```bash
# Query authoritative name servers.
dig @"$IP" corp.com NS
# Request every record type the server returns.
dig @"$IP" corp.com ANY
# Attempt a DNS zone transfer.
dig @"$IP" corp.com AXFR | tee dns-axfr.txt
# Resolve the target address to a hostname.
dig @"$IP" -x "$IP"
# Locate LDAP domain controllers.
dig @"$IP" _ldap._tcp.dc._msdcs.corp.com SRV
# Enumerate standard DNS records.
dnsrecon -n "$IP" -d corp.com -t std | tee dnsrecon.txt
# Enumerate records and subdomains.
dnsenum --dnsserver "$IP" corp.com | tee dnsenum.txt
# Brute-force subdomains.
gobuster dns -d corp.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o dns-gobuster.txt
```

```text
corp.com.  3600  IN  NS  dc01.corp.com.
corp.com.  3600  IN  A   192.168.50.20
```
