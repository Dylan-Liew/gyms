## Services

Use this page after port discovery. Begin without credentials, repeat with every
credential set recovered later, and record both readable and writable resources.

### FTP — 21

```bash
ftp "$IP"
nmap -Pn -p21 --script ftp-anon,ftp-syst "$IP"
curl -v "ftp://anonymous:anonymous@example.com@$IP/"
```

Check anonymous access, directory listings, downloadable files, and whether an
uploaded file becomes reachable through another service such as HTTP.

```text
binary
passive
ls -la
get <remote-file> <local-file>
put <local-file> <remote-file>
```

```text
Name: anonymous
Password: anonymous@example.com
```

### SSH — 22

```bash
ssh -v "$USER@$IP"
ssh -i id_rsa "$USER@$IP"
ssh-keygen -y -f id_rsa
nmap -Pn -p22 --script ssh-auth-methods,ssh2-enum-algos,ssh-hostkey "$IP"
```

SSH usually becomes useful after discovering a username, password, or private
key. Inspect key permissions and convert encrypted keys for offline recovery.

```bash
chmod 600 id_rsa
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

### DNS — 53

```bash
dig @"$IP" -x "$IP"
dig @"$IP" example.local ANY
dig @"$IP" example.local AXFR
dig @"$IP" host.example.local A
dig @"$IP" example.local NS
dig @"$IP" _ldap._tcp.dc._msdcs.example.local SRV
dnsrecon -n "$IP" -d example.local -t std
```

Add confirmed names to `/etc/hosts`; do not rely on the target IP alone when
enumerating web applications.

### SMTP — 25, 465, 587

```bash
nc -nv "$IP" 25
smtp-user-enum -M VRFY -U users.txt -t "$IP"
nmap -Pn -p25 --script smtp-commands,smtp-enum-users "$IP"
swaks --server "$IP" --quit-after EHLO
```

Manual SMTP dialogue:

```text
EHLO example.local
VRFY username
MAIL FROM:<sender@example.local>
RCPT TO:<recipient@example.local>
```

Useful findings include valid usernames, internal domains, application-generated
mail, and credentials stored in mail configuration.

### SMB — 139, 445

#### First pass

```bash
nmap -Pn -p139,445 --script smb-protocols,smb2-security-mode,smb2-time "$IP"
smbclient -N -L "//$IP"
netexec smb "$IP" -u '' -p '' --shares
rpcclient -N -U '' "$IP"
enum4linux-ng -A "$IP"
```

#### With credentials

```bash
smbclient -L "//$IP" -U "$DOMAIN/$USER%$PASS"
smbclient "//$IP/share" -U "$DOMAIN/$USER%$PASS"
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --shares
smbmap -H "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS"
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --users
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --sessions
```

Inside `smbclient`:

```text
recurse ON
prompt OFF
ls
mget *
put test.txt
```

Distinguish share access from filesystem permissions. A share may be visible but
unreadable, or readable while a particular directory is writable.

#### RPC enumeration

```bash
rpcclient -U "$DOMAIN/$USER%$PASS" "$IP"
```

```text
enumdomusers
enumdomgroups
querydispinfo
queryuser <RID>
enumprinters
netshareenumall
```

### NFS — 111, 2049

```bash
rpcinfo -p "$IP"
showmount -e "$IP"
nmap -Pn -p111,2049 --script 'nfs*' "$IP"
sudo mkdir -p /mnt/nfs
sudo mount -t nfs -o vers=3,nolock "$IP:/export" /mnt/nfs
find /mnt/nfs -maxdepth 3 -ls
```

Check ownership by numeric UID, writable directories, keys, backups, and whether
`root_squash` is enabled. Unmount when finished.

```bash
sudo umount /mnt/nfs
```

### SNMP — 161/UDP

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt "$IP"
snmpwalk -v2c -c public "$IP" 1.3.6.1.2.1.1
snmpwalk -v2c -c public "$IP" 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -v2c -c public "$IP" 1.3.6.1.2.1.25.6.3.1.2
snmpwalk -v2c -c public "$IP" 1.3.6.1.2.1.4.20.1.1
snmpwalk -v2c -c public "$IP" 1.3.6.1.2.1.6.13.1.3
```

Prioritize system details, running processes, installed software, interfaces,
routes, and command-line arguments.

### LDAP — 389, 636

Discover the naming context before constructing searches.

```bash
ldapsearch -x -H "ldap://$IP" -s base namingcontexts
ldapsearch -x -H "ldap://$IP" -b 'DC=example,DC=local' '(objectClass=user)' sAMAccountName
ldapsearch -x -H "ldap://$IP" -D "$USER@$DOMAIN" -w "$PASS" \
  -b 'DC=example,DC=local' '(objectClass=*)'
ldapsearch -x -H "ldap://$IP" -D "$USER@$DOMAIN" -w "$PASS" \
  -b 'DC=example,DC=local' '(objectClass=group)' cn member
ldapsearch -x -H "ldap://$IP" -D "$USER@$DOMAIN" -w "$PASS" \
  -b 'DC=example,DC=local' '(objectClass=computer)' dNSHostName operatingSystem
```

For TLS problems, test `ldaps://` and inspect the certificate for domain names.

### Databases

#### MSSQL — 1433

```bash
impacket-mssqlclient "$DOMAIN/$USER:$PASS@$IP" -windows-auth
```

```sql
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT name FROM sys.databases;
EXEC sp_linkedservers;
SELECT name,type_desc,is_disabled FROM sys.server_principals;
```

#### MySQL — 3306

```bash
mysql -h "$IP" -u "$USER" -p
```

```sql
SELECT user();
SHOW DATABASES;
SELECT user,host,plugin FROM mysql.user;
SHOW VARIABLES LIKE 'secure_file_priv';
SELECT @@version,@@hostname;
```

#### PostgreSQL — 5432

```bash
psql -h "$IP" -U "$USER" -d postgres
```

```sql
SELECT current_user;
\l
\du
\dt
SELECT version();
```

### Redis — 6379

```bash
redis-cli -h "$IP" ping
redis-cli -h "$IP" INFO
redis-cli -h "$IP" CONFIG GET dir
redis-cli -h "$IP" CONFIG GET dbfilename
redis-cli -h "$IP" --user "$USER" --pass "$PASS" INFO
```

Check authentication, server version, bound interfaces, persistence paths, and
accessible keys before considering any write primitive.

### RDP and WinRM

```bash
xfreerdp3 /v:"$IP" /u:"$USER" /p:"$PASS" /d:"$DOMAIN" /cert:ignore
evil-winrm -i "$IP" -u "$USER" -p "$PASS"
evil-winrm -i "$IP" -u "$USER" -H '<NTLM>'
netexec rdp "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS"
netexec winrm "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS"
```

Authentication success does not guarantee authorization to log on through that
service. Record the distinction and try the same credentials against other
appropriate services.
