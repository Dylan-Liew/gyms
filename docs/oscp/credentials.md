## Credentials

### Credential ledger

| Domain/host | Username | Secret type | Source | Validated services |
| --- | --- | --- | --- | --- |
| `EXAMPLE` | `jsmith` | Password | Web configuration | SMB, WinRM |

Never overwrite the original hash or ciphertext. Keep transformed cracking input
in a separate file.

### Identify hashes

```bash
# Identify hash formats using both context and identification tools
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
# Convert protected files into formats accepted by John
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
# Try wordlists, rules, masks, and display recovered results
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
# Build a small target-specific candidate list from observed evidence
cewl -d 2 -m 5 -w web.words "$URL"
hashcat --stdout base.words -r /usr/share/hashcat/rules/best64.rule > mutated.words
sort -u web.words mutated.words > candidates.txt
crunch 8 10 -t 'Example%%%^^' -o pattern.words
printf '%s\n' Spring Summer Autumn Winter | sed 's/$/2026!/' >> candidates.txt
```

### Search Linux files

```bash
# Search likely Linux application and user locations for secrets
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
# Search likely Windows files, PowerShell history, and registry values
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
# Validate one recovered credential across justified services
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
# Perform narrowly scoped online checks after confirming lockout risk
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

## Cloud foothold checks

Cloud CLIs and metadata can explain an application’s identity and reachable
resources. Query them only when the host and cloud account are inside scope;
avoid recursively downloading buckets or secrets during initial enumeration.

```bash
# Identify configured AWS profiles and the active caller without listing data
find ~/.aws -maxdepth 2 -type f -ls 2>/dev/null
aws configure list-profiles
aws sts get-caller-identity --profile default

# Inspect the local AWS role name through IMDSv2
TOKEN=$(curl -fsS -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# Identify Azure CLI context without changing subscriptions
az account show
az account list --output table

# Identify Google Cloud CLI context and active project
gcloud auth list
gcloud config list
```

```powershell
# Locate common cloud configuration and token-cache directories
Get-ChildItem $HOME\.aws,$HOME\.azure,$HOME\AppData\Roaming\gcloud -Force -ErrorAction SilentlyContinue

# Inspect environment variable names while redacting their values
Get-ChildItem Env: | Where-Object Name -Match 'AWS|AZURE|GOOGLE|GCP' | Select-Object Name
```

Record account/tenant, principal, region, project/subscription, credential
source, expiry, and allowed action. A valid token is not proof of broad access.
