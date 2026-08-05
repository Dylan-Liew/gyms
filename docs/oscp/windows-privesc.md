## Windows Privilege Escalation

### Baseline

```powershell
whoami /all
hostname
systeminfo
ipconfig /all
route print
netstat -ano
tasklist /svc
Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture
Get-ChildItem Env: | Sort-Object Name
Get-PSDrive -PSProvider FileSystem
Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,DriveType,FileSystem,Size,FreeSpace
Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled
```

Record integrity level, groups, token privileges, architecture, domain membership,
installed software, running services, and listening ports.

### Token privileges

```powershell
whoami /priv
whoami /groups
whoami /claims
```

Investigate enabled or enableable privileges such as `SeImpersonatePrivilege`,
`SeAssignPrimaryTokenPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege`.
The correct technique depends on the OS build, service context, and available
communication mechanism.

### Services

```powershell
Get-CimInstance Win32_Service |
  Select-Object Name,StartName,State,PathName

sc.exe qc <service>
sc.exe query <service>
```

For interesting services, check:

- permissions on the service configuration;
- permissions on the executable and parent directories;
- unquoted paths containing spaces;
- writable DLL or configuration search locations;
- whether the current user can restart the service;
- the account used to run the service.

```powershell
sc.exe sdshow <service>
icacls 'C:\Path\To\service.exe'
Get-Acl 'C:\Path\To' | Format-List
accesschk.exe -uwcqv "$env:USERNAME" *
accesschk.exe -uwdqs Users C:\
```

### Unquoted service paths

```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' } |
  Select-Object Name,StartName,State,PathName

wmic service get name,displayname,pathname,startmode |
  findstr /i /v "C:\Windows\\" | findstr /i /v '"'
```

An unquoted path is exploitable only when a candidate path is writable and the
service can be started or will start predictably.

### Scheduled tasks and startup

```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object State -ne Disabled
Get-CimInstance Win32_StartupCommand
Get-ScheduledTask | ForEach-Object { $_ | Get-ScheduledTaskInfo }
schtasks /query /xml ONE /tn '<task-name>'
```

Startup and autorun locations:

```powershell
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Get-CimInstance Win32_StartupCommand | Format-List Name,Command,Location,User
```

Inspect task actions, executing users, triggers, referenced scripts, and
permissions on every component of the execution path.

### AlwaysInstallElevated

```powershell
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both values must be enabled for the policy to create the expected elevation
path.

### Credentials

```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath
cmdkey /list
dir C:\Users\*\Desktop,C:\Users\*\Documents -Force -ErrorAction SilentlyContinue
Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object Name -match '\.(config|xml|ini|txt|kdbx|rdp)$'
Get-ChildItem C:\inetpub,C:\xampp,C:\ProgramData -Recurse -File -ErrorAction SilentlyContinue |
  Select-String -Pattern 'password|secret|token|connectionString'
```

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
dir /s /b C:\*unattend*.xml C:\*sysprep*.xml C:\*.kdbx 2>nul
findstr /si password C:\*.xml C:\*.ini C:\*.config 2>nul
```

Also review web roots, service configuration, unattended installation files,
saved RDP files, application backups, and mapped shares.

### SAM and SYSTEM hives

If the current context can read or save the required registry hives:

```powershell
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY
vssadmin list shadows
wmic shadowcopy get DeviceObject,InstallDate
```

Process transferred copies offline:

```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

### Installed software and patches

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
  HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName,DisplayVersion,InstallLocation

Get-HotFix
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic product get Name,Version 2>nul
```

Search for application-specific configuration flaws before selecting an OS
exploit. Confirm architecture, build, patches, and prerequisites.

### Local groups and sessions

```powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
query user
net use
quser
qwinsta
net localgroup
net user
```

## Filesystem permissions

```powershell
icacls C:\Path\To\Directory
Get-Acl C:\Path\To\Directory | Format-List
Get-ChildItem C:\ProgramData,C:\inetpub -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.Attributes -notmatch 'ReparsePoint' } |
  ForEach-Object { try { Get-Acl $_.FullName } catch {} }
```

Prioritize custom application directories and service paths rather than dumping
ACLs for the entire operating system.

## Network and local services

```powershell
Get-NetTCPConnection -State Listen | Sort-Object LocalPort
Get-Process -Id (Get-NetTCPConnection -State Listen).OwningProcess -ErrorAction SilentlyContinue
Get-SmbShare
Get-SmbConnection
Get-ChildItem \\.\pipe\
```

Group membership may expose backup, remote management, virtualization, or
application-control capabilities even when the account is not a local
administrator.

### Automated enumeration

Use `winPEAS`, `Seatbelt`, or `PowerUp` as a second pass. Validate every reported
finding manually and prioritize paths where a privileged process consumes a
user-controlled file, command, token, or credential.

```powershell
.\winPEASx64.exe log=winpeas.out
.\Seatbelt.exe -group=system
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

### When stuck

- Re-check token privileges and group memberships.
- Inspect non-Microsoft services and scheduled tasks first.
- Test permissions on parent directories, not only the executable.
- Look for credentials in application context and user history.
- Examine localhost-only services and named pipes.
- Re-enumerate after changing user or integrity level.
