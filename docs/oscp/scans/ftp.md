## FTP — 21

```bash
# Detect the FTP version and anonymous access.
sudo nmap -sC -sV -p21 "$IP" -oN ftp.txt
# Open an interactive FTP session.
ftp "$IP"
```

```text
Name: anonymous
Password: anonymous@example.com
# Use binary mode for non-text files.
ftp> binary
# List remote files.
ftp> ls -la
# Download the backup archive.
ftp> get backup.zip
# Upload a harmless marker.
ftp> put marker.txt
```

```bash
# Test the admin account against a password list.
hydra -l admin -P /usr/share/wordlists/rockyou.txt "ftp://$IP" -o ftp-hydra.txt
# List files through an anonymous FTP URL.
curl -v "ftp://anonymous:anonymous@example.com@$IP/"
```
