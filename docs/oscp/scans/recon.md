## Recon

### Hosts

```bash
# Query WHOIS through the target service.
whois megacorpone.com -h "$IP" | tee whois.txt
# Discover live hosts in the target subnet.
nmap -sn 192.168.50.0/24 -oA hosts
# Discover NetBIOS hosts and names.
sudo nbtscan -r 192.168.50.0/24 | tee nbtscan.txt
```

### TCP

```bash
# Scan every TCP port quickly.
sudo nmap -Pn -n -p- --min-rate 2000 --open "$IP" -oA tcp
# Extract the open port numbers from the scan.
ports=$(awk -F'Ports: ' '/Ports:/{print $2}' tcp.gnmap | tr ',' '\n' | awk -F/ '$2=="open"{gsub(/ /,"",$1);print $1}' | paste -sd,)
# Run scripts and version detection on open ports.
sudo nmap -Pn -n -sC -sV -p "$ports" "$IP" -oA services
# Sweep the top 20 TCP ports across the subnet.
nmap -sT -A --top-ports 20 192.168.50.1-253 -oG sweep.txt
```

Example:

```text
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1
80/tcp  open  http    Apache httpd 2.4.52
445/tcp open  smb     Samba smbd 4.15.13
```

### UDP

```bash
# Scan the 50 most common UDP ports.
sudo nmap -Pn -n -sU --top-ports 50 --open "$IP" -oA udp
# Probe common UDP services with version detection.
sudo nmap -Pn -n -sU -sV -p53,69,111,123,137,161,500,4500 "$IP" -oA udp-services
```

### Banners

```bash
# Read the SSH banner.
nc -nv "$IP" 22 | tee banner.txt
# Read the HTTPS certificate names and issuer.
openssl s_client -connect "$IP:443" -servername corp.com </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName
```
