## Methodology

### Prepare the workspace

Keep raw tool output separate from working notes and downloaded files.

```bash
# Create a private workspace and record the terminal session
mkdir -p "$IP"/{scans,loot,web,exploits}
cd "$IP"
date -Is | tee notes.md
umask 077
touch findings.md credentials.md attempts.md
script -q -f terminal.log
```

Use `exit` to close the recorded terminal session. For parallel work, keep
listeners, scans, web traffic, and notes in named terminal panes.

```bash
# Start a named tmux session for parallel enumeration and listeners
tmux new-session -s "$IP"
tmux rename-window recon
```

Maintain four short lists while working:

- confirmed facts;
- credentials and where they came from;
- hypotheses worth testing;
- attempted paths and why they failed.

### Phase 1: discover

- Verify connectivity and determine whether the host answers only on specific
  protocols.
- Scan all TCP ports before assuming the initial result is complete.
- Run focused scripts and version detection only against discovered ports.
- Check common UDP services when TCP findings do not explain the target.
- Resolve discovered hostnames and virtual hosts locally.

```bash
# Confirm the route, name resolution, and direct TCP reachability
ip route get "$IP"
getent hosts "$IP"
timeout 3 bash -c "</dev/tcp/$IP/$PORT" && echo open
```

The output of this phase should be an attack-surface list, not merely an Nmap
file.

### Phase 2: enumerate

For every service, answer:

1. What exact product or protocol is exposed?
2. Does it allow anonymous or guest access?
3. What names, shares, files, routes, or users can it reveal?
4. Does it accept credentials already discovered elsewhere?
5. Can any accessible resource be written or executed?
6. Is the version actually vulnerable under this configuration?

Prefer a small number of deliberate commands over several overlapping
enumeration scripts.

Capture banners and certificates independently when version detection is vague.

```bash
# Capture raw service banners, TLS details, and HTTP behavior
nc -nv "$IP" "$PORT"
openssl s_client -connect "$IP:$PORT" -servername "$IP" </dev/null
curl -vk --max-time 10 "$URL"
```

### Phase 3: obtain a foothold

Prioritize attack paths with evidence behind them:

1. exposed credentials or secrets;
2. unsafe file upload or writable network shares;
3. authenticated application functionality;
4. injection and file-read vulnerabilities;
5. configuration-specific public exploits;
6. password guessing with a justified, narrow candidate set.

For public exploits, read the source before execution. Identify the vulnerable
version range, required access, hard-coded addresses, callback settings, and
expected side effects.

```bash
# Find, copy, and inspect a public exploit before execution
searchsploit '<product> <version>'
searchsploit -w '<product> <version>'
searchsploit -m <exploit-id-or-path>
file exploits/*
rg -n 'RHOST|RPORT|LHOST|LPORT|target|payload' exploits/
```

### Phase 4: enumerate locally

Immediately record the current identity, host, network configuration, groups,
privileges, running services, listening ports, and interesting files. Local
enumeration should explain the system rather than produce an unreadable dump.

Ask:

- Which security boundary am I trying to cross?
- What does the current user control?
- What privileged process consumes data that the user can modify?
- Which credentials or tokens are available in this context?

```bash
# Linux
# Capture the current identity, host, network, and process baseline
id; hostname; uname -a
ip addr; ip route; ss -lntup
ps auxww
```

```powershell
# Windows
# Capture the current identity, host, network, and process baseline
whoami /all
hostname
ipconfig /all
route print
netstat -ano
tasklist /svc
```

### Phase 5: escalate and expand

Test configuration mistakes before kernel exploits. After escalation, repeat
credential and network discovery because privileged access may expose new
secrets, interfaces, routes, or sessions.

```bash
# Compare the post-escalation Linux context
# Look for environment, mount, or listener changes after escalation
id; env | sort; findmnt; ss -lntup
```

```powershell
# Compare the post-escalation Windows context
# Look for privilege, share, and listener changes after escalation
whoami /all
Get-SmbConnection
Get-NetTCPConnection -State Listen
```

### When stuck

- Re-read every service banner and application response.
- Compare TCP and UDP coverage with the service checklist.
- Revisit authenticated functionality using every recovered credential.
- Check hostnames, virtual hosts, redirects, certificates, and source comments.
- Inspect files already downloaded instead of collecting more data.
- Confirm that an exploit matches the exact architecture and configuration.
- Try the same hypothesis manually with fewer moving parts.

## Exploit adaptation

Treat public exploit code as a hypothesis. Before running it, identify transport,
target version, architecture, authentication, hard-coded offsets, payload format,
callback settings, and expected success signal.

```bash
# Preserve an original copy and locate assumptions that require adaptation
cp exploit.py exploit.lab.py
rg -n 'RHOST|RPORT|LHOST|LPORT|offset|target|payload|shellcode|sleep' exploit.lab.py
diff -u exploit.py exploit.lab.py

# Check Python syntax and trace a failing execution
python -m py_compile exploit.lab.py
python -m pdb exploit.lab.py

# Observe network calls when source behavior is unclear
strace -ff -s 2048 -e trace=network -o traces/exploit python exploit.lab.py
```

For Python 2 to 3 ports, review byte strings, socket sends, integer division,
encoding, imports, exception syntax, and hexadecimal conversions explicitly.

```bash
# Generate a mechanical Python 3 preview, then inspect the diff manually
2to3 -w -n exploit.lab.py
python -m py_compile exploit.lab.py

# Confirm payload architecture and forbidden bytes before delivery
file payload.bin
xxd -g 1 payload.bin | head
python -c 'p=open("payload.bin","rb").read(); print(len(p), [hex(x) for x in (0,10,13) if bytes([x]) in p])'
```
