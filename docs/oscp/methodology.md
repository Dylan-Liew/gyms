## Methodology

### Prepare the workspace

```bash
# Create a private workspace and initialize the notes
mkdir -p "$IP"/{scans,loot,web,exploits}
cd "$IP"
date -Is | tee notes.md
umask 077
touch findings.md credentials.md attempts.md
```

Record every command and result as you work. Capture screenshots when a step
proves access, code execution, privilege escalation, or a recovered credential;
the same evidence supports the report and makes it possible to resume a stalled
attack path later.

### Timebox the work

- Keep a visible timer for each target and attack path.
- If a path stops producing evidence, record the last result and rotate to the
  next exposed service instead of tunnelling on one idea.
- Take short breaks away from the desk. Fatigue makes enumeration gaps and
  transcription mistakes more likely.
- Return to the attack-surface table after each break and choose the next action
  from evidence, not memory.

### Connectivity

```bash
# Confirm the route and name resolution
ip route get "$IP"
getent hosts "$IP"
```

### Service enumeration

For every service, answer:

1. What exact product or protocol is exposed?
2. Does it allow anonymous or guest access?
3. What names, shares, files, routes, or users can it reveal?
4. Does it accept credentials already discovered elsewhere?
5. Can any accessible resource be written or executed?
6. Is the version actually vulnerable under this configuration?

Note the hostname and any role-like name such as `web-srv1`, `mail-srv1`, or
`dc01`. Names often reveal the intended function of a host and which services
should correlate.

```bash
# Capture raw service banners, TLS details, and HTTP behavior
nc -nv "$IP" "$PORT"
openssl s_client -connect "$IP:$PORT" -servername "$IP" </dev/null
curl -vk --max-time 10 "$URL"
```

### Public exploits

```bash
# Find, copy, and inspect a public exploit before execution
searchsploit '<product> <version>'
searchsploit -w '<product> <version>'
searchsploit -m <exploit-id-or-path>
file exploits/*
rg -n 'RHOST|RPORT|LHOST|LPORT|target|payload' exploits/
```

Search by exact product and version in Exploit-DB/Searchsploit, vendor
advisories, and public repositories. A Metasploit module is evidence that a
technique may have a public implementation, not proof that the target is
vulnerable. Validate prerequisites and prefer an inspected standalone exploit.
If an exam or lab limits Metasploit use, reserve it for a deliberate late-stage
attempt and record where the allowance was consumed.

### Local enumeration

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

### Post-escalation

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

## Exploit adaptation

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

```bash
# Generate a mechanical Python 3 preview, then inspect the diff manually
2to3 -w -n exploit.lab.py
python -m py_compile exploit.lab.py

# Confirm payload architecture and forbidden bytes before delivery
file payload.bin
xxd -g 1 payload.bin | head
python -c 'p=open("payload.bin","rb").read(); print(len(p), [hex(x) for x in (0,10,13) if bytes([x]) in p])'
```
