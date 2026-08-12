---
title: OSWE
---

# OSWE

WEB-300 source-assisted web exploitation notes. The core loop is:
route → input → transformation → security decision → sink → observable result.

## Repository orientation

```bash
# Inventory languages, manifests, routes, and configuration
find . -maxdepth 3 -type f | sort | sed -n '1,240p'
find . -iname 'package*.json' -o -iname '*.csproj' -o -iname 'pom.xml' -o -iname 'composer.json'
rg -n 'route|router|controller|endpoint|Map(Get|Post)|@RequestMapping|app\.(get|post)'

# Locate secrets, connection strings, and security configuration
rg -ni 'password|secret|token|connectionstring|jdbc:|mongodb|redis|jwt|oauth'
rg -n 'authorize|authentication|permission|role|middleware|guard|filter'
```

Build a route ledger with handler, method, input fields, authentication,
authorization, transformations, persistence, and response behavior.

## Source-to-sink searches

```bash
# Find common process, file, SQL, template, and deserialization sinks
rg -n 'exec\(|spawn\(|Process\.Start|Runtime\.getRuntime|system\(|popen\('
rg -n 'File\.|readFile|writeFile|Path\.Combine|sendFile|include\(|require\('
rg -n 'SELECT |INSERT |UPDATE |DELETE |executeQuery|FromSqlRaw|createQuery'
rg -n 'deserialize|unserialize|ObjectInputStream|BinaryFormatter|pickle\.loads'
rg -n 'render\(|render_template|Template\(|eval\(|new Function'

# Find server-side requests and XML parsers
rg -n 'HttpClient|requests\.|urllib|fetch\(|axios\.|curl_exec'
rg -n 'DocumentBuilderFactory|XmlReader|XDocument|DOMDocument|simplexml'
```

Do not stop at the sink. Trace validation, canonicalization, encoding, query
construction, object binding, and role checks on every path that reaches it.

## Run and debug

```bash
# Start a Node application with inspector support
node --inspect-brk app.js

# Start a Python application under the debugger
python -m pdb app.py

# List listening processes and attach system-call tracing
ss -lntup
strace -ff -s 2048 -o traces/app -p PID
```

```powershell
# List .NET processes and attach a diagnostic trace
Get-Process dotnet,w3wp -ErrorAction SilentlyContinue
dotnet-trace collect --process-id PID
```

Use the debugger to verify runtime types and transformed values; source alone
often hides framework decoding, implicit binding, or middleware order.

## Reproducible request harness

```python
# Preserve cookies and make response differences explicit
import requests

BASE = "https://target.example"
s = requests.Session()
s.verify = False

r = s.get(f"{BASE}/api/item", params={"id": "1"}, timeout=10)
print(r.status_code, len(r.content), r.elapsed.total_seconds())
print(r.headers.get("Content-Type"))
print(r.text[:500])
```

Keep transport, authentication, baseline request, probe, oracle, and final
demonstration as separate functions.

## Authentication and business logic

```bash
# Compare authorization behavior between two controlled sessions
curl -sk -b user.cookies https://target.example/api/admin -o user.out
curl -sk -b admin.cookies https://target.example/api/admin -o admin.out
diff -u user.out admin.out

# Inspect JWT structure without assuming the signature is valid
python -c 'import base64,json,sys; p=sys.argv[1].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"===")))' 'TOKEN'
```

Trace password reset, invitation, account linking, object ownership, and role
changes as state machines. Test missing, reordered, repeated, and concurrent steps.

## Blind-oracle skeleton

```python
# Measure a boolean oracle with repeated samples
import statistics, time, requests

def sample(value, count=5):
    times = []
    for _ in range(count):
        start = time.monotonic()
        requests.get("https://target.example/item",
                     params={"id": value}, verify=False, timeout=15)
        times.append(time.monotonic() - start)
    return statistics.median(times)

print("baseline", sample("1"))
print("probe", sample("1 AND 1=2"))
```

Use stable signals: status, exact marker, normalized length, redirect location,
or median timing. Add retries and checkpoints before extracting data.

## Serialization and object binding

```bash
# Identify dependency versions and known serialization packages
npm ls --all 2>/dev/null | rg -i 'serialize|yaml|xml'
dotnet list package
mvn dependency:tree

# Decode Java serialization data for offline inspection
base64 -d object.b64 > object.bin
file object.bin
xxd -l 32 object.bin
```

Map format, framework, signing or encryption, attacker-controlled fields, gadget
availability, and the exact deserialization call. Treat gadget generators as
version-specific lab tools, not universal payload factories.

## Upload, SSRF, XML, and prototype paths

```bash
# Inspect file validation and storage code together
rg -n 'multipart|upload|filename|content-type|mimetype|extension'

# Find URL parsing, allowlists, redirects, and proxy behavior
rg -n 'urlparse|Uri\(|URL\(|redirect|allowlist|whitelist|proxy'

# Search JavaScript merge and prototype-sensitive operations
rg -n '__proto__|constructor|prototype|Object\.assign|merge|deep'
```

For SSRF, test parser differential, redirect handling, DNS resolution, scheme,
port, and response visibility separately. For uploads, separate validation,
storage, retrieval, processing, and execution.

## References

- [Official WEB-300 syllabus](https://manage.offsec.com/app/uploads/2026/03/WEB-300_Syllabus.pdf)
- [aaidanquimby OSWE notes](https://github.com/aaidanquimby/OSWE-Notes)
- [farhankn OSWE preparation](https://github.com/farhankn/oswe_preparation)
