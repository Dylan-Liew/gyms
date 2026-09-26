---
title: OSWE
---

# OSWE

## Variables

```bash
export SRC="$PWD"
export URL='https://target.example'
mkdir -p traces
```

## Review points

| Area | Check |
| --- | --- |
| Routes | Handler, input, authentication, authorization |
| Queries | Parameter binding and database privileges |
| Files | Canonical path, ownership, storage location |
| Serialization | Format, dependency version, signature validation |
| Outbound requests | URL parsing, redirects, destination controls |
| Sessions | Cookie attributes, token validation, expiry |

## Source

```bash
find "$SRC" -maxdepth 3 -type f | sort | sed -n '1,240p'
find "$SRC" -iname 'package*.json' -o -iname '*.csproj' -o -iname 'pom.xml' -o -iname 'composer.json'
rg -n 'route|router|controller|endpoint|Map(Get|Post)|@RequestMapping|app\.(get|post)'

rg -ni 'password|secret|token|connectionstring|jdbc:|mongodb|redis|jwt|oauth'
rg -n 'authorize|authentication|permission|role|middleware|guard|filter'
```

## Sinks

```bash
rg -n 'exec\(|spawn\(|Process\.Start|Runtime\.getRuntime|system\(|popen\('
rg -n 'File\.|readFile|writeFile|Path\.Combine|sendFile|include\(|require\('
rg -n 'SELECT |INSERT |UPDATE |DELETE |executeQuery|FromSqlRaw|createQuery'
rg -n 'deserialize|unserialize|ObjectInputStream|BinaryFormatter|pickle\.loads'
rg -n 'render\(|render_template|Template\(|eval\(|new Function'

rg -n 'HttpClient|requests\.|urllib|fetch\(|axios\.|curl_exec'
rg -n 'DocumentBuilderFactory|XmlReader|XDocument|DOMDocument|simplexml'
```

Trace input transformations, validation, and authorization through to the sink.

## Debugging

```bash
node --inspect-brk app.js

python -m pdb app.py

ss -lntup
strace -ff -s 2048 -o traces/app -p PID
```

```powershell
Get-Process dotnet,w3wp -ErrorAction SilentlyContinue
dotnet-trace collect --process-id PID
```

Confirm runtime types and framework decoding in the debugger.

## Requests

```python
import requests

BASE = "https://target.example"
s = requests.Session()
s.verify = False

r = s.get(f"{BASE}/api/item", params={"id": "1"}, timeout=10)
print(r.status_code, len(r.content), r.elapsed.total_seconds())
print(r.headers.get("Content-Type"))
print(r.text[:500])
```

## Authentication

```bash
curl -sk -b user.cookies "$URL/api/admin" -o user.out
curl -sk -b admin.cookies "$URL/api/admin" -o admin.out
diff -u user.out admin.out

python -c 'import base64,json,sys; p=sys.argv[1].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(p+"===")))' 'TOKEN'
```

Decoding a JWT does not verify its signature.

## Response comparison

```python
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

## Serialization

```bash
npm ls --all 2>/dev/null | rg -i 'serialize|yaml|xml'
dotnet list package
mvn dependency:tree

base64 -d object.b64 > object.bin
file object.bin
xxd -l 32 object.bin
```

Match the serialization format, dependency version, and validation to the actual deserialization call.

## Files and URLs

```bash
rg -n 'multipart|upload|filename|content-type|mimetype|extension'

rg -n 'urlparse|Uri\(|URL\(|redirect|allowlist|whitelist|proxy'

rg -n '__proto__|constructor|prototype|Object\.assign|merge|deep'
```

## References

- [WEB-300 course](https://www.offsec.com/courses/web-300/)
