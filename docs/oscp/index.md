---
title: OSCP
---

# OSCP

Practical notes for moving from an unknown target to a controlled system. These
pages are organized by task rather than by the PEN-200 course syllabus.

## Attack loop

1. Establish the target, scope, and a clean workspace.
2. Discover every reachable TCP and relevant UDP service.
3. Enumerate each service manually before searching for exploits.
4. Turn information into a foothold: credentials, writable content, vulnerable
   applications, or unsafe configuration.
5. Enumerate again from the new security context.
6. Escalate privileges, reuse credentials, and pivot only when the evidence
   supports it.

## Working variables

Use the same variable names throughout the notes so commands remain easy to
adapt.

```bash
export IP='192.0.2.10'
export PORT='80'
export URL="http://$IP:$PORT"
export LHOST='192.0.2.20'
export LPORT='443'
export DOMAIN='example.local'
export USER='username'
export PASS='password'
```

Do not create aliases that replace standard tools such as `nc`, `wget`, `john`,
or `smbclient`. They make copied commands unpredictable.

## Operating principle

Every useful finding should produce a next action. Record usernames, hostnames,
domains, technologies, versions, credentials, writable locations, and trust
relationships as soon as they appear. When stuck, return to the evidence rather
than running a larger automated scan.

--8<-- "docs/gyms/oscp/methodology.md"

--8<-- "docs/gyms/oscp/enumeration.md"

--8<-- "docs/gyms/oscp/services.md"

--8<-- "docs/gyms/oscp/web.md"

--8<-- "docs/gyms/oscp/credentials.md"

--8<-- "docs/gyms/oscp/shells-transfers.md"

--8<-- "docs/gyms/oscp/linux-privesc.md"

--8<-- "docs/gyms/oscp/windows-privesc.md"

--8<-- "docs/gyms/oscp/active-directory.md"

--8<-- "docs/gyms/oscp/pivoting.md"
