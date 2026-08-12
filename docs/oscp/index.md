---
title: OSCP
---

# OSCP

## Working variables

```bash
# Define reusable target and callback variables before copying commands
export IP='192.0.2.10'
export PORT='80'
export URL="http://$IP:$PORT"
export LHOST='192.0.2.20'
export LPORT='443'
export DOMAIN='example.local'
export USER='username'
export PASS='password'
```

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

## References

- [Official PEN-200 syllabus](https://manage.offsec.com/app/uploads/2026/03/PEN-200_Syllabus.pdf)
- [Official OSCP exam guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [Rai2en OSCP notes](https://github.com/Rai2en/OSCP-Notes)
