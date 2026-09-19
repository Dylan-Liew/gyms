## SMTP — 25, 465, 587

```bash
# Enumerate SMTP commands and users.
nmap -Pn -p25,465,587 --script smtp-commands,smtp-enum-users "$IP" -oN smtp.txt
# Test recipient addresses from users.txt.
smtp-user-enum -M RCPT -U users.txt -D corp.com -t "$IP" | tee smtp-users.txt
# Read the SMTP EHLO response.
swaks --server "$IP" --quit-after EHLO
# Open a raw SMTP connection.
nc -nv "$IP" 25
```

```text
# Introduce the client domain.
EHLO corp.com
# Check whether root is a valid mailbox.
VRFY root
# Set the envelope sender.
MAIL FROM:<pete@corp.com>
# Test the recipient address.
RCPT TO:<admin@corp.com>
```

## POP3 — 110, 995

```bash
# Open an unencrypted POP3 session.
telnet "$IP" 110
# Open a TLS POP3 session.
openssl s_client -connect "$IP:995" -quiet
```

```text
# Send the POP3 username.
USER pete
# Send the POP3 password.
PASS Nexus123!
# List available messages.
LIST
# Retrieve the first message.
RETR 1
# Close the POP3 session.
QUIT
```

## IMAP — 143, 993

```bash
# Open an unencrypted IMAP session.
telnet "$IP" 143
# Open a TLS IMAP session.
openssl s_client -connect "$IP:993" -quiet
```

```text
# Authenticate to IMAP.
1 LOGIN pete Nexus123!
# List every mailbox.
2 LIST "" *
# Select the inbox.
3 SELECT INBOX
# Retrieve the first complete message.
4 FETCH 1 BODY[]
# Close the IMAP session.
5 LOGOUT
```
