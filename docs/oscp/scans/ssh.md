## SSH — 22

```bash
# Enumerate SSH authentication, algorithms, and host keys.
nmap -Pn -p22 --script ssh-auth-methods,ssh2-enum-algos,ssh-hostkey "$IP" -oN ssh.txt
# Connect with a password.
ssh "$RUSER@$IP"
# Connect with a private key.
ssh -i id_rsa "$RUSER@$IP"
# Restrict the private key permissions.
chmod 600 id_rsa
# Derive the public key from the private key.
ssh-keygen -y -f id_rsa
# Test the george account against a password list.
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 22 "ssh://$IP" -o ssh-hydra.txt
```

### Encrypted key

```bash
# Extract the private-key password hash.
ssh2john id_rsa > ssh.hash
# Crack the private-key password.
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
# Display the recovered password.
john --show ssh.hash
```
