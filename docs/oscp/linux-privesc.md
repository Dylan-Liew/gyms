## Linux Privilege Escalation

Privilege escalation is usually a trust-boundary problem: a privileged process
reads, executes, imports, or modifies something controlled by the current user.

### Baseline

```bash
id
uname -a
cat /etc/os-release
hostname
sudo -l
ip addr
ip route
ss -lntup
ps auxww
findmnt
env | sort
getent passwd
getent group
last -a | head
w
```

Also record the current shell, environment, groups, home directory, umask, and
available compilers or scripting runtimes.

### Sudo

```bash
sudo -l
sudo -V | head
sudo -ll
grep -RIns '^[^#].*' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

For every allowed command, ask whether it can:

- start a shell or editor;
- execute another command;
- load a library, plugin, or configuration file;
- write an arbitrary file;
- preserve a dangerous environment variable;
- use a wildcard or attacker-controlled path.

Test the exact rule, including arguments and host restrictions. Do not assume a
binary behaves the same under `sudo` as it does interactively.

### SUID and SGID

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
find / -perm /6000 -type f -exec ls -la {} \; 2>/dev/null
```

Prioritize unusual binaries and standard tools with shell, file-write, or command
execution features. Inspect custom binaries:

```bash
file /path/to/binary
strings -a /path/to/binary | less
ldd /path/to/binary
strace -f /path/to/binary 2>&1 | less
readelf -d /path/to/binary
objdump -x /path/to/binary | less
```

Look for relative commands, writable configuration, unsafe temporary files, and
libraries loaded from controllable paths.

### Capabilities

```bash
getcap -r / 2>/dev/null
getcap /usr/bin/* /usr/local/bin/* 2>/dev/null
```

High-value capabilities include `cap_setuid`, `cap_dac_read_search`,
`cap_dac_override`, and `cap_sys_admin`. Interpret the capability together with
what the binary can actually do.

### Scheduled work

```bash
cat /etc/crontab
find /etc/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all
ls -la /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
systemctl list-timers --all --no-pager
```

Observe activity when the definition does not reveal the executed path:

```bash
pspy64
```

Check the script, its parent directories, referenced files, wildcard expansion,
`PATH`, and environment. Write access must influence privileged execution to be
useful.

### Services and sockets

```bash
systemctl list-units --type=service --state=running
systemctl cat <service>
ss -lntup
find /run /var/run -type s -ls 2>/dev/null
systemctl list-unit-files --type=service
find /etc/systemd/system /usr/local/lib/systemd/system -type f -writable -ls 2>/dev/null
ls -la /etc/init.d 2>/dev/null
```

Investigate custom services, local-only management interfaces, Docker sockets,
and writable service files. Group membership in `docker`, `lxd`, or similar
administrative services may cross the root boundary.

### Writable paths and PATH usage

```bash
find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev)'
find / -writable -type f 2>/dev/null | grep -vE '^/(proc|sys|dev)'
printf '%s\n' "$PATH" | tr ':' '\n'
find / -user root -perm -002 -type f -ls 2>/dev/null
find / -user root -perm -002 -type d -ls 2>/dev/null
namei -l /path/to/interesting/file
getfacl /path/to/interesting/file
```

A writable directory is only a finding when a privileged process consumes data
from it. For PATH hijacking, confirm that a privileged program invokes a command
without an absolute path and that a searched directory is controllable.

### Credentials and sensitive files

```bash
find /home /root -maxdepth 3 -type f \( -name '.*history' -o -name 'id_*' \
  -o -name '*.kdbx' \) -ls 2>/dev/null
rg -n -i 'password|secret|token|credential' /var/www /opt /srv 2>/dev/null
cat /etc/passwd
ls -la /etc/shadow /etc/passwd
find / -type f \( -name '*.bak' -o -name '*.old' -o -name '*.save' -o -name '*.swp' \) 2>/dev/null
find /home -maxdepth 4 -type f -readable -printf '%u %m %p\n' 2>/dev/null
ls -la /var/mail /var/spool/mail 2>/dev/null
for p in /proc/[0-9]*/environ; do tr '\0' '\n' <"$p" 2>/dev/null; done | sort -u
```

Review application configuration, backups, shell history, mail, mounted shares,
process environments, and command-line arguments.

### NFS and containers

```bash
cat /etc/exports 2>/dev/null
mount
ls -l /var/run/docker.sock 2>/dev/null
docker images 2>/dev/null
id | grep -E 'docker|lxd|disk'
docker ps -a 2>/dev/null
lxc list 2>/dev/null
```

From Kali, validate NFS export behavior:

```bash
showmount -e "$IP"
nmap -Pn -p111,2049 --script nfs-showmount,nfs-ls,nfs-statfs "$IP"
```

For NFS, correlate export options with numeric UID ownership. For containers,
determine whether the current context can mount the host filesystem or control a
privileged container runtime.

### Kernel exploits: last resort

```bash
uname -a
cat /proc/version
dpkg -l 2>/dev/null | head
rpm -qa 2>/dev/null | head
sysctl kernel.unprivileged_userns_clone 2>/dev/null
grep -E 'CONFIG_(USER_NS|BPF|OVERLAY_FS)' /boot/config-"$(uname -r)" 2>/dev/null
```

Confirm the exact kernel build, architecture, distribution patches, required
configuration, and exploit side effects. Prefer configuration flaws because
kernel exploits may crash or corrupt the target.

### Automated enumeration

Run tools such as `linpeas` or `lse` to support manual reasoning, not replace it.
Review the output by trust boundary: credentials, sudo, SUID, services, scheduled
work, writable paths, containers, and kernel exposure.

```bash
./linpeas.sh -a | tee /tmp/linpeas.out
./lse.sh -l 1 | tee /tmp/lse.out
./pspy64 -pf -i 1000
```

### When stuck

- Re-run enumeration after obtaining a new group or credential.
- Inspect custom applications and services before standard system binaries.
- Compare file ownership with the identity of the consuming process.
- Monitor processes and filesystem activity over time.
- Check local-only ports from the target itself.
