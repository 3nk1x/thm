# Silent Monitor (TryHackMe)

- **Path/module:** Jr Penetration Tester -> **Jr Pentester Challenges** (Capstone Challenge JRP). Premium.
  Web-to-root chain: enumerate an internal service, exploit the web app, pivot, and crack to root.
- **Date:** 2026-10-26.
- **Status:** SOLVED (both flags). Driven **headless from `C:\CTF`** over the THM VPN (threaded Python port
  scan, curl, Python `urllib` RCE runner, Paramiko SSH, pykeepass + rockyou). Target `Silent-Monitor` at
  **<ip>** (Ubuntu 22.04; only **22** and **5050** open).

## Flags

| File | Flag |
|---|---|
| user.txt | `THM{…}` |
| root.txt | `THM{…}` |

## 1. Enumerate - the NOC web app

- Only **22** and **5050** open (nmap SYN failed - can't bind the VPN adapter for pcap; a **threaded Python
  connect scanner** found the ports fast). 5050 = Flask/Werkzeug 2.0.2 "CorpNet NOC".
- Homepage is a static landing page; the dashboard on `:8812` ("Backup Agent") in the UI is **fake** (not a
  real listening service). Directory brute found **`/internal`** (the operator login).

## 2. Exploit the web app

- **SQLi auth bypass** on `/internal` (login): `username=' OR '1'='1'-- -`, any password -> 302 to
  `/internal/dashboard` with a Flask session `{"role":"operator","user":"netops"}`. (Source:
  `"... WHERE username='%s' AND password='%s'"` - unparameterised; a `union select` blocklist is why UNION
  failed, but boolean bypass works.)
- Dashboard -> **Host Health** (`/internal/health`) runs `ping -c 2 -W 1 <target>`. Input filter is
  `PING_BLOCK_RE = re.compile(r"[;|\`$&]")` - it blocks `;`, `|`, backtick, `$`, `&` **but not the
  newline**. The audit log even plants the hint `127.0.0.1%0awhoami`.
  - **Command injection via newline:** send the body **raw** (`--data`, not `--data-urlencode`, so `%0a`
    decodes to `\n` server-side):
    ```bash
    curl -b noc.txt -X POST http://<ip>:5050/internal/health --data 'target=127.0.0.1%0aid'
    # ... ping output ... uid=33(www-data)
    ```
  - RCE as **www-data**. (In the injected shell line, avoid `;$|&` and backtick - all filtered; chain with
    extra newlines or run one command per request.)

## 3. Pivot to sysadmin (user.txt)

- `/opt/netops` is `root:www-data` (group-accessible). `app.py` confirms the vulns; **`secret.config`**
  leaks the service account:
  ```ini
  [backup_agent]
  run_as   = sysadmin
  password = <redacted-pw>
  ```
- **SSH as `sysadmin`** with that password -> `~/user.txt` = `THM{…}`.
  (netops pw was also recoverable - `app.py` seeds `md5("<redacted-pw>")` - but netops isn't an OS user.)

## 4. Crack to root (root.txt)

- `sysadmin` can't sudo; SUID/caps standard. The "crack your way to root" artifact: **`~/backups/
  infrastructure.kdbx`** (KeePass 2.x / KDBX 4).
- Exfil over SSH (`base64 -w0`), crack the master with **pykeepass + rockyou**: master = **<redacted-pw>**
  (rockyou line 2524; AES-KDF, ~30ms/attempt so a dictionary run is fast).
- Vault entry **"Root User Password"**: `root : <redacted-pw>`. Root SSH is disabled, so `su - root`
  from the sysadmin shell (PTY via `invoke_shell`) -> `uid=0`, `/root/root.txt` =
  `THM{…}`.

## Lessons learned

- **nmap SYN is useless over this OpenVPN adapter** (`pcap_activate FAILED`); a quick **threaded Python
  `connect_ex` scanner** is the reliable headless substitute on this PC. Always full-scan - the only web
  service hid on **5050**.
- **`--data-urlencode` double-encodes `%`** - my `%0a` became literal `%250a` and failed. Use raw `--data`
  (or a real newline) so the server decodes the newline. The newline is the one metacharacter the
  `[;|\`$&]` blocklist forgot - classic incomplete-blocklist command injection.
- **The audit log was the hint board:** planted entries `admin' --`, `' OR 1=1#`, and `127.0.0.1%0awhoami`
  pointed straight at the login SQLi and the health-check newline injection.
- **Secrets live in config files** - `secret.config`'s backup-agent block handed over the sysadmin password
  (web -> OS pivot via a *service-account* credential).
- **KDBX cracking is a dictionary job:** `keepass2john`+john/hashcat is the usual route, but **pykeepass +
  rockyou** needs no extra tooling and is plenty fast when the KDF is AES (not Argon2). The vault then holds
  the root password outright.
- Whole chain headless from `C:\CTF`: threaded scan, `urllib` RCE runner that strips the ping preamble,
  Paramiko for SSH + `su` via a PTY shell, pykeepass for the crack. See [[ctf-workspace-dir]].

## Related

- [[tryhackme-learning-buddy]] / [[always-doc-rooms]] / [[ctf-workspace-dir]]. Same web->pivot->root shape
  and headless toolkit as [[domino]] (the other Jr Pentester Challenge solved this session); SQLi + command
  injection classes connect to [[writing-pentest-reports]]; re-test/validation mindset to [[re-testing]].
