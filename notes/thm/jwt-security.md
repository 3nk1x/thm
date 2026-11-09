# JWT Security (TryHackMe)

Room: JWT Security — premium web-app pentesting room on JSON Web Token flaws. A Flask API
(`JWT_API_Server_v5`) exposes `http://MACHINE_IP/api/v1.0/exampleX`; each example demonstrates one
JWT weakness. Goal per example: obtain a token with `admin` set to `1`, then `GET
.../exampleX?username=admin` to retrieve the flag. Completed: 2026-11-02 | Target: <ip>.

Solved fully **headless from `C:\CTF`** with `curl` + stdlib `python` (no PyJWT, no browser). JWTs
were forged by hand (base64url + `hmac`/`hashlib`), which sidesteps every library-version quirk.

## API shape

- `POST /api/v1.0/exampleX` with JSON `{"username":"user","password":"passwordX"}` → `{"token": "..."}`.
- `GET /api/v1.0/exampleX?username=admin` with header `Authorization: Bearer <jwt>` → flag when the
  token's `admin` claim is `1`.
- A JWT is `base64url(header).base64url(payload).base64url(signature)`; signing input is the first
  two segments joined by a dot. HS256 signature = `HMAC-SHA256(secret, header.payload)`.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Header used to transport the JWT | `Authorization: Bearer` |
| 3 | HS256 algorithm type | `Symmetric` |
| 3 | RS256 algorithm type | `Asymmetric` |
| 3 | Name for encrypted JWTs | `JWE` |
| 4 | Flag — example 1 | `THM{…}` |
| 5 | Flag — example 2 | `THM{…}` |
| 5 | Flag — example 3 | `THM{…}` |
| 5 | Flag — example 4 | `THM{…}` |
| 5 | Flag — example 5 | `THM{…}` |
| 6 | Flag — example 6 | `THM{…}` |
| 7 | Flag — example 7 | `THM{…}` |

## Reproducible steps

### Example 1 — Sensitive information disclosure
The flag is a *claim inside the token* (JWTs are signed, not encrypted — anyone can read the payload).

```bash
curl -s -H 'Content-Type: application/json' -X POST \
  -d '{ "username":"user","password":"password1" }' \
  http://<ip>/api/v1.0/example1
# decode the middle segment:
python -c "import base64,json; p='<payload-seg>'; print(base64.urlsafe_b64decode(p+'=='))"
# payload: {"username":"user","password":"password1","admin":0,"flag":"THM{…}"}
```

### Example 2 — No signature verification
Server decodes with `verify_signature=False`. Forge any payload and drop the signature (keep the
trailing dot):

```python
import base64, json
b = lambda d: base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()
tok = b({'typ':'JWT','alg':'HS256'}) + '.' + b({'username':'admin','admin':1}) + '.'
```
`GET example2?username=admin` with that token returns the flag.

### Example 3 — `None` algorithm downgrade
Same as ex2 but the server reads `alg` from the header. Set `alg` to **`None`** (capital N) with an
empty signature. Observed: lowercase `none` is rejected (`When alg = "none", key value must be
None.` — PyJWT's hardening fires because a secret is configured), but `None` slips through the
`algorithms` check and verification is skipped.

### Example 4 — Weak symmetric secret
HS256 with a crackable secret. The room suggests `hashcat -m 16500`; here the secret was recovered
instantly by HMAC-testing a short candidate list (no internet from the VPN shell, so the wallarm
list wasn't reachable):

```python
import hmac, hashlib, base64
h,p,s = open('jwt.txt').read().strip().split('.')
for c in ['secret','password','changeme','key','jwtsecret', ...]:
    if base64.urlsafe_b64encode(hmac.new(c.encode(),(h+'.'+p).encode(),hashlib.sha256).digest()).rstrip(b'=').decode()==s:
        print('FOUND', c)   # -> <redacted-secret>
```
Then re-sign `{'username':'admin','admin':1}` with `<redacted-secret>` and request the flag.

### Example 5 — Algorithm confusion (RS256 → HS256)
Server allows both RS and HS algorithms with the **public key** as the verification key. The login
response hands over the public key (`ssh-rsa AAAA...`). Forge an **HS256** token signed with that
public-key string as the HMAC secret — the server, verifying HS256, uses its public key as the
secret and the signature matches. Script: `C:\CTF\ex5.py` (pulls the key from the login response,
HMACs with `pub.encode()`, requests `?username=admin`). Observed: the `ssh-rsa` string works
as-is as the secret — no PEM conversion needed.

### Example 6 — No `exp` claim
A pre-issued, validly signed token with `{"username":"user","admin":1}` and no expiry never dies.
Use it unmodified; `GET example6?username=admin` returns the flag (`?username=user` → "Invalid
request made").

### Example 7 — Cross-service relay (audience not enforced)
Auth endpoint `example7` takes an extra `"application":"appX"` field and sets the `aud` claim.
`appB` login yields `{"username":"user","admin":1,"aud":"appB"}`. appA **does not verify `aud`**, so
replaying the appB token on `example7_appA?username=admin` grants admin and returns the flag. (The
same token on `example7_appB` is admin but has no flag; `appA` login is non-admin.)

## Lessons

- **Signed ≠ encrypted.** Example 1 is the whole point of the "sensitive info disclosure" class — a
  password and flag sat in plaintext claims. Never put secrets in a JWT payload.
- **Forge JWTs with stdlib, not PyJWT.** Hand-building base64url + `hmac`/`hashlib` avoids the
  library's `alg=none` / asymmetric-key-as-HMAC guards entirely and is version-proof. It also made
  the capital-`None` bypass (ex3) and the raw-`ssh-rsa`-as-secret trick (ex5) trivial to drive.
- **Algorithm confusion:** when an endpoint accepts both HS* and RS* and the public key is exposed,
  sign HS256 with the exact public-key bytes the server holds. Here the server kept the key in
  `ssh-rsa` form, so that string — verbatim — was the HMAC secret.
- **Audience is enforced client-side (per app), not by the issuer.** A token minted admin for one
  app is only as safe as every *other* app that trusts the same signing key and skips the `aud`
  check (ex7). Classic privilege-escalation-by-relay.
- **No internet from the VPN shell.** `curl` to `raw.githubusercontent.com` returned HTTP 000 while
  the THM target was reachable — the VPN route carries only lab traffic. Keep a small offline
  candidate list (and local wordlists in `C:\CTF`) for secret-cracking rather than fetching live.
- **Git-Bash vs native Python paths:** `curl` understands `/c/CTF`, but Windows `python` needs
  `C:/CTF`. Mixing the two silently writes/reads the wrong path (bit me on the ex4 `jwt.txt` write).
