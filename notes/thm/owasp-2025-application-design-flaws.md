# OWASP Top 10 2025: Application Design Flaws (TryHackMe)

- **Path:** Jr Penetration Tester - module "OWASP Top 10 (2025)".
- **Room:** OWASP Top 10 2025: Application Design Flaws (beginner, ~30 min).
- **Date:** 2026-10-13.
- **Target:** `<ip>` (THM VPN; challenges on ports 5002-5005). Lab machine title
  `owasptop102025applicationdesignflawstwo`.
- **Status:** SOLVED. All 4 flags captured from own Windows PC over the VPN (Python `urllib`
  client); Task 3 confirmed against the downloaded Task Files source.
- **Scope:** four categories, each an architecture/design flaw:
  AS02 Security Misconfigurations, AS03 Software Supply Chain Failures,
  AS04 Cryptographic Failures, AS06 Insecure Design.

## Flags

| Task | Category | Port | Flag |
|---|---|---|---|
| 2 | AS02 Security Misconfigurations | 5002 | `THM{…}` |
| 3 | AS03 Software Supply Chain Failures | 5003 | `THM{…}` |
| 4 | AS04 Cryptographic Failures | 5004 | `THM{…}` |
| 5 | AS06 Insecure Design | 5005 | `THM{…}` |

## Environment note

All four services reachable from the Windows host over the standard THM VPN. Use a Python
`urllib`/`requests` client rather than curl (curl has been flaky over this link in prior rooms).
Force UTF-8 output (`sys.stdout.reconfigure(encoding='utf-8')`) on Windows or emoji in page bodies
crash printing under cp1252.

## AS02 Security Misconfigurations (Task 2, port 5002)

The landing page documents one endpoint: `GET /api/user/<user_id>`, "User ID must be numeric".

- A numeric ID returns JSON for John Doe (`/api/user/123`, `/api/user/1`, etc. all return the
  same user - placeholder data).
- A **non-numeric** ID triggers an unhandled `ValueError` and the app returns a verbose error:
  HTTP 500 with the full traceback and a `debug_info.flag` field.

```
GET /api/user/abc  -> 500
{
  "debug_info": {"flag": "THM{…}"},
  "error": "Invalid user ID format: abc. Flag: THM{…}",
  "traceback": "... File \"/app/app.py\", line 21, in get_user ... ValueError ..."
}
```

**Flag:** `THM{…}`. The misconfiguration is debug/verbose error handling left on
in a deployed service, leaking stack traces (and here, a secret) to clients.

## AS03 Software Supply Chain Failures (Task 3, port 5003)

`GET /` documents `POST /api/process` (JSON `{"data": "..."}`) and `GET /api/health`
(`{"status":"healthy","version":"1.0.0"}`). The live `/api/process` appears to only return
`"Output: " + data.upper()`: no SSTI (`{{7*7}}` not evaluated), no format-string injection, no
deserialization path, and source files are not web-served. Black-box probing alone does not reveal
the flag here; the flaw is in the imported third-party component and a hidden branch in the app.

Reading the provided Task Files source (`app.py`) shows the app blindly imports an unverified
local library and exposes an undocumented debug branch:

```python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))
from vulnerable_utils import process_data, format_output, debug_info   # unverified dependency
...
if data == 'debug':
    return jsonify(debug_info())      # leaks secrets from the dependency
```

Sending exactly `{"data": "debug"}` invokes `debug_info()` from the third-party library, which
returns its internal secrets:

```json
{
  "admin_token": "admin_token_12345",
  "flag": "THM{…}",
  "internal_secret": "internal_secret_key_2024",
  "version": "1.2.3"
}
```

**Flag:** `THM{…}`. The supply-chain lesson: the app trusts an unvetted
local library (`lib/vulnerable_utils.py`) and ships its `debug_info()` into a reachable route, so a
compromised/leaky dependency directly exposes app secrets. The exact-match `data == 'debug'` trigger
is easy to miss from pure black-box testing, which is why reading the provided source is the
intended workflow. (Flask `debug=True` in the dependency's `app.run` is a second misconfiguration.)

## AS04 Cryptographic Failures (Task 4, port 5004)

`GET /` is a "Secure Document Viewer" showing a base64 "encrypted document" and loading
`/static/js/decrypt.js`. That client-side JS hard-codes the crypto config:

```js
const SECRET_KEY = "my-secret-key-16";   // 16 bytes -> AES-128
const ENCRYPTION_MODE = "ECB";
const KEY_SIZE = 128;
```

Decrypting the blob with AES-128-ECB and the hard-coded key, then stripping PKCS#7 padding:

```python
import base64
from Crypto.Cipher import AES
blob = "Nzd42HZGgUIUlpILZRv0jeIXp1WtCErwR+j/w/lnKbmug31opX0BWy+pwK92rkhjwdf94mgHfLtF26X6B3pe2fhHXzIGnnvVruH7683KwvzZ6+QKybFWaedAEtknYkhe"
data = base64.b64decode(blob + "=" * (-len(blob) % 4))
pt = AES.new(b"my-secret-key-16", AES.MODE_ECB).decrypt(data)
print(pt[:-pt[-1]].decode())
# CONFIDENTIAL: The admin password is '<redacted-pw>'. Flag: THM{…}
```

**Flag:** `THM{…}`. Two crypto failures stacked: a secret key shipped in
client-side JavaScript, and ECB mode. Anyone who views source gets the key.

## AS06 Insecure Design (Task 5, port 5005)

`GET /` is a "SecureChat" page claiming the service is "exclusively for mobile devices - download
the app". This wall is cosmetic: the page is served identically regardless of `User-Agent`
(tested iPhone, Android, `Mobi`, `okhttp`, app-style headers - all byte-identical), so there is no
real device gate. The flawed design assumption is that *only the mobile app would ever call the
backend API*, so the API itself has no authentication or access control.

Enumerating the API directly:

- `GET /api/users` - returns all users unauthenticated (admin, user1/Alice, user2/Bob, with roles).
- `GET /api/messages/admin` - returns the admin's private messages, no auth:

```json
{"user": "admin", "messages": [
  {"from": "system", "content": "Admin panel access key: THM{…}"}
]}
```

**Flag:** `THM{…}`. You cannot patch this with input validation; the trust
boundary itself is wrong. Auth/authorisation must be enforced server-side on every request,
regardless of which client is "supposed" to call it.

## Lessons learned

- **AS02:** verbose errors and debug mode in production are a misconfiguration, not a code bug;
  malformed input that trips an unhandled exception is the fastest way to surface leaked traces.
- **AS04:** any secret reachable by the client (JS, mobile app bundle) is not a secret; ECB also
  leaks structure. "Encrypted on the client with a shipped key" is plaintext with extra steps.
- **AS06:** a client-side or UA-based "gate" is not access control; test the API the client talks
  to directly. Insecure design is architectural and cannot be patched at the input layer.
- Content discovery mattered most on the insecure-design box: the front page was a decoy and the
  whole challenge was an unauthenticated API one directory deep.

## Status

Room complete, all four flags captured. Together with the IAAA Failures room
([owasp-2025-iaaa-failures](owasp-2025-iaaa-failures.md)) this satisfies the two-room Gold League
goal.
