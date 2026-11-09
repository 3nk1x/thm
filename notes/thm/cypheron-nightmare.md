# Cypheron — Nightmare / n8n Unauth RCE → Container Root (TryHackMe)

- **Event:** 2026: An AI Odyssey CTF — Cypheron room, Task 3 "Nightmare"
- **Category:** AI Security + Red Team · **Difficulty:** Insane · 120 pts
- **Completed:** 2026-10-08 · **Target:** <ip> (changes each redeploy)
- **Flags:** user `THM{…}` · root `THM{…}`

A self-hosted **n8n 1.120.4** (port 5678) with a public file-upload form. The form
"is too trusting about what its visitors claim to carry" → **CVE-2026-21858** content-type
confusion = **unauthenticated arbitrary file read**. Read the secrets + DB → **forge the
owner session cookie** → authenticated **Execute Command** node = RCE as `node` → **`su` to
root** with a password leaked in a world-readable boot script → read the root flag from the
**host filesystem mounted read-only at `/host-root`**.

## Recon

- Only ports: **22** (SSH) and **5678** (n8n). `GET /rest/settings` is public → `versionCli`
  `1.120.4`, owner already set up, MFA on. REST API otherwise needs auth.
- `/form/file-processor` = an n8n **Form Trigger** "Document Upload Service" with one `file`
  field, wired to a **Respond to Webhook** node (`respondWith: binary`). Behaves as a pure
  echo: it returns the uploaded bytes and sets the response `Content-Type` to whatever the
  upload *claims*. That echo + binary-respond is exactly what makes the file-read exfiltrate.
- Dead end that ate a whole session first: `/chat` is a WebSocket that closes `1008 Policy
  Violation` on every connection — it's the AI agent but hard-gated to an internal source
  range, unreachable from the VPN. **Not** the path. (Theme-matched bait.)

## CVE-2026-21858 — arbitrary file read (unauthenticated)

The Form Trigger took `files` straight from the JSON body and `copyBinaryFile(file.filepath)`
without checking the request was really `multipart/form-data`. So POST **`Content-Type:
application/json`** and name any `filepath`:

```json
{ "data": {},
  "files": { "f-abc": { "filepath": "/etc/passwd",
                        "originalFilename": "x.bin",
                        "mimetype": "application/octet-stream",
                        "size": 12345 } } }
```

The two details earlier attempts got wrong (→ HTTP 500): **`data` must be an empty object `{}`**
(not an array) and **`mimetype` is lowercase** (not `mimeType`). Response body = the file.

```
POST /form/file-processor   (Content-Type: application/json)   →  200, file bytes
```

## Chain to RCE

1. **Read `/proc/self/environ`** → leaks the n8n secrets directly (set as env vars here):
   - `N8N_USER_MANAGEMENT_JWT_SECRET=<redacted-secret>`
   - `N8N_ENCRYPTION_KEY=<redacted-secret>`
2. **Read `$HOME/.n8n/database.sqlite`** (≈9.8 MB). Owner row (image-baked, stable across
   redeploys): `admin@lab.local`, id `f52da01b-db1b-4ad5-97d0-2f2ee6332825`, bcrypt
   `<redacted-secret>`, `roleSlug=global:owner`.
   No `THM{` anywhere in the DB → flags are files, reachable only after RCE.
3. **Forge the `n8n-auth` cookie** offline. n8n's `AuthService` signs
   `HS256({ id, hash }, jwtSecret)` where `hash = base64(sha256("email:password_hash"))[:10]`.
   Because `N8N_USER_MANAGEMENT_JWT_SECRET` is set, the secret is that env value *verbatim*
   (not the `sha256(encryptionKey[::2])` fallback some PoCs assume). `GET /rest/users` with the
   cookie → authenticated as owner.
4. **Execute Command RCE.** This box runs with `N8N_ALLOW_EXEC_COMMAND` enabled (proved by an
   active `Internal Automation — DO NOT SHARE` webhook wired to an `executeCommand` node).
   Create a workflow `manualTrigger → n8n-nodes-base.executeCommand`, run it, done.
   - **Exfil trick:** have the command write to `/tmp/<rnd>` and read that file back with the
     file-read bug — sidesteps parsing n8n's flattened execution data. Runs as `uid=1000(node)`.

## User flag

`/home/node/flag-user-lfi.txt` (world-readable) → read straight out with the file-read bug:

```
THM{…}
```

## Root — leaked password + host mount

`/setup.sh` is world-readable (bind-mounted **ro**, despite `-rwxrwxr-x node`). It's the boot
script that runs as root then drops to node via `su-exec`, and it contains:

```sh
echo 'root:<redacted-pw>' | chpasswd      # root password, in cleartext
chmod 600 /etc/passwd                               # (why reading /etc/passwd 500s as node)
# ...
exec su-exec node tini -- /docker-entrypoint.sh
```

`/bin/su` is SUID-root. `/host-root` is the **host root home**, bind-mounted read-only
(`/dev/root … /host-root ext4 ro`), `drwx------ root` → need uid 0 to read it. So:

- RCE is non-interactive (no TTY) and `su` demands a terminal. `script -c` (pty) gave
  "Authentication token manipulation error"; **`setsid` worked**:

```sh
setsid sh -c "printf '%s\n' '<redacted-pw>' | su root -c 'sh /tmp/rc.sh'"
```

- As root, the flag is at **`/host-root/flag.txt`** (the `find` nailed it; it is *not* under
  `/host-root/root/`):

```
THM{…}
```

The flag name describes the box's *intended* root path — a kernel **page-cache write**
container escape via the mounted host block device (`/dev/root`). We took the simpler route the
file-read exposed (leaked root password), which is equally valid for the flag.

## Lab credentials / secrets (lab-only)

- n8n owner cookie forged from: `admin@lab.local` + image-baked bcrypt + JWT secret
  `<redacted-secret>`.
- Root password: `<redacted-pw>` (leaked in `/setup.sh`).

## Lessons

- **"Too trusting about what visitors claim to carry"** = content-type confusion. A server that
  trusts a client-declared `Content-Type`/`filepath` and acts on it is an arbitrary file read.
- **Arbitrary file read is rarely the end** — it leaks the material (JWT secret, DB, creds) to
  forge sessions and pivot to RCE. Read `/proc/self/environ` first; it's the fastest secret dump.
- **Don't trust a PoC's constants.** The public exploit *derived* the JWT secret from the
  encryption key; this lab *set it explicitly* via env var, so only reading `environ` gave the
  right value. Verify the actual config, don't assume.
- **Privesc is looting, not always exploiting** (cf. Beach Bar / Infrastructure): the root
  password was sitting in a readable boot script. Always read `*.sh`, entrypoints, env.
- **Non-interactive `su` needs a PTY**: `setsid` (or `script -c`) + piped password. Same class
  of trick as the Python-pty `su` on the Infrastructure box.
- **Enumerate the real path before guessing.** The prior session burned time `cat`-ing invented
  flag paths; one `find` as root found `/host-root/flag.txt` immediately.
- Chase the obvious bait last: `/chat` (the AI agent) looked like the theme's intended target
  but was deliberately unreachable. The humble upload form was the way in.
