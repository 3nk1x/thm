# Web Server Attacks - I (TryHackMe)

- **Path:** Jr Penetration Tester → Web Application Security Fundamentals
- **Room:** Web Server Attacks - I (recon / misconfiguration identification)
- **Completed:** 2026-10-07
- **Target:** <ip> — one VM, 4 servers: Apache :80, Python :8000, Node/Express :3000, Nginx :8080

Recon & misconfig ID across the dominant Linux web servers. No exploitation — the skill is
knowing *what is exposed and why it matters*. Core idea: **defaults are permissive; security
requires deliberate configuration.**

## Fingerprinting (headers + error pages)

| Port | Server | `Server` header | Framework tell |
|---|---|---|---|
| 80 | Apache2 | `Apache/2.4.x (Ubuntu)` | version in 404 footer too |
| 8000 | Python HTTP | `SimpleHTTP/0.6 Python/3.12.3` | plain-text responses |
| 3000 | Node/Express | *(none)* | `X-Powered-By: Express` |
| 8080 | Nginx | `nginx/1.24.x (Ubuntu)` | version in 404 footer |

`curl -sI http://IP:PORT` (headers) · `curl -s http://IP:PORT/nonexistent` (default error page).
Apache = `ServerTokens OS`; Nginx = `server_tokens on` (both default to leaking version).

## The four recurring misconfigs

1. **Version disclosure** — `Server` / `X-Powered-By` → exact software/version → CVE lookup.
2. **Directory listing**
   - Python HTTP: serves the *whole* working dir incl. **dotfiles** (`.env`!) — zero access control.
   - Apache: `Options +Indexes` → `/files/` "Index of" page.
   - Nginx: `autoindex on` in a location block → "Index of /files/".
3. **Status / debug endpoints**
   - Apache: `/server-status` (mod_status; exposed when `Require all granted` overrides `Require local`).
   - Nginx: `/nginx_status` (stub_status; `allow all` instead of localhost).
   - Node: `/api/debug/env` (dumps `process.env` → DB_PASSWORD), `/api/routes` (lists all routes),
     verbose stack traces from custom error handlers, `NODE_ENV=development` on prod.
4. **Missing security headers** (all 4, by default): `X-Frame-Options` (clickjacking),
   `X-Content-Type-Options: nosniff` (MIME sniffing), `Content-Security-Policy`,
   `Referrer-Policy`, `Strict-Transport-Security` (HTTPS only).
   Audit: `for p in 80 8000 3000 8080; do curl -sI http://IP:$p/ | grep -iE "x-frame|x-content|content-security|referrer|strict-transport"; done`

## Tools

- **Gobuster** finds unlinked files: `gobuster dir -u http://IP:80 -w .../common.txt -x bak,txt,html`
  (`.bak` backups + `.htpasswd` = jackpot).
- **Nikto**: `nikto -h http://IP:80 -nointeractive` — flags server-status, dir indexing, backup files,
  missing headers. Reports "Directory indexing found" for exposed listings.

## Loot found (why each matters)

- Python `.env` → `DATABASE_URL=postgresql://webapp:<redacted-pw>@localhost/production` (real DB creds).
- Node `/api/debug/env` → `DB_PASSWORD: <redacted-pw>`, `NODE_ENV: development` (unhardened).
- Node `config.js` static file → flag in a comment ("meant to be public" ≠ "safe to expose").
- Backup archives in served dirs (`backup.zip`, `old-backup.tar.gz`) + Apache `backup.bak`.

## Flags / answers

| Task | Answer |
|---|---|
| Python Server header | *(find it yourself)* |
| port 3000 framework header | *(find it yourself)* |
| port 8080 server | *(find it yourself)* |
| .env DB password | `<redacted-pw>` |
| Python backup flag | `THM{…}` |
| Apache status module | *(find it yourself)* |
| Apache /files/ flag | `THM{…}` |
| Node NODE_ENV | *(find it yourself)* |
| Node static flag | `THM{…}` |
| Nginx listing directive | *(find it yourself)* |
| Nginx stats path | *(find it yourself)* |
| Nginx /files/ flag | `THM{…}` |
| iframe/clickjacking header | *(find it yourself)* |
| Nikto dir-indexing text | *(find it yourself)* |
