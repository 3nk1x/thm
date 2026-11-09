# Content Discovery (TryHackMe)

- **Path:** Jr Penetration Tester → Web Application Security Fundamentals
- **Room:** Content Discovery (Acme IT Support)
- **Completed:** 2026-10-07
- **Target:** <ip> (10.49.x, general THM VPN)

Finding content not meant to be public / not linked anywhere: admin panels, backups,
old versions, config/log files. Three approaches: **manual**, **OSINT**, **automated**.

## 1. Manual discovery

| Source | What it gives |
|---|---|
| `/robots.txt` | a *gift list* — owners "hide" sensitive paths here (`Disallow: *(find it yourself)*`). Not a security control; visit the paths directly. |
| `/sitemap.xml` | pages the owner wants indexed — often leaks staging/old/secret paths (*(find it yourself)*) + `id=` params |
| HTTP headers (`curl -v` / `-D -`) | `Server`, `X-Powered-By` (framework), custom headers (`X-FLAG: THM{…}`) |
| favicon | hash it → identify the framework (OWASP favicon DB) |
| framework → its docs | docs reveal default admin path + **default creds**. `/thm-framework-login` + `admin/<redacted-pw>` → flag |

## 2. OSINT (open-source intel)

- **Google dorking:** `site:` (one domain), `inurl:admin`, `filetype:pdf`, `intitle:`, `intext:password`, `cache:`. Combine them.
- **Wappalyzer** — browser extension/site that fingerprints the tech stack (CMS, framework, versions).
- **Wayback Machine** — `https://web.archive.org/` — deleted pages/old endpoints still archived.
- **GitHub** — search company/domain; check **commit history** (secrets removed later still live in history: API keys, `.env`).
- **S3 buckets** — URL format `.s3.amazonaws.com` (e.g. `{company}-backup.s3.amazonaws.com`); misconfigured public buckets leak files.

## 3. Automated — Gobuster (AttackBox/Kali; not on Windows)

```bash
# dir: brute dirs/files
gobuster dir -u http://IP -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
#   -x .php,.txt,.js (extensions)  -s 200,301 (status filter)  -r (follow redirects)  -k (skip TLS)

# dns: brute subdomains (resolved by DNS) — required: -d and -w
gobuster dns -d example.thm -w .../DNS/subdomains-top1million-5000.txt --wildcard
#   -i (show IPs)

# vhost: brute virtual hosts (resolved by web server via Host: header)
gobuster vhost -u http://IP --domain example.thm -w .../subdomains-top1million-5000.txt \
  --append-domain --exclude-length <baseline-size>
```

- **Subdomain vs vhost:** subdomain = **DNS** record → IP. vhost = same IP, server picks the site
  by the **`Host:` header** (no public DNS needed → truly hidden). Favourite exam trap.
- Wordlists: **SecLists** at `/usr/share/wordlists/SecLists/`.

## Gotchas / lessons

- **Read which domain the question targets.** Room text showed a vhost scan on `example.thm`
  (found none) but the question asked about **acmeitsupport.thm** → actually several vhosts *(find it yourself)*. The
  walkthrough's sample output is NOT always the answer.
- Vhost enum without gobuster: `curl -H "Host: sub.domain.thm" http://IP/` and compare response
  size/content to an invalid-host baseline; distinct 200 = real vhost.

## Flags / answers

| Task | Answer |
|---|---|
| robots.txt disallowed dir | *(find it yourself)* |
| sitemap secret area | *(find it yourself)* |
| X-FLAG header | `THM{…}` |
| admin portal (default creds) | `THM{…}` |
| site dork operator | *(find it yourself)* |
| tech-detection tool | *(find it yourself)* |
| Wayback Machine URL | *(find it yourself)* |
| S3 bucket format | *(find it yourself)* |
| `/mo…` directory | *(find it yourself)* |
| log file | *(find it yourself)* |
| dns-mode required flag | *(find it yourself)* |
| vhosts on acmeitsupport.thm returning 200 | *(find it yourself)* |
