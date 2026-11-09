# Burp Suite: The Basics (TryHackMe)

- **Path:** Jr Penetration Tester > Burp Suite module (room 1 of 5)
- **Completed:** 2026-10-09 - **Target:** <ip> ("Bastion Hosting", nginx/1.18.0)
- **Tool:** Burp Suite Community v2026.3.3 on own Windows PC, built-in browser.

Mostly theory + the Proxy. Core idea: Burp sits between browser and server and lets you intercept,
read, and change every request and response before it moves on. Everything else is built on that.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Edition that runs on a server, constant scanning | *(find it yourself)* |
| 2 | Burp attacks web applications and ___ applications | *(find it yourself)* |
| 3 | Feature to intercept requests | *(find it yourself)* |
| 3 | Tool to brute-force a login form | *(find it yourself)* |
| 5 | Menu showing Burp actions + connection details | *(find it yourself)* |
| 6 | Tab that Ctrl+Shift+P switches to | *(find it yourself)* |
| 7 | Category with a "Cookie jar" reference | *(find it yourself)* |
| 7 | Base category holding the "Updates" sub-category | *(find it yourself)* |
| 7 | Sub-category to change keybindings | *(find it yourself)* |
| 7 | Can uploaded Client-Side TLS certs be overridden per-project | *(find it yourself)* |
| 10 | Flag from the unusual endpoint | THM{…} |

(Task 10 flag: watch for an `l`-vs-`1` ambiguity — a character that looks like a `1` is actually a
lowercase L; copy it straight from Burp's Response panel to be safe. Tasks 1, 4, 8, 9, 11, 12, 13, 14, 15 need no answer.)

## The six Community tools (one-liners)
- Proxy: intercept/read/edit traffic (the core).
- Repeater: replay one request with tweaks (manual probing).
- Intruder: automate a request with payload lists (brute-force/fuzz; rate-limited in Community).
- Decoder: encode/decode data.
- Comparer: diff two chunks (word or byte).
- Sequencer: test randomness of tokens/session cookies.
- Extender / BApp Store: add-ons (e.g. Logger++).

Nav: top bar = modules, second bar = sub-tabs. Shortcuts: Ctrl+Shift+ D dashboard, T target, P proxy,
I intruder, R repeater. Window > Detach pops a tab into its own window.

## Task 10 - Site map and the hidden endpoint (the real skill)
1. Proxy tab > Intercept sub-tab > make sure "Intercept is off" (so browsing flows).
2. Click "Open Browser" (Burp's built-in Chromium, pre-proxied, cert trusted - zero setup).
3. Browse http://<ip>/ and click every nav link (About, Products, Contact, Support, Privacy).
4. Target tab > Site map > expand http://<ip>.
5. One entry stands out: an unusual path (`/<unusual-endpoint>`) - MIME type "text", no title, unlike the HTML pages.
6. Click it > Response panel > the flag is in the body.

Why it is there: the /ticket/ page's script emailFilter.js runs fetch("/<unusual-endpoint>") in the
background on load. You never clicked it, but Burp logs EVERY request the browser makes, including
silent fetch/XHR calls, so the site map surfaces endpoints a wordlist or clicking would never find.
Confirmed by the request's Referer header: http://<ip>/ticket/.

## Task 12 - Scoping
Target > Site map > right-click the host > Add to scope > Yes (stop logging out-of-scope). Check
under Target > Scope. Then make the proxy obey it: Proxy > Proxy settings > Intercept Client
Requests > tick "And URL Is in target scope". Keeps the traffic view clean.

## Task 13 - Proxying HTTPS
For a manually-proxied normal browser you must trust Burp's CA: browse http://burp/cert to get
cacert.der, then import it into the browser's trusted CAs ("Trust this CA to identify websites").
Not needed with Burp's built-in browser (it already trusts the CA), nor on the AttackBox.

## Task 14 - Example attack: client-side filter bypass -> reflected XSS
The email field has a client-side filter (emailFilter.js) that strips special characters as you type,
so <script> will not go in directly. A client-side filter only runs in the browser; Burp sits after
the browser, so submit clean data and swap the payload in transit.
1. Proxy > Intercept > "Intercept is on".
2. In the Burp browser, /ticket/ > email pentester@example.thm, query "Test Attack" > Submit.
3. Request is caught in Intercept. Replace the email body value with:
   <script>alert("Succ3ssful XSS")</script>
4. Select that payload, press Ctrl+U to URL-encode it, then click Forward.
5. Browser shows the alert "Succ3ssful XSS". Turn Intercept off afterwards.

Lesson that carries forward: client-side validation is a UX convenience, never a security control.
Enforce on the server. Same family as the .phtml upload bypass and "a rule in the prompt is a
suggestion".

## Environment gotchas hit this session (reinforce)
- VPN drops on idle: ping to the box returned "Destination net unreachable" from <ip> and the
  DCO adapter showed "Media disconnected". Fix: reconnect with openvpn-gui --command connect thm, wait
  for a 192.168.180.x IP.
- Burp proxy failed to start: Event log "Failed to start proxy service on 127.0.0.1:8080 - another
  service is already using it". Cause here: NVIDIA Broadcast was holding port 8080. Fixes: free 8080
  (close the other app) and re-tick the listener, or move Burp's listener to 8081 (Proxy settings >
  Proxy listeners > Edit). Diagnose with: netstat -ano | find ":8080" then tasklist for the PID.
- Windows Defender quarantined the Web Server Attacks II note (Backdoor:ASP/Chopper.J) because it
  held a literal web-shell string. Keep offensive examples in notes defanged.
