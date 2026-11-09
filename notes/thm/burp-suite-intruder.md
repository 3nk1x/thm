# Burp Suite: Intruder (TryHackMe)

- **Path:** Jr Penetration Tester > Burp Suite module (room 3 of 5)
- **Completed:** 2026-10-09 - **Target:** <ip> ("Bastion v1.6", nginx/1.18.0, Flask)
- **Tool:** Burp Suite Community v2026.3.3. Brute-force tasks replicated with Python/requests
  because Community's Intruder is rate-limited; Burp setup noted for each.

Intruder = automated request fuzzing/brute-force. Capture a request, mark positions with §, load
payload sets, pick an attack type, run. Community is rate-limited (slow); real work often uses ffuf/
wfuzz, but the concepts are the same.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Tab to set the Attack type | *(find it yourself)* |
| 3 | Symbol marking a payload position | *(find it yourself)* |
| 4 | Payload-processing rule to append chars | *(find it yourself)* |
| 5 | Attack type: one payload at a time per position | *(find it yourself)* |
| 6 | Sniper, 3 positions, 100-word list, request count | *(find it yourself)* |
| 6 | Payload sets Sniper accepts | *(find it yourself)* |
| 7 | Battering ram, list [admin,Guest], first body | *(find it yourself)* |
| 8 | Max payload sets in Pitchfork | *(find it yourself)* |
| 9 | Cluster bomb 100 x 2 x 30 request count | *(find it yourself)* |
| 10 | Support login valid creds | m.rivera:<redacted-pw> |
| 11 | Best attack type (IDOR fuzz) | *(find it yourself)* |
| 11 | Ticket flag | THM{…} |
| 12 | Admin login valid creds | o.bennett:<redacted-pw> |

## The four attack types (the core of this room)
- Sniper: 1 payload set, one position at a time. Requests = words x positions.
- Battering ram: 1 payload set, same value in ALL positions at once. Requests = words.
- Pitchfork: N sets (max 20), paired in parallel: set1[i] with set2[i]. Requests = shortest set.
- Cluster bomb: N sets (max 20), every combination. Requests = product of set sizes.

## Task 10 - credential stuffing (Pitchfork)
Leaked creds given at http://<ip>:9999/Credentials/BastionHostingCreds.zip
(usernames.txt, passwords.txt, emails.txt, combined.txt; 100 each, usernames are f.lastname).
Pitchfork pairs usernames[i] with passwords[i] -> 100 attempts (credential stuffing, not full
brute-force). POST username+password to /support/login/ (note trailing slash; /support/login 308s).
All 99 fails redirect to /support/login/ (len 236); the one success redirects to /support/ (len 224):
   m.rivera:<redacted-pw>
Burp: capture login POST > Ctrl+I > Pitchfork > positions on username+password only (clear cookie
pos) > load the two lists > Start > sort results by Length > the short one is the hit.

## Task 11 - IDOR (Sniper)
Logged in, tickets live at /support/ticket/<int>. No per-user access control = IDOR: you can read
any ticket. Sniper-fuzz the number 1..100. A handful return 200 (existing tickets); the flag is
in one of them *(find it yourself)*: THM{…}.
Burp: capture a logged-in GET /support/ticket/1 > Intruder > Sniper > position on the number >
Payloads type "Numbers" 1-100 > Start > open the 200s.

## Task 12 - credential stuffing past CSRF + session (Pitchfork + macro)
/admin/login/ sets a fresh `session` cookie and a hidden `loginToken` (CSRF) on every GET, both
change each request, so a plain replay 403s. In Burp you add a Macro (a GET to /admin/login/) and a
Session Handling Rule scoped to Intruder only that runs the macro before each request and updates
just the `loginToken` param and `session` cookie. Replicated as GET-then-POST per attempt. Success:
   o.bennett:<redacted-pw>   (redirects to /admin/, len 220 vs the 232 everyone else gets)

## Lessons
- Credential stuffing > brute-force when you have leaked user:pass pairs (Pitchfork, 1:1), far fewer
  requests than Cluster bomb's every-combination.
- When status codes are identical (all 302), differentiate by RESPONSE LENGTH. Sort by Length, the
  outlier is the win.
- Sequential integer IDs + no access control = IDOR. Fuzz the id, read everyone's data.
- Anti-automation (per-request CSRF token + rotating session) is beaten with a macro that refreshes
  the token before each attempt. It raises the bar, it does not stop a determined attacker.
- Defence: rate-limit/lockout on login, bind CSRF tokens to a server-side session properly, enforce
  per-object authorization (don't trust the id in the URL), and never store plaintext passwords.
