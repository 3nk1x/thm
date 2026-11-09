# Broken Authentication (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities II (room 2)
- **Completed:** 2026-10-10 - **Target:** Acme IT Support @ <ip> (driven over VPN)

Four classic auth-bypass techniques: username enumeration, credential brute force, logic flaws in
account recovery, and cookie manipulation.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Reusing creds across unrelated apps | *(find it yourself)* (answer box wants a two-word term; note the room prose instead says "stuffing") |
| 3 | Username starting si*** / st*** / ro**** | *(find it yourself)* |
| 4 | Valid username/password | steve/<redacted-pw> |
| 5 | Flag from Robert's support ticket | THM{…} |
| 6 | Plain-text cookie flag | THM{…} |
| 6 | MD5 <redacted-hash> | *(find it yourself)* |
| 6 | base64 decode *(find it yourself — the string decodes to the flag)* | THM{…} |
| 6 | base64 encode {"id":1,"admin":true} | *(find it yourself)* |

## Task 3 - username enumeration
Signup form /customers/signup leaks existing usernames: a taken username returns a page containing
"Already" (len ~3720); a free one is created (empty/redirect). Enumerate a names list, collect the
"Already" hits. Valid seeded accounts found: *(several — find them yourself)*.
Room questions: si*** / st*** / ro**** -> *(find it yourself)*.
(Original room uses ffuf + a SecLists names wordlist and match on the difference; here replicated
with a Python loop over common first names.)

## Task 4 - brute force login
/customers/login: invalid -> 200 (login re-rendered), valid -> 302 to /customers. Brute the
enumerated usernames x a top-100 password list, filter for 302. Hit: steve/<redacted-pw>.
ffuf form: ffuf -w users:W1,top100:W2 -X POST -d "username=W1&password=W2" -u .../customers/login -fc 200

## Task 5 - logic flaw: parameter pollution in password reset (PHP $_REQUEST)
Two-step reset: step 2 identifies the account from the QUERY STRING `email`, but builds the outbound
email using PHP $_REQUEST (merges GET+POST, POST wins). So a second `email` in the POST BODY overrides
where the reset link is sent, while the identity check still reads robert from the query string.
Acme gives every customer an inbox {username}@customer.acmeitsupport.thm (mail -> support ticket).
Exploit:
1. Register a customer account -> inbox <me>@customer.acmeitsupport.thm.
2. POST /customers/reset?email=robert@acmeitsupport.thm  body: username=robert&email=<me>@customer.acmeitsupport.thm
3. Robert's reset link arrives as a ticket on MY account (e.g. /customers/reset/<token>).
4. Follow the link -> browser is authenticated as Robert.
5. Read Robert's tickets -> THM{…}.
(Full curl: curl 'http://IP/customers/reset?email=robert@acmeitsupport.thm' -d 'username=robert&email=<me>@customer.acmeitsupport.thm')

## Task 6 - cookie manipulation
- Plain text: curl -H "Cookie: logged_in=true; admin=true" http://IP/cookie-test -> Logged In As An
  Admin - THM{…}. (logged_in=true alone = user; both true = admin.)
- Hashed: a hash is not a signature. MD5 <redacted-hash> cracks to *(find it yourself)*
  (6-digit number; cracked by brute since short/predictable; CrackStation would also do it).
- Encoded base64: *(find it yourself)* -> THM{…};
  {"id":1,"admin":true} -> eyJpZCI6MSwiYWRtaW4iOnRydWV9. Edit JSON (admin:true), re-encode, resubmit.

## Lessons
- Username enumeration: return identical responses (body+status+timing) for taken vs free on signup/
  login/reset; add rate limiting + CAPTCHA.
- Brute force: rate limit + lockout + MFA; long passphrases beat short-complex-rotated passwords.
- Logic flaws: every security decision must read its inputs from ONE trusted source. Compose the
  reset email from the DB address tied to the account, not a re-read request value. Avoid $_REQUEST;
  use $_GET/$_POST/$_COOKIE explicitly.
- Cookie tampering: sign cookies (HMAC/JWT) or store state server-side with an opaque session id.
  Hashing a cookie value proves nothing about who issued it.
