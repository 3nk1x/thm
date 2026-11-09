# Session Management (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities II (room 1)
- **Completed:** 2026-10-10 - **Target:** <ip> (React/Vite SPA :80, backend API :5000)

Session management = creating, tracking, expiring, terminating sessions securely (HTTP is
stateless). The practical flaw here was broken server-side authorization: the API served all data
with no auth check; client-side role (cookie + localStorage) was cosmetic only.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Logout button phase | *(find it yourself)* |
| 2 | Providing credentials phase | *(find it yourself)* |
| 2 | Actions after auth phase | *(find it yourself)* |
| 2 | Forgot to log out phase | *(find it yourself)* |
| 3 | Tracking/logging actions (IAAA) | *(find it yourself)* |
| 3 | Granting a session value (IAAA) | *(find it yourself)* |
| 3 | Verifying permissions (IAAA) | *(find it yourself)* |
| 4 | HTTPS-only cookie attribute | *(find it yourself)* |
| 4 | Header announcing a cookie | *(find it yourself)* |
| 4 | Header carrying a JWT | *(find it yourself)* |
| 5 | Predictable session value | *(find it yourself)* |
| 5 | Can't flush a hijacker | *(find it yourself)* |
| 5 | Not enough incident info | *(find it yourself)* |
| 5 | Leaked via insecure redirect | *(find it yourself)* |
| 6 | Username of student named "X" | THM{…} |
| 6 | Lecturers registered | *(find it yourself)* |
| 6 | Roles excluding unauthenticated | *(find it yourself)* |
| 6 | Total test attempts | *(find it yourself)* |
| 6 | Student1 highest score | *(find it yourself)* |
| 6 | Database Types correct answers (y/n) | *(find it yourself)* |

## Theory recap
- Lifecycle: Creation (login) -> Tracking (each request) -> Expiry (timeout) -> Termination (logout).
- IAAA: Identification (claim identity) / Authentication (prove it) / Authorisation (rights to act)
  / Accountability (logging). authentication != authorisation.
- Cookies: browser auto-sends per domain; attributes Secure (HTTPS only), HttpOnly (no JS read),
  Expire, SameSite (CSRF). Tokens (JWT): client-side JS in LocalStorage, sent as
  Authorization: Bearer; not auto-attached, CSRF-resistant, good for decentralised apps.
- Where it breaks: weak/guessable session values (e.g. base64(username)); controllable tokens
  (unsigned JWT); session fixation (value not rotated after auth); insecure transmission (open
  redirect in SSO); authz bypass (vertical = do a higher-priv action; horizontal = act on another
  user's data); insufficient logging; excessive lifetimes; broken server-side termination.

## Practical - broken object-level authorisation (BOLA)
The app is a React/Vite SPA. The dev server serves the TS source, which reveals the whole API:
- `/src/utils/consts.tsx`: `API_URL = http://<host>:5000/` (backend on port 5000).
- `/src/api/*.ts`: endpoints /students /lecturers /grades /tests/:id/questions /test_attempts/:id
  /superadmin_stats /lecturer_stats, axios withCredentials:true (cookie auth).
The backend endpoints return full data with NO auth/authz check (unauthenticated curl works):
```
curl -s http://<ip>:5000/students          # all students incl id9 name "X" user THM{…}
curl -s http://<ip>:5000/lecturers         # 1 lecturer
curl -s http://<ip>:5000/superadmin_stats  # total_students 4, total_lecturers 1, modules 3, tests 2
curl -s http://<ip>:5000/grades            # 4 attempts (ids 9-12), Student1, grades 0,0,0,3
curl -s http://<ip>:5000/test_attempts/12  # perfect (3/3) attempt -> answer key: correct=true
```
test_attempts/12 (score 3) exposes the correct answers for "database types":
Q10 Is SQL relational? yes(correct) -> y ; Q11 Is MongoDB relational? no(correct) -> n ;
Q12 MongoDB foreign keys? no(correct) -> n => y,n,n.
Client-side role (localStorage userRole student->lecturer, or role 2->3) only changes the UI; the
server never checks it, so it is cosmetic.

## Lessons
- Reading a SPA's served source (Vite dev server) hands you the full API map and base URL - always
  review client JS/TS for endpoints and the backend port.
- Client-side role/session controls are UI only; authorisation MUST be enforced server-side on every
  object (BOLA/IDOR). Here there was not even authentication on the data endpoints.
- authentication != authorisation; a valid session is not permission to access any object.
