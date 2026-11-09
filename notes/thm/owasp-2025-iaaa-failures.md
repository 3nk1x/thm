# OWASP Top 10 2025: IAAA Failures (TryHackMe)

- **Path:** Jr Penetration Tester - module "OWASP Top 10 (2025)".
- **Room:** OWASP Top 10 2025: IAAA Failures (beginner, ~30 min).
- **Date:** 2026-10-13.
- **Status:** PARTIAL. Theory tasks (2, 3 Q1) and the A09 log investigation (Task 5) solved
  and verified from pasted evidence. Two live-site flags (Task 3 Q2, Task 4) not yet captured;
  reproduction steps recorded below so they can be grabbed on the running boxes.
- **Scope:** three of the OWASP Top 10 2025 categories, each a failure of one IAAA layer:
  A01 Broken Access Control, A07 Authentication Failures, A09 Logging & Alerting Failures.

## Flags and answers

| Task | Question | Answer | Source |
|---|---|---|---|
| 2 | What does IAAA stand for? | *(find it yourself)* | theory |
| 3 | Privilege escalation type (view other user's data, no new roles) | *(find it yourself)* | theory |
| 3 | Note on the >$1M account | `THM{…}` - NOT YET CAPTURED | live site |
| 4 | Flag on admin dashboard | `THM{…}` - NOT YET CAPTURED | live site |
| 5 | Attacker IP (brute force) | `<ip>` | log |
| 5 | Compromised username | *(find it yourself)* | log |
| 5 | Endpoint the attacker accessed | *(find it yourself)* | log |

## IAAA (Task 2)

A layered model for verifying users and their actions; you cannot skip a level, and each one
depends on the one before it.

- **Identity** - the unique account (user ID / email) representing a person or service.
- **Authentication** - proving that identity (passwords, OTP, passkeys).
- **Authorisation** - what that identity is allowed to do.
- **Accountability** - recording and alerting on who did what, when, and from where.

The three categories below each map to a broken layer: A01 breaks authorisation, A07 breaks
authentication, A09 breaks accountability.

## A01: Broken Access Control (Task 3)

The server fails to enforce *who can access what* on every request, because it trusts the client
too much. Classic form is IDOR: if changing an identifier in the request (`?id=7` -> `?id=6`) lets
you read or edit another record, access control is broken.

- **Horizontal** privilege escalation: same role, another user's data.
- **Vertical** privilege escalation: jumping to higher-privilege (admin-only) actions.

The Task 3 question describes seeing another user's data with no new roles gained, so the answer
is `horizontal`.

### Reproduce (note flag, Task 3 Q2)

1. Start the static site on Task 3 and click **View Site**.
2. Find the `accountID` parameter in the URL.
3. Increment it (`?accountID=1`, `2`, `3`, ...) and watch the balance field on each page.
4. On the account showing a balance over $1,000,000, read the note displayed - that is the flag
   (`THM{…}`).

See also local notes: [idor](idor.md), and the deeper THM rooms Broken Access Control and
Insecure Direct Object References linked from the task.

## A07: Authentication Failures (Task 4)

The app cannot reliably verify or bind a user's identity. Common weaknesses: username enumeration,
weak/guessable passwords with no lockout or rate limiting, logic flaws in the login/registration
flow, and insecure session or cookie handling.

### Reproduce (admin dashboard flag, Task 4)

1. Start the static site on Task 4. The real admin username is `admin`.
2. Register a new account as `aDmiN` (mixed case).
3. The registration flow normalises or matches the username inconsistently with how the record is
   stored, so the new `aDmiN` account resolves to the existing `admin` account (a case-collision /
   username-normalisation logic flaw).
4. Log in with the new credentials; the flag is on the admin dashboard
   (`THM{…}`).

**Hypothesis note:** the exact mechanism (case-insensitive match on login vs. case-sensitive
uniqueness check on registration) is inferred from the task wording, not yet confirmed against the
live app behaviour. Confirm when capturing the flag.

See also local note: [broken-authentication](broken-authentication.md).

## A09: Logging & Alerting Failures (Task 5)

When an app does not record or alert on security-relevant events, defenders cannot detect or
investigate attacks. Logging underpins accountability: proving who did what, when, and from where.
Failures look like missing auth events, vague errors, no alerting on brute force or privilege
changes, short retention, or logs an attacker can tamper with.

### Investigation (observed)

Evidence: SIEM dashboard for `bank.thm`, 40 logs, 2026-01-15 session (log timestamps dated
2025-01-15 in the exercise data).

A single source IP `<ip>` produced a tight burst of failed `POST /login` attempts against
`user=admin`, then one success, then an immediate sensitive GET:

```
08:42:09  401  <ip>  POST /login?user=admin&pass=admin123
08:42:13  401  <ip>  POST /login?user=admin&pass=password
08:42:17  401  <ip>  POST /login?user=admin&pass=12345
08:42:21  401  <ip>  POST /login?user=admin&pass=letmein
08:42:25  401  <ip>  POST /login?user=admin&pass=qwerty
08:42:29  200  <ip>  POST /login?user=admin&pass=<redacted-pw>   <- break-in
08:42:31  200  <ip>  GET  /supersecretadminstuff               <- action
```

- **Attacker IP:** `<ip>`
- **Compromised account:** *(find it yourself)*
- **Endpoint accessed after compromise:** *(find it yourself)*

The tell is five-plus failures from one IP within seconds, followed by a success from the same IP.
The other `401`s in the log (`john`, `sarah`, `robert`, `emily`) are single isolated failures from
different IPs, consistent with normal mistyped logins rather than an attack.

## Lessons learned

- IAAA gives a clean mental map of the OWASP 2025 categories: each failure is a broken layer
  (authorisation / authentication / accountability).
- Horizontal vs. vertical privilege escalation turns on whether you gain a new role or just reach
  another user's data at the same role.
- IDOR is the canonical A01 demo: increment an object identifier and watch for data you should not
  see.
- Username case-collision at registration is a concrete A07 logic flaw; it works when login
  matching and registration uniqueness use different normalisation.
- Brute force in logs is identified by rate and sequence from one source, not by a lone 401; the
  event right after the first 200 is usually the attacker's real objective.
- The OWASP Top 10 2025 renumbered and regrouped the older list; A01 Broken Access Control stays at
  the top, A07 covers authentication failures, A09 covers logging/alerting.

## Outstanding

- Capture Task 3 Q2 note flag from the >$1M account (steps above).
- Capture Task 4 admin dashboard flag via the `aDmiN` registration (steps above); confirm the
  normalisation mechanism while doing so.
- Completing this room plus one more secures the Gold League spot (2 rooms/quizzes needed).
