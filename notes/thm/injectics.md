# Injectics (TryHackMe)

Room: Injectics — Web Application Pentesting / Injection Attacks (challenge room). A Laravel-less PHP
leaderboard app on MySQL; the login endpoint has a SQLi behind a weak keyword-stripping filter.
Completed: 2026-11-09 | Target: <ip> (`injecticsv1.79-badr`). Driven **headless from `C:\CTF`**
with `curl` + Python stdlib (flag-2 filename supplied by Valentino — see note).

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | Flag after logging into the admin panel | `THM{…}` |
| 2 | Content of the hidden text file in the flags folder | `THM{…}` |

## Recon

- `GET /` leaderboard; `login.php` (JS → `functions.php`, `function=login`), **`adminLogin007.php`**
  (admin panel), `dashboard.php`, `edit_leaderboard.php`, `conn.php`, `vendor/` (Composer).
- HTML comments on the homepage:
  `<!-- Website developed by John Tim - dev@injectics.thm-->` and
  **`<!-- Mails are stored in mail.log file-->`**.
- `GET /mail.log` leaks the "Injectics" service note + **default** creds restored if the `users`
  table is dropped: `superadmin@injectics.thm:<redacted-pw>`, `dev@injectics.thm:<redacted-pw>`
  (these are *defaults*; the live passwords had been changed, so they don't log in directly).

## The login filter (client + server)

`script.js` blocks `['or','and','union','select','"',"'"]` **client-side only** — bypassed by POSTing
to `functions.php` directly. The *server* also filters, but only as a single-pass `str_replace` that
strips `or`/`and`/`union` **as substrings anywhere** (not `select`, which passes untouched). Key
findings from probing:

- `or` is stripped → double it: `oorr` → `or`. (`' OR 1=1` fails; `'oorr(1=1)` works.)
- Same for `union` (`ununionion`→`union`) and `and` (`aandnd`→`and`).
- `select` is **not** filtered — plain `select` works; doubling it (`seselectlect`) *breaks* it.
- Because the strip is substring-wide, it also mangles identifiers: `passw`**`or`**`d` → `passwd`,
  `inf`**`or`**`mation` → `infmation`. Fix: double the `or` inside them (`passwoorrd`,
  `infoorrmation_schema`), or use hex literals for string values (`0x...`) so no keyword text appears.

Injection confirmed by time-based test (`username=x'oorr(sleep(3))-- -` → 6 s). **Single query only**
(no stacked queries — `x';select sleep(3)` shows no delay).

## Flag 1 — UNION dump → real creds → admin panel

Login query is `SELECT * FROM users WHERE email='$u' AND password='$p'` (6 columns: `email, fname,
lname, password, reset_token, auth`). The JSON response reflects `first_name`(col2)/`last_name`(col3):

```
username = x'ununionion select 1,2,3,4,5,6-- -     # 6-col UNION; col2/col3 reflected
```

Dump credentials (double `or` inside `password`):

```
x'ununionion select 1,(select group_concat(email,0x3a,passwoorrd,0x3a,auth,0x0a) from users),3,4,5,6-- -
-> dev@injectics.thm:<redacted-pw>:1
   superadmin@injectics.thm:<redacted-pw>:0
```

`adminLogin007.php` (itself **not** injectable) with either real credential →
**`THM{…}`**. (Alt intended path: SQLi-drop the `users` table so the service
restores the known *default* creds — same result, but no DROP was possible here without stacking.)

## Flag 2 — hidden file `/var/www/html/flags/<md5>.txt`

`/flags/` exists (403, `-Indexes`); files inside return 200 if present, so the content is one
`GET /flags/<name>` away — but the filename is a random md5:

```
GET /flags/<redacted-hash>.txt  ->  THM{…}
```

**How the filename is *meant* to be found — and why it wasn't, here.** The intended route is
SQLi → MySQL `root@localhost` → write a PHP webshell to the webroot with `INTO OUTFILE`, then
`ls flags/`. On this instance that was blocked:

- `@@secure_file_priv = /var/lib/mysql-files/` → `LOAD_FILE`/`OUTFILE` restricted to that dir
  (webroot read/write both fail; `/etc/passwd` → `NULL`). Writing to `/var/lib/mysql-files/` works and
  reads back via `LOAD_FILE`, but it isn't web-served (no Apache alias — `/flags/`, `/files/` … all 404).
- No stacked queries → the `general_log`-to-webshell trick (`SET GLOBAL general_log_file=...`) is
  unreachable (needs `SET`, not a `SELECT`).
- `root@localhost` = `mysql_native_password` `*<redacted-hash>` — not in
  rockyou, so no phpMyAdmin pivot (would give multi-query). Dashboard re-query is parameterised; no
  LFI; Twig 2.14.0 is a dependency but never reaches user input (leaderboard ints are validated,
  `fname` is re-queried, not reflected from the UNION).

So on this box the md5 filename is only obtainable with working `INTO OUTFILE`/RCE, which
`secure_file_priv` denies. **Valentino supplied the filename** (`<redacted-hash>.txt`)
and the flag fell to a plain HTTP GET. Worth retrying the OUTFILE webshell on a fresh instance where
`secure_file_priv` is empty.

## Lessons

- **A client-side keyword blocklist is not a control.** The real filter was a single-pass
  substring `str_replace`; doubling the keyword (`oorr`, `ununionion`) reconstructs it after one
  removal. Always check whether the filter is recursive (it wasn't — `oorr`→`or`, not `→''`).
- **Substring filters corrupt your own payload's identifiers.** `password`→`passwd`,
  `information`→`infmation`. Double the inner keyword or switch string args to hex (`0x...`) so the
  filter sees no keyword text at all — hex also dodges nested-quote problems in UNION columns.
- **Reflected response fields = a UNION exfil channel.** The login JSON echoing `first_name`/
  `last_name` turned a boolean login into a full 6-column `SELECT *` read of the DB as `root`.
- **`secure_file_priv` is the difference between SQLi-root and RCE.** With FILE priv but
  `secure_file_priv` set and no stacked queries, you can read the whole DB yet never touch the
  webroot — so a random-named flag file stays out of reach. Enumerate `@@secure_file_priv`,
  `current_user()`, and stacked-query support early to know which escalations are even on the table.
- **Headless pattern** (cf. [[ldap-injection]], [[orm-injection]], [[server-side-template-injection]]):
  `curl --data-urlencode` for the filter-bypass login, a Python `http.client` + `group_concat` UNION
  harness for schema/data exfil, timing probes for stacked/injectable detection — all from `C:\CTF`.
