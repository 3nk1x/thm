# Burp Suite: Repeater (TryHackMe)

- **Path:** Jr Penetration Tester > Burp Suite module (room 2 of 5)
- **Completed:** 2026-10-09 - **Target:** <ip> ("Bastion Hosting", nginx/1.18.0, Flask)
- **Tool:** Burp Suite Community v2026.3.3 on own Windows PC.

Repeater = take a captured request, edit it, resend it, read the response, repeat. The core loop of
manual web testing. Proxy catches the request, right-click > Send to Repeater (Ctrl+R), iterate there.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Section giving more intuitive control over requests | *(find it yourself)* |
| 3 | View that populates when sending Proxy > Repeater | *(find it yourself)* |
| 4 | Option that visualises the page as a browser would | *(find it yourself)* |
| 5 | Inspector section specific to POST requests | *(find it yourself)* |
| 6 | Flag from adding the FlagAuthorised header | THM{…} |
| 7 | Flag from causing a 500 on the products endpoint | THM{…} |
| 8 | Flag from the Union SQL injection | THM{…} |

## Repeater basics
- Response views: Pretty (default), Raw, Hex, Render (browser view). The \n button shows
  non-printable chars (the \r\n line endings in headers).
- Inspector (far right, also in Proxy): tabular view/edit of Request attributes (method/path/HTTP
  version), Query parameters (GET, in URL), Body parameters (POST), Cookies, Request headers.
  Response headers are read-only and appear only after a response.

## Task 6 - add a header
The homepage returns a flag only if you send a header a browser never would.
1. Capture GET / in Proxy > Send to Repeater.
2. Add a header line: `FlagAuthorised: True`
3. Send. Flag is in the response.
   (Verify with curl: `curl -H "FlagAuthorised: True" http://<ip>/`)

## Task 7 - break it with bad validation (500)
/products/<id> accepts any integer. A non-existent id just 404s (even numbers past the 64-bit
limit), so a merely BIG number is not enough. The gap is that it never rejects a NEGATIVE id, and a
negative breaks the backend lookup -> unhandled 500 with the flag.
- Send `GET /products/-1 HTTP/1.1` -> 500 + flag.
- Observed: /products/1 -> 200, /products/0 -> 404, /products/-1 -> 500,
  /products/<huge> -> 404, /products/abc -> 404.
- Lesson: it validates the TYPE (integer) but not the RANGE/validity. Validate that input is a
  valid, in-range, existing value, not just "is it a number".

## Task 8 - Union SQL injection on /about/<id>
The id is dropped raw into a 5-column SELECT, and the server returns verbose DB errors.
1. Capture GET /about/2 > Send to Repeater.
2. Confirm: path `/about/2'` -> 500. The error even leaks the query:
   `SELECT firstName, lastName, pfpLink, role, bio FROM people WHERE id = 2'` (so, 5 columns).
3. Extract (CEO = id 1, target column = notes):
   `GET /about/0 UNION ALL SELECT notes,null,null,null,null FROM people WHERE id = 1 HTTP/1.1`
   - id 0 so the real query returns nothing and the injected row is what renders.
   - notes + four nulls to match the 5 columns.
   - Flag renders where the person's name/details normally show (Ctrl+F the response for THM{).
- Room pre-did the enumeration; the full manual path would be: find column count (ORDER BY /
  UNION SELECT null,null,...), then column names via
  `group_concat(column_name) FROM information_schema.columns WHERE table_name="people"`
  (columns found: id, firstName, lastName, pfpLink, role, shortRole, bio, notes).

## Lessons
- Repeater is the trial-and-error workbench: one request, many edits, instant response diffing.
  Better than re-submitting through the browser each time.
- Verbose error messages are a gift to an attacker: the 500 handed us the table, the columns, and
  confirmed injectability. Production should log details server-side and return a generic page.
- Input validation must check validity, not just type (negative id -> 500).
- SQLi root cause is unchanged from the SQLi rooms: user input concatenated into a query. Fix =
  parameterised queries / prepared statements.

## Environment note
Target <ip> was reachable on the normal thm Premium VPN (<ip>/12 routes via the DCO
adapter). Manual Repeater requests need the Target set (Host = bare IP, no http:// or path) and a
`Host:` header; easiest is to capture from Proxy and Send to Repeater so both are filled in.
