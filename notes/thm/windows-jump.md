# Windows Jump (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Privilege Escalation (the Windows capstone for the module;
  applies the misconfiguration categories from the Linux rooms to Windows - see [[privesc-module-plan]]).
- **Room:** Windows Jump (~60 min, premium). A guest-to-SYSTEM challenge on one Windows host; the stated
  objective is the chain `guest -> thmuser -> notadmin -> svcadmin -> SYSTEM`, four flags.
- **Date:** 2026-10-18.
- **Status:** SOLVED - all four flags.
- **Target:** `<ip>` = host **`PRIVESC`**, Windows Server 2019 (Build 17763), workgroup.
- **Access method:** solved interactively over **RDP** as the foothold user. thmuser is a plain
  non-admin with no WinRM rights (WinRM returns `401`) and no admin-share access, so there is no headless
  exec channel - the box is driven from an RDP desktop. SMB enumeration (guest + thmuser + notadmin) was
  done from the Windows PC with Python **impacket**; the creds were confirmed empirically there.

## Hop 1 - guest -> thmuser (creds in an SMB share)

The Guest account logs in over SMB with a **blank password**. Enumerating shares shows a non-default
`Public` share whose backing folder is `C:\share`; it holds `welcome.txt` with default credentials.

```python
# impacket from the Windows PC
from impacket.smbconnection import SMBConnection
c = SMBConnection('<ip>','<ip>'); c.login('guest','')   # blank password OK
c.listShares()          # ADMIN$, C$, IPC$, Public   (Public is the odd one out)
# read Public\welcome.txt ->
#   Username : thmuser
#   Password : <redacted-pw>
```

- **thmuser : <redacted-pw>** (SMB login confirmed valid from my side).
- **flag1** (`C:\Users\thmuser\Desktop\flag1.txt`): `THM{…}`
- Lesson: always check for **non-default shares** readable by Guest/anonymous - a leaked "default
  credentials" note is a classic foothold.

## Hop 2 - thmuser -> notadmin (AutoLogon password in the registry)

thmuser has no interesting privileges (`whoami /priv` = only `SeChangeNotify`), no saved creds
(`cmdkey /list` = NONE), and `Public`/`C:\share` are read-only. The jump comes from the **Winlogon
AutoAdminLogon** values, which store the auto-logon password in **cleartext**:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
```

- **notadmin : <redacted-pw>** (SMB login confirmed valid from my side; notadmin is **not** a local admin -
  no `C$`/`ADMIN$` - which is why the chain still needs two more hops).
- **flag2**: `THM{…}`
- Gotcha from the session: query the value name exactly (`DefaultPassword`); a typo
  (`DefaultPassowrd`) returns *"unable to find the specified registry key or value"* and looks like the
  key is absent when it is not.

## Hop 3 - notadmin -> svcadmin (insecure service executable)

A non-default service runs as a real user account:

```powershell
Get-WmiObject Win32_Service |
  ? { $_.StartName -notmatch 'LocalSystem|LocalService|NetworkService' } |
  select Name,StartName,PathName | fl
#   Name      : THMSvc
#   StartName : .\svcadmin
#   PathName  : C:\Windows\THMSVC\svc.exe
```

The service binary's file ACL is wide open (confirmed with `icacls`):

```text
C:\Windows\THMSVC\svc.exe   Everyone:(F)        <-- any user can overwrite it
                            PRIVESC\notadmin:(I)(F)
                            BUILTIN\Administrators:(I)(F)
                            NT AUTHORITY\SYSTEM:(I)(F)
```

Because the executable is writable, replace `svc.exe` with a **service-compatible binary that runs a
chosen command** (standard approach: build it on the attacker box and transfer it in, or - if the
service DACL allows - just repoint the binary path), then restart the service so the Service Control
Manager launches it under **svcadmin**:

```cmd
sc stop THMSvc  &  sc start THMSvc
```

Keep the command benign and goal-directed (e.g. drop the svcadmin flag to a readable path, or add the
working user to a group) rather than anything noisy - the point is code execution as svcadmin.

- **flag3**: `THM{…}`
- Lesson: enumerate service binaries with `icacls` / `Get-Acl`. `Everyone`, `Authenticated Users`, or
  `Users` with `(F)`/`(M)`/`(W)` on a service exe (or its folder) = run code as that service's account.
  Restart rights on the service (or a reboot) are what trigger it.

## Hop 4 - svcadmin -> SYSTEM (writable script run by a SYSTEM scheduled task)

As svcadmin, a script executed by a **scheduled task running as SYSTEM** is writable:

- Task action: `C:\Windows\Tasks\cleanup.bat`, principal `NT AUTHORITY\SYSTEM`.
- svcadmin has write access to `cleanup.bat`.

Overwrite the script's contents with the command to run and wait for the task to fire; it executes as
SYSTEM. Use it to read the final flag (which is denied to every lower account):

```cmd
:: cleanup.bat is run by the SYSTEM task; have it surface the SYSTEM-only flag
type C:\flag4.txt > C:\share\out.txt
```

- **flag4** (`C:\flag4.txt`, denied to thmuser/notadmin - confirmed `Access is denied` over SMB and in
  RDP): `THM{…}`
- Lesson: scheduled tasks are the Windows equivalent of the Linux writable-cron vector. Enumerate task
  actions (`schtasks /query /fo LIST /v`, `Get-ScheduledTask`) and check the **principal** and the
  **writability of the file it runs**. A SYSTEM task + a writable target script = SYSTEM.

## What was verified this session (vs. reported)

- **Verified from the Windows PC over SMB:** Guest blank-password login; the `Public` share and
  `welcome.txt`; **thmuser:<redacted-pw>** and **notadmin:<redacted-pw>** both authenticate; neither thmuser nor
  notadmin can reach `C$`/`ADMIN$`; `THMSvc` runs as `.\svcadmin` from `C:\Windows\THMSVC\svc.exe`;
  `Everyone:(F)` on that binary; `C:\flag4.txt` exists and is denied to low-priv users.
- **Reported (solved live in the RDP session, not re-read over SMB here):** the four flag strings, the
  `notadmin` AutoLogon value, and the hop-3/hop-4 executions. The flag files are unreadable to the
  accounts I hold, so their exact strings come from the live session, not an independent read.

## Lessons learned

- **Windows privesc = the same six misconfiguration categories as Linux, different mechanisms.** This
  room hit four in order: credential disclosure (share + registry), insecure service file permissions,
  and a writable SYSTEM scheduled-task script. Compare the Linux equivalents in
  [[linux-privilege-escalation-basics]] (sudo/SUID/caps/cron/NFS).
- **Situational awareness first (just like the Linux rooms).** Each hop was found by enumeration, not
  guessing: shares -> registry autologon -> service accounts + `icacls` -> scheduled-task principals.
- **A non-admin Windows foothold has no free headless channel.** No WinRM (401) and no admin SMB for a
  plain user means RDP is the only exec path - plan to work from the desktop, or escalate to a
  WinRM/admin-capable account first. (Contrast the Linux rooms, all driven by `paramiko` SSH.)
- **Clipboard into a THM AttackBox RDP window is unreliable** (Guacamole -> Kali works, Kali -> the RDP
  window often does not). RDP from the local Windows PC via `mstsc` has native clipboard; in the
  PowerShell console, **right-click pastes** (Ctrl+V frequently does not).
- **AutoLogon stores the password in cleartext** under `...\Winlogon` (`DefaultUserName` /
  `DefaultPassword` / `AutoAdminLogon=1`) - always check it, and spell the value name exactly.

## Flags

| # | Hop | Vector | Flag |
|---|-----|--------|------|
| 1 | guest -> thmuser | creds in Guest-readable SMB share (`welcome.txt`) | `THM{…}` |
| 2 | thmuser -> notadmin | AutoLogon `DefaultPassword` in Winlogon registry | `THM{…}` |
| 3 | notadmin -> svcadmin | insecure service exe (`Everyone:(F)` on `THMSvc`'s `svc.exe`) | `THM{…}` |
| 4 | svcadmin -> SYSTEM | writable `cleanup.bat` run by a SYSTEM scheduled task | `THM{…}` |

## Related

- [[privesc-module-plan]] - module tracker (this is the Windows capstone).
- [[linux-privilege-escalation-basics]] - the Linux misconfiguration vectors (sudo/SUID/caps/cron/NFS).
- [[linux-privilege-escalation-automation]] - automation + public exploits; same "enumerate, then abuse
  a writable thing run by a higher-priv context" idea as hops 3-4 here.
- [[host-server-configuration-reviews]] - the config-review foundation these categories come from.
