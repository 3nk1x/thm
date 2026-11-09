# Intro to AD Lateral Movement (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory (room 7, after
  [[intro-to-credential-harvesting]]).
  **Lateral movement** = reusing valid creds / hashes / tickets to hop host-to-host across the domain -
  "not breaking down doors, walking through them with stolen keys" - until you reach the DC.
- **Date:** 2026-10-21.
- **Status:** SOLVED. **Whole room empirically headless from the Windows PC, no AttackBox** - including the
  pivot. impacket SMB `C$` reads (local-admin + PtH) for WRK/SERVER1, and a **paramiko SSH local
  port-forward** through the WebServer to reach the DC, then PtH to read the final flag. Every flag + hash
  below was read live off the targets.
- **Network:** `<ip>/24` (VPN tun `<ip>`). Lateral chain starts from SSH on the WebServer.

| Host | IP | Role |
|---|---|---|
| WebServer | `<ip>` | compromised Linux host = SSH **pivot point**; hosts internal Gitea (`:80`, not directly reachable) |
| WRK (`WRK1`) | `<ip>` | Windows 10/Server 2019 workstation; `jdoe` is **local admin** |
| SERVER1 | `<ip>` | Windows server; `jdoe` is **Remote Management Users** (not local admin) |
| ROOTDC (`RDC1`) | `<ip>` | Domain Controller `thm.loc` - **not** directly reachable (needs pivot) |

- **Start creds:** SSH to WebServer as `jdoe : <redacted-pw>` (also local admin on WRK, RMU on SERVER1).

## Task answers

| Task | Question | Answer |
|---|---|---|
| 2 | Authenticate with an NTLM hash, no plaintext | *(find it yourself)* |
| 2 | Group (besides Administrators) that permits WinRM | *(find it yourself)* |
| 3 | System-log Event ID that is the primary PsExec indicator | *(find it yourself)* |
| 3 | `flag3a.txt` on WRK | `THM{…}` |
| 3 | NT hash in the WRK loot file | `<redacted-hash>` |
| 3 | `flag3b.txt` on SERVER1 | `THM{…}` |
| 4 | NetExec flag for local-SAM auth | *(find it yourself)* |
| 4 | `flag4.txt` on SERVER1 | `THM{…}` |
| 4 | Domain Administrator NT hash (on SERVER1) | `<redacted-hash>` |
| 5 | Nmap flag to use instead of `-sS` through a SOCKS proxy | *(find it yourself)* |
| 5 | `flag5.txt` on the DC | `THM{…}` |
| 6 | Feature that generates unique local-admin passwords | *(find it yourself)* |
| 6 | System-log Event ID for a new service installed | *(find it yourself)* |

## The three pillars (Task 2)

1. **Remote execution** - run commands on a remote host over legit admin protocols. PsExec (SMB service),
   WinRM (PowerShell over HTTP), WMI/DCOM/SMBExec/AtExec. All need **local admin** on the target *except*
   WinRM, which also accepts **Remote Management Users**.
2. **Credential reuse** - Pass-the-Hash (NTLM hash completes the challenge-response without the password),
   Pass-the-Ticket, Overpass-the-Hash (NT hash -> Kerberos TGT), token impersonation.
3. **Pivoting** - use a dual-homed compromised host as a relay (SSH `-L`/`-D` SOCKS, Chisel, Ligolo-ng) to
   reach segmented subnets you can't touch directly.

**Hash-confusion trap:** only the **NT hash** (32 hex, from SAM/NTDS/LSASS) is pass-the-hashable.
**Net-NTLMv2** (from Responder/coercion, `user::DOMAIN:challenge:hmac:blob`) is **not** - crack or relay it.

## The attack chain (Tasks 3-5)

Compromised WebServer (SSH) -> WRK -> SERVER1 -> DC. Each host hands the key to the next:
**move -> harvest -> move again.**

1. **PsExec to WRK (Task 3).** `jdoe` is local admin on WRK, so PsExec writes a service EXE to `ADMIN$`,
   `CreateServiceW` + `StartServiceW` -> **SYSTEM** shell (Event ID **7045**). flag3a =
   `THM{…}`. SYSTEM let the room read `C:\Users\Administrator\Documents\loot.txt` =
   local Administrator NT hash `<redacted-hash>`.
2. **Evil-WinRM to SERVER1 (Task 3).** `jdoe` is **Remote Management Users** (not admin) on SERVER1, so
   WinRM is the right tool (PsExec would fail - no `ADMIN$`). Runs **as jdoe**, not SYSTEM. flag3b =
   `THM{…}`. `Administrator\Desktop\flag4.txt` -> *Access denied* as jdoe.
3. **Pass-the-Hash to SERVER1 (Task 4).** The WRK local-admin password is **reused** on SERVER1 (no LAPS),
   so the same NT hash authenticates as local Administrator with `--local-auth` -> SYSTEM. flag4 =
   `THM{…}`; `da_creds.txt` = **domain** Administrator NT hash
   `<redacted-hash>` (a DA cred cached where it never should be).
4. **Pivot to the DC (Task 5).** The DC `.100` is unreachable from the attacker net. SSH-tunnel through the
   WebServer (`ssh -D 1080` SOCKS + ProxyChains, or `-L`) and PtH the **domain** Administrator hash to the
   DC's SMB -> SYSTEM on `RDC1`. flag5 = `THM{…}`.

## How I verified it headless from the PC (no AttackBox)

The room teaches `nxc` / `psexec.py` / `evil-winrm` / `ssh -D` + ProxyChains. I reproduced every result
read-only with impacket + paramiko from Windows, since Git-Bash/PC has impacket but no nxc/evil-winrm/
proxychains:

- **WRK** (`wrk.py`): SMB login as `thm.loc/jdoe:<redacted-pw>`; because jdoe is local admin, `C$` reads both
  his own `flag3a.txt` **and** the restricted `Administrator\Documents\loot.txt` - no SYSTEM shell needed.
- **SERVER1** (`server1.py`): **PtH local-auth** - `SMBConnection.login("Administrator","", "",
  lmhash=..., nthash=<redacted-hash>)` (empty domain = authenticate against the box's own SAM, = nxc
  `--local-auth`). Admin `C$` read flag3b (jdoe's own file, which WinRM-as-jdoe reads in-room), flag4, and
  `da_creds.txt`.
- **DC pivot** (`dc_pivot.py`): paramiko SSH to the WebServer as jdoe, a threaded `direct-tcpip` channel
  exposing a **local forward** `127.0.0.1:14450 -> <ip>:445`, then
  `SMBConnection(remoteName="<ip>", remoteHost="127.0.0.1", sess_port=14450)` + PtH the
  **domain** Administrator hash (`login("Administrator","", "thm.loc", nthash=<redacted-hash>)`) -> `C$` read of
  flag5. This is the impacket+paramiko equivalent of `ssh -L` / `ssh -D`+ProxyChains -> `psexec.py -hashes`.

**Observed, not claimed:** the TCP probe confirmed the room's own topology before any attack -
WebServer `:22` open, WebServer `:80` **timeout**, WRK `:445` open, SERVER1 `:445`/`:5985` open, DC `:445`
**timeout** (only reachable after the tunnel came up).

## Mitigations (Task 6)

| Attack we used | Control that stops it |
|---|---|
| PtH off reused local-admin hash | **Windows LAPS** - unique rotated local-admin password per host |
| PsExec/WMI/DCOM need local admin | least privilege + **tiered admin** (T0/T1/T2 don't cross) |
| PtH / relay over SMB | **SMB signing** (always), **Restrict NTLM** (Deny/Audit), **Credential Guard** (VBS isolates LSASS) |
| Workstation-to-workstation exec | **host firewall** - block inbound 445/5985/3389 between workstations |
| Pivot reached every host inc. DC | **network segmentation** - DCs on a hardened subnet, mgmt jump hosts only |
| DA hash cached on SERVER1 | **PAWs** - Tier-0 creds never touch daily-driver/servers |
| detection | Event IDs **4624 T3/T10**, **4648**, **7045/4697** (PsExec), **4698** (AtExec), **4688** + Sysmon 1/10 |

## Lessons learned

- **Local admin != Domain Admin, until it is.** jdoe's local-admin on WRK was "low value" - but it exposed
  a local-admin hash reused on SERVER1, which cached a **Domain Admin** hash. Three hops, zero exploits.
- **Pick the tool to the access level.** Local admin -> PsExec (SYSTEM, but noisy: file + service + 7045).
  Only RMU -> Evil-WinRM (runs as the user, quiet: just 4624 T3). Reading the required group saves a failed,
  loud PsExec attempt.
- **PtH needs the right hash and the right scope.** `--local-auth` (empty domain in impacket) for a **local**
  SAM hash; domain auth for a **domain** account. Mixing them up is the usual PtH failure.
- **DCC2 would not have worked here; NT hashes did.** Unlike [[intro-to-credential-harvesting]] (cached DCC2
  = crack-only), this room hands raw **NT** hashes from SAM/secretsdump format - directly pass-the-hashable.
- **Pivoting is just routing.** `ssh -L` = one fixed pipe; `ssh -D` = SOCKS for everything. Through a SOCKS
  proxy, Nmap must use `-sT -Pn` (no raw sockets / ICMP) and ProxyChains drops UDP/ICMP. paramiko's
  `direct-tcpip` is the same idea in code - and enough to carry SMB to an otherwise-dead DC.
- **This one *was* headless from the PC** - unlike breaching/cred-harvesting (Defender-quarantined
  mimikatz/kerberos, no hashcat). Lateral movement is pure auth-material reuse, which impacket + paramiko
  do natively on Windows.

## Related

- [[intro-to-credential-harvesting]] - where the hashes come from (LSASS/SAM/LSA/NTDS); this room reuses them.
- [[intro-to-ad-authentication]] - NTLM challenge-response + Kerberos tickets that PtH/PtT/OPtH abuse.
- [[intro-to-ad-breaching]] - earlier pivot-ish room; same `thm.loc` lab family, reach web vhosts via tunnel.
- [[ad-module-plan]] / [[tryhackme-learning-buddy]] - module trackers.
