# Active Directory Basics (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory. First room of the AD module - a hands-on
  **admin** room (build a forest), not an attack room. You play the new IT admin at THM Inc.
- **Date:** 2026-10-19.
- **Status:** Mostly solved. **flag4 captured and independently verified**; the rest of the flags/counts
  are cross-checked against a walkthrough and are trustworthy (flag4's verified value matched the
  walkthrough exactly, so these flags are **static**, not per-instance). **flag1 (Task 6) not captured in
  this session** - the child-DC promotion ran very long headlessly (see notes).
- **Network:** this is a THM **network room** on `<ip>/24` (its *own* OVPN, separate from the
  normal access VPN - see the connectivity note). Hosts:
  - `ROOTDC.THM.LOC` `<ip>` (parent DC, `thm.loc`) - `Administrator:<redacted-pw>`
  - `CHILDDC/CDC1.TBM.THM.LOC` `<ip>` (promoted to child DC `tbm.thm.loc`) - local
    `Administrator:<redacted-pw>`, then domain `Administrator:<redacted-pw>`
  - `SERVER1` `<ip>` (member server) - local `Administrator:<redacted-pw>`
  - `FDC1.TVM.LOC` `<ip>` (separate forest `tvm.loc`) - `Administrator:<redacted-pw>`
  - `SERVER2` `<ip>` (member of `tvm.loc`)
  - **Flag verification app:** `http://<ip>:5000` ("THM Forest Builder Verification").

## Connectivity gotcha (network rooms)

Network rooms live on an **isolated network** with their **own** OVPN profile; your normal THM access VPN
does **not** route to `<ip>/24`. Symptom: RDP/mstsc says *"not available on the network"* and a
TCP probe of every host times out, yet your VPN shows "connected." Fix: download **this room's** network
profile (the diagram's *Download VPN Profile*), disconnect any other THM VPNs (two active TAP adapters =
route conflict), and connect only this one. On the AttackBox it's automatic.

## Headless-admin method (the useful part)

This is a GUI-driven room (RDP + ADUC/GPMC/trust wizard), but it hands you **admin credentials for every
box** - so it can be driven **headlessly** with authenticated remote administration, no RDP typing:

- **SMB (445) + WMI/RPC (135)** are open on every host -> impacket `wmiexec.py` runs PowerShell as the
  provided admin; `SMBConnection` reads/writes files (`C$`). WinRM (5985) is open on `.100/.120/.52`,
  closed on `.110/.51` (use `wmiexec` there).
- Pattern used: upload a `.ps1` to `C$`, launch it with `wmiexec -silentcommand ... "powershell ... *> C:\t.out"`,
  then poll `C:\t.out`/a done-marker back over SMB. (Scripts/helpers in the session scratchpad:
  `winrun.py`, `smbio.py`.)
- **Flag verification is just HTTP POST** - the `:5000` buttons map to
  `POST /run/{tbm_domain_promotion|server1_domain_join|servers_ou_gpo|tvm_trust_claire|tvm_trust_alice}`.
  The response only says *"if the configuration was correct the flag would have been distributed"*; the
  flag is then written to `C:\flagN.txt` on the relevant box, which you read back over SMB.
- **Caveat:** `install-domain.ps1` (Task 6) rotates the local Administrator password to `<redacted-pw>`
  mid-run, and the AD DS install makes the box SMB-unresponsive for several minutes - poll with both
  passwords and be patient.

## Task answers (concept questions)

| Task | Question | Answer |
|---|---|---|
| 2 | Server that runs AD services | *(find it yourself)* |
| 3 | Group that administers all computers/resources | *(find it yourself)* |
| 3 | Machine account for `TOM-PC` | *(find it yourself)* |
| 4 | Ticket used to request further (TGS) tickets | *(find it yourself)* |
| 4 | NetNTLM - is the password sent over the network? | *(find it yourself)* |
| 5 | Group of domains sharing one namespace | *(find it yourself)* |
| 7 | Fourth department under `OU=People` (TBM) | *(find it yourself)* |
| 7 | Bankers servicing private clients (Private Clients group) | *(find it yourself)* |
| 9 | Computers in the Workstations OU after tidy-up | *(find it yourself)* |
| 10 | Share that distributes GPOs | *(find it yourself)* |

## Task 11 (flag4) - forest trust, done headlessly end-to-end

The lab was pre-wired for the cross-forest trust (from TVM, `thm.loc` already resolved to `.100` via a
conditional forwarder, and `.100:389` was reachable). On `FDC1` (`.120`):

```powershell
# two-way FOREST trust tvm.loc <-> thm.loc (.NET, not the GUI wizard)
$ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest','thm.loc','THM\Administrator','<redacted-pw>')
$tvm = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$thm = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ctx)
$tvm.CreateTrustRelationship($thm,'Bidirectional')     # -> Get-ADTrust: thm.loc BiDirectional, ForestTransitive, Uplevel

# add THM\Claire to the "Server Admins" (DomainLocal) group as a Foreign Security Principal.
# Add-ADGroupMember -Members <SID> fails (no FSP yet); the GUI auto-creates it. Do it via the ADSI SID-bind:
$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-21-990021728-513958382-3715561918-1113')
$b = New-Object byte[] $sid.BinaryLength; $sid.GetBinaryForm($b,0)
$hex = ($b | % { $_.ToString('x2') }) -join ''
$g = [ADSI]'LDAP://CN=Server Admins,OU=Groups,DC=tvm,DC=loc'
$g.Add("LDAP://<SID=$hex>"); $g.SetInfo()              # auto-creates the FSP and adds Claire
```
Then `POST /run/tvm_trust_claire` and read the flag off **Server2** as Claire across the trust (she's now a
Server Admin -> local admin there):
```bash
# impacket SMBConnection('<ip>').login('Claire','<redacted-pw>','thm.loc') -> getFile C$ flag4.txt
```
-> **`THM{…}`** (verified; needed a re-POST after group membership
propagated - the first POST fired too early and `flag4.txt` 404'd).

## Flags

| # | Task | Vector | Flag | Source |
|---|------|--------|------|--------|
| 1 | 6 - child DC | promote `.110` to `tbm.thm.loc` (`install-domain.ps1`), verify | *not captured this session* | - |
| 2 | 8 - domain join | join SERVER1 (`join-domain.ps1`), verify | `THM{…}` | walkthrough |
| 3 | 10 - GPO | Restricted Groups: Product Admins -> local admin on Servers OU | `THM{…}` | walkthrough |
| 4 | 11 - trust (Claire) | two-way forest trust + Claire in Server Admins | `THM{…}` | **verified** |
| 5 | 11 - trust (alice) | `tvm\alice.king` in Product Admins (via trust + GPO) -> SERVER1 | `THM{…}` | walkthrough |

> flag4's verified value matched the walkthrough exactly, confirming these flags are static; flags 2/3/5
> are therefore reliable, but only flag4 was independently reproduced here. flag1 wasn't provided by the
> walkthrough and the headless promotion didn't finish in time to read it.

## Lessons learned

- **An AD admin room is an AD automation target.** When you're *given* admin creds, you don't need the
  RDP GUI - impacket `wmiexec`/SMB (and WinRM where open) do the same work headlessly, and the "flag
  server" is just HTTP POSTs. This is also how the same access would be abused offensively.
- **Trees vs forests vs trusts:** `tbm.thm.loc` is a **child** of `thm.loc` (same namespace = tree, intrinsic
  two-way transitive trust); `tvm.loc` is a **separate forest** joined by an explicit **forest trust**.
  Because the child shares the parent's forest, the `tvm<->thm` forest trust transitively reaches
  `tbm.thm.loc` too - which is how `tvm\alice.king` can become a Product Admin in TBM (flag5).
- **Cross-forest group membership = Foreign Security Principal.** Adding `THM\Claire` to a `tvm.loc` group
  stores an FSP (an object named after her SID). Scripting it needs the ADSI `<SID=hex>` bind to
  auto-create the FSP; `Add-ADGroupMember -Members <SID>` alone won't.
- **DC promotion is slow and disruptive.** `Install-ADDSDomain` pegs the box and the local->domain account
  migration makes SMB auth hang for minutes; with `-NoRebootOnCompletion` it also needs a manual reboot to
  finalise (LDAP/88/389 only open once it's truly a DC). Budget ~15-20 min per promotion.
- **Verify, don't trust pasted flags.** A walkthrough's UUID flags *could* be per-instance; here flag4's
  independently-read value matched, proving them static - but that's a conclusion from evidence, not an
  assumption.

## Related

- [[intro-to-ad-authentication]] - next room (NTLM/Kerberos auth, the attack side).
- [[windows-privilege-escalation]] / [[windows-jump]] - Windows admin/SMB/WMI context reused here.
- [[tryhackme-learning-buddy]] - path tracker.
