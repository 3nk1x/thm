# AD: Authenticated Enumeration (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory (room 5, after [[ad-basic-enumeration]]).
  **Authenticated Enumeration** = what you do *once you hold a valid domain account*: AS-REP roast for
  more creds, map users/groups/privs/sessions with LOTL `net`/PowerShell, and graph the whole domain with
  BloodHound/PowerView to find attack paths.
- **Date:** 2026-10-20.
- **Status:** SOLVED - every answer verified headless from the Windows PC: SSH into WRK as the given
  account for the `net`/AD-module/PowerView counts, plus an authenticated LDAP bind to the DC for DNs,
  group members and the roast flag. No AttackBox needed.
- **Network:** `<ip>/24` (own OVPN `Jr-Pentester-AD-v01-BH`; my tun IP `<ip>`).
  - `DC.tryhackme.loc` `<ip>` - DC/DNS/KDC (LDAP 389, SMB 445).
  - `WRK.tryhackme.loc` `<ip>` - workstation, **OpenSSH open (22)**; AD module + PowerSploit staged
    in `C:\Users\asrepuser1\Downloads\PowerSploit-master`.
  - `<ip>:8080` - BloodHound-CE web UI (`admin` / `<redacted-pw>`).
- **Given creds:** domain user `tryhackme.loc\asrepuser1` : `<redacted-pw>` (SSH to WRK). Same domain
  `tryhackme.loc` as [[ad-basic-enumeration]] but a *separate* network/instance.

## Task answers

| Task | Question | Answer |
|---|---|---|
| 2 | Flag making an account AS-REP roastable | *(find it yourself)* |
| 2 | Tool that auto-finds roastable users (no userlist) | *(find it yourself)* |
| 2 | Hashcat mode for AS-REP hashes | *(find it yourself)* |
| 2 | Password of asrepuser1 | `<redacted-pw>` |
| 3 | Domain user accounts | *(find it yourself)* |
| 3 | rduke's full name | *(find it yourself)* |
| 3 | Local user accounts on WRK | *(find it yourself)* |
| 3 | Domain groups | *(find it yourself)* |
| 4 | distinguishedName of asrepuser1 | *(find it yourself)* |
| 4 | Users in Domain Admins ("All Domain Admins" query) | *(find it yourself)* |
| 4 | Edge between DRGONZ0 and DOMAIN ADMINS | *(find it yourself)* |
| 5 | Computer accounts | *(find it yourself)* |
| 5 | Groups `Get-DomainGroup "*admin*"` returns | *(find it yourself)* |

## How each was done

**Task 2 - AS-REP Roasting (concept + the one roastable account).** The flag is
`UF_DONT_REQUIRE_PREAUTH` ("Do not require Kerberos preauthentication"): with pre-auth off, the KDC hands
out an AS-REP encrypted with the user's key to *anyone* who asks, so it cracks offline (`hashcat -m 18200`,
mode **18200**). `Rubeus.exe asreproast` finds roastable accounts on Windows with no userlist; impacket's
`GetNPUsers.py` is the cross-platform equivalent (needs a users file). asrepuser1's password is
**`<redacted-pw>`** - proven directly by the SSH login succeeding, and LDAP shows its
`userAccountControl = 4260352 = 0x410200` which includes `0x400000` (DONT_REQ_PREAUTH) + `0x10000`
(pw-never-expires) + `0x200` (normal) - i.e. it really is the roastable account.

**Task 3 - manual / LOTL enumeration (SSH to WRK as asrepuser1).** Ran the native commands the room
teaches and counted the live output:
```text
net user /domain         -> *(find it yourself)* domain user accounts
net user                 -> *(find it yourself)* local accounts on WRK (Administrator, DefaultAccount,
                            Guest, sshd, WDAGUtilityAccount)
net user rduke /domain   -> Full Name = *(find it yourself)*
net group /domain        -> *(find it yourself)* domain groups
```
Cross-checked the domain-user count against authenticated LDAP (`(&(objectClass=user)(objectCategory=
person))`) = **(find it yourself)**, same as `net`. (The room's Task-4 text quotes bloodhound-python "Found 32 users" from
a stale example run; the live box count agrees via both `net` and LDAP.) The domain groups are the
*global-scope* groups `net group /domain` lists (Domain Admins, Enterprise Admins, Tier 0/1/2 Admins,
Server Admins, HR Share RW, Internet Access, ... ), not the 58 BloodHound counts (which includes BUILTIN
local groups).

**Task 4 - BloodHound facts (answered via authenticated LDAP - same data the graph is built from).**
- asrepuser1 DN = *(find it yourself)*.
- Domain Admins (`samaccountname=Domain Admins`) has **5 direct members**:
  `Administrator`, `drgonz0`, `empanadal0v3r`, `Strategos` (users) **+ the nested group `Tier 0 Admins`**.
  `Tier 0 Admins` is **empty** (0 members), so the distinct *users* that are Domain Admins = **(find it yourself)**.
- `drgonz0` is a *direct* member of Domain Admins (its DN is in the `member` list, and
  `Get-ADPrincipalGroupMembership drgonz0` returns Domain Users / Administrators / Domain Admins), so the
  BloodHound edge DRGONZ0 -> DOMAIN ADMINS is **`*(find it yourself)*`**.
```python
# impacket authenticated bind, then plain LDAP searches
ld = ldap.LDAPConnection("ldap://<ip>", "DC=tryhackme,DC=loc")
ld.login(user="asrepuser1", password="<redacted-pw>", domain="tryhackme.loc")
ld.search(searchFilter="(samaccountname=Domain Admins)", attributes=["member"])
```

**Task 5 - ActiveDirectory module + PowerView (PowerShell over the same SSH).**
```powershell
Import-Module ActiveDirectory
(Get-ADComputer -Filter *).Count                    # *(find it yourself)*  -> DC, WRK
Get-ADGroup -Filter {Name -like '*admin*'}          # *(find it yourself)* groups
# PowerView (PowerSploit\Recon\PowerView.ps1) agreed exactly:
Get-DomainGroup '*admin*'                            # *(find it yourself)*
```
The admin-named groups: Administrators, Hyper-V Administrators, Storage Replica Administrators, Schema
Admins, Enterprise Admins, Domain Admins, Key Admins, Enterprise Key Admins, DnsAdmins, Tier 0/1/2 Admins,
Server Admins.

## Lessons learned

- **An authenticated account turns the DC into an open book.** As a plain domain user you can read nearly
  the whole directory over LDAP - every user, group, membership, DN, and `userAccountControl`. That is
  normal AD behaviour, not a misconfig; it's why BloodHound exists and why tiering matters.
- **"Defenders think in lists, attackers think in graphs."** The flat `net` output says Domain Admins has
  5 "members", but the graph shows the distinct *users* + an (empty, here) nested `Tier 0 Admins` group - nesting is
  exactly what list-based review misses. Always resolve nested groups when counting effective admins.
- **Read the `userAccountControl` bits.** `0x400000` = DONT_REQ_PREAUTH (AS-REP roastable), `0x10000` =
  pw-never-expires, `0x80` = reversible encryption, `0x2` = disabled. One integer tells you which accounts
  are low-hanging fruit. asrepuser1 = `0x410200` flagged it as the planted roast target.
- **Pick the tool whose output the grader quotes.** `net user /domain` (users), `net group /domain`
  (global groups), `net user` (local) each count a *different* population than BloodHound's LDAP totals -
  *(find it yourself)* users / *(find it yourself)* groups vs BloodHound's 32 / 58. Counting with the taught command avoids off-by-N answers;
  I still verified against LDAP to be sure (both agreed).
- **SSH + paramiko = a clean headless Windows shell** for `net`/`powershell`/PowerView without RDP. The
  `Import-Module : Access is denied ... console output buffer` stderr over non-interactive SSH is benign -
  stdout still carries the real results.
- **LOTL privileges cheat-sheet** (from `whoami /all`): `SeImpersonatePrivilege`/
  `SeAssignPrimaryTokenPrivilege` -> potato/token attacks; `SeBackupPrivilege` -> read SAM/SYSTEM;
  `SeRestorePrivilege` -> write any file/key; `SeDebugPrivilege` -> LSASS dump.

## Related

- [[ad-basic-enumeration]] - the *unauth* half (SMB null session, SAMR, anonymous LDAP) in the same domain;
  this room is the authenticated continuation.
- [[intro-to-ad-authentication]] - Kerberos/AS-REP internals behind the roast.
- [[ad-module-plan]] / [[tryhackme-learning-buddy]] - module trackers.
