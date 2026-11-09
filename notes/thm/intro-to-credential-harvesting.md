# Intro to Credential Harvesting (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory (room 6, after [[ad-authenticated-enumeration]]).
  **Credential harvesting** = pulling secrets out of where Windows already keeps them, then reusing them to
  climb to Domain Admin - no exploits, just loot-and-reuse.
- **Date:** 2026-10-20.
- **Status:** SOLVED. Mixed verification:
  - **Empirically confirmed headless from the PC (impacket):** `secretsdump` against WRK dumped the local
    SAM + cached **DCC2** hashes (drgonzo = `$DCC2$10240#drgonzo#<redacted-hash>`);
    drgonzo's crack `<redacted-pw>` was verified **offline** by recomputing DCC2 (recompute == dumped hash);
    and a read-only **DCSync** as `drgonzo` (`secretsdump -just-dc`) returned the domain **Administrator
    NT hash `<redacted-hash>`** exactly. The WRK LSA-secrets dump had **no** `_SC_`
    service-plaintext for svc-app, confirming svc-app's plaintext lives only in live LSASS.
  - **AttackBox / user-confirmed:** the DPAPI vault + live-LSASS plaintexts (ElonTusk gmail, svc-app) need
    **mimikatz** on WRK (Defender quarantines it on the host), and the DCC2 crack itself needs
    **hashcat/john + rockyou** (not on the PC) - same host-tooling gap as [[intro-to-ad-breaching]]. The
    final flag was read on the AttackBox via `psexec` PtH as Administrator.
- **Network:** `<ip>/24`. `WRK` `<ip>` (domain-joined workstation, Defender disabled for the
  exercise), `DC` `<ip>` (`tryhackme.loc`).
- **Start creds:** local Administrator on WRK `WRK\Administrator : <redacted-pw>` (RDP).

## Task answers

| Task | Question | Answer |
|---|---|---|
| 2 | Component holding live NTLM/Kerberos creds in memory | *(find it yourself)* |
| 2 | AD database file in `C:\Windows\NTDS\` | *(find it yourself)* |
| 2 | Mimikatz command to export DPAPI Vault creds | *(find it yourself)* |
| 3 | Elon Tusk's Gmail password | `<redacted-pw>` |
| 3 | svc-app's password | `<redacted-pw>` |
| 4 | drgonzo's (cracked) password | `<redacted-pw>` |
| 4 | Domain Administrator NTLM hash | `<redacted-hash>` |
| 4 | Flag on the domain admin's Desktop | `THM{…}` |

## The credential stores (Task 2)

| Store | Holds | Access | Tool |
|---|---|---|---|
| **LSASS memory** | live NTLM/SHA1 hashes, Kerberos tickets, sometimes plaintext | dump `lsass.exe` (SYSTEM) | `sekurlsa::logonpasswords` |
| **SAM + SYSTEM hives** | local account NT hashes (SYSTEM = BootKey decrypts SAM) | reg save / VSS / offline | `lsadump::sam`, `secretsdump` |
| **LSA Secrets** | cached domain creds (MSCacheV2), service/scheduled-task plaintext, RDP | LSARPC (SYSTEM/admin) | `lsadump::cache`/`secrets`, `secretsdump` |
| **DPAPI Vault** | saved app creds (browser, RDP, Wi-Fi) per user | user token or master key | `vault::list`, `vault::cred /export`, `dpapi.py` |
| **NTDS.dit** (DC only) | every domain NT hash + Kerberos key | MS-DRSR replication (DCSync) or offline parse | `secretsdump -just-dc`, `lsadump::dcsync` |

## The attack chain (Tasks 3-4)

Goal: local admin on WRK -> Domain Admin on the DC -> read the flag on the DA Desktop.

1. **DPAPI vault (Task 3 Q1).** As local Administrator, `mimikatz vault::list` then `vault::cred /export`
   showed the saved Web/Windows credentials. Local admin has file access to the Administrator vault +
   master keys, so the generic web cred decrypts: **ElonTusk / gmail.com -> `<redacted-pw>`**.
   *(Headless equivalent: pull `%APPDATA%\Microsoft\Protect` master keys + the vault/credential blobs over
   SMB and decrypt with impacket `dpapi.py` using the `DPAPI_SYSTEM` LSA secret.)*
2. **LSASS live memory (Task 3 Q2).** `privilege::debug` + `sekurlsa::logonpasswords` read the credman
   block from LSASS and exposed the service account's plaintext: **`TRYHACKME\svc-app` -> `<redacted-pw>`**.
   svc-app's *vault* copy stays encrypted (DPAPI key tied to svc-app's own context, so `vault::cred` left
   it blank) - the plaintext only exists in live LSASS, which is exactly why mimikatz (not secretsdump)
   was needed here. No domain creds were in LSASS otherwise, because those users had no active session on
   WRK.
3. **SAM/LSA + cached creds (Task 4, enumeration).** `secretsdump.py WRK/Administrator:<redacted-pw>@
   <ip>` dumped local SAM NT hashes **and** the cached domain logons (MSCacheV2 / **DCC2**) for
   Administrator, raoulduke, svc-app, **drgonzo** - these are stored so the box can log domain users in
   offline.
4. **Crack the DCC2 (Task 4 Q1).** DCC2 is **not** pass-the-hashable (PBKDF2-SHA1, 10240 iters, salt =
   lowercased username), so it must be cracked offline. `john --format=mscash2` (hashcat `-m 2100`) with
   rockyou -> **drgonzo : `<redacted-pw>`**. drgonzo is a Domain Admin.
5. **DCSync as Domain Admin (Task 4 Q2).** `secretsdump.py TRYHACKME/drgonzo:<redacted-pw>@<ip>
   -just-dc` used DRSUAPI replication to pull NTDS.dit, giving every domain NT hash - including the domain
   **Administrator NT hash `<redacted-hash>`**.
6. **Pass-the-Hash to the DC (Task 4 Q3).** `psexec.py TRYHACKME/Administrator@<ip> -hashes
   :<redacted-hash>` -> `nt authority\system` shell on the DC -> read the DA Desktop
   flag: **`THM{…}`**.

## Lessons learned

- **Harvest-and-reuse beats exploitation.** The whole domain fell with zero CVEs: read creds from LSASS,
  DPAPI, SAM, LSA cache, then reuse them. Local admin on one workstation + a logged-in/ cached Domain
  Admin = game over.
- **DCC2 (MSCacheV2) is crack-only, never PtH.** NTLM hashes pass-the-hash; DCC2 is PBKDF2 and only cracks
  offline. So the chain *had* to crack drgonzo before it could DCSync - the cached hash alone isn't a key.
- **DCSync needs no code on the DC.** `-just-dc` abuses legitimate replication (MS-DRSR/DRSUAPI) as a
  Domain Admin - stealthier than dumping NTDS.dit from disk, and why `Replicating Directory Changes`
  rights are tier-0.
- **Know which secret lives where.** svc-app's plaintext was in *live LSASS* (mimikatz only); ElonTusk's
  web cred was in the *DPAPI vault* (local-admin file access decrypts it); the climb to DA came from the
  *LSA cache* (DCC2). Same box, three different stores, three different tools.
- **Why this one wasn't headless from the PC:** live-LSASS plaintext needs mimikatz on WRK (Defender
  quarantines it on the host) and the DCC2 crack needs a GPU cracker + rockyou (not on the PC) - so it ran
  on the AttackBox. The remote steps (`secretsdump`, DCSync, `psexec` PtH) *are* doable with the PC's
  impacket. Same host-tooling gap noted in [[intro-to-ad-breaching]].
- **Defences:** Credential Guard (isolates LSASS), disable WDigest, LAPS for unique local-admin passwords,
  don't let Domain Admins log on to / cache on workstations, and monitor DRSUAPI replication from
  non-DCs.

## Related

- [[intro-to-ad-breaching]] - earlier room with the same host-tooling gap (no Responder/hashcat on the PC).
- [[intro-to-ad-authentication]] - NTLM/Kerberos + Golden Ticket; this room feeds the same hashes/keys.
- [[ad-authenticated-enumeration]] / [[ad-basic-enumeration]] - the enumeration that precedes the loot.
- [[ad-module-plan]] / [[tryhackme-learning-buddy]] - module trackers.
