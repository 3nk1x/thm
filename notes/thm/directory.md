# Directory (TryHackMe)

- **Type:** Blue-team / DFIR - network forensics (PCAP analysis). Investigate an intrusion against a
  small music company's server from a single Wireshark capture.
- **Room:** Directory (~120 min). Only artifact is `traffic.pcap` (Larry, the Art Director, found a
  "random note" on his Desktop; IT only had Wireshark running).
- **Date:** 2026-10-15.
- **Evidence:** `traffic-1725627206938.pcap`, MD5 `<redacted-hash>` (verified, matches
  room). ~85 MB, 11,136 frames. Analyzed read-only with `tshark` (never executed); no artifact modified.
- **Status:** SOLVED - all 6 answers, every value verified empirically against the capture.
- **Hosts:** attacker `<ip>`, target/AD server `<ip>` (realm `DIRECTORY.THM`, Windows Server
  2022, PSVersion 5.1.20348). Internet IPs in the pcap (20.x/23.x/52.x) are benign Microsoft/Akamai
  browsing by `.75`.

## Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | Ports initially found open (low->high) | *(find it yourself)* |
| 2 | Username that gave the foothold (`Domain.TLD\user`) | *(find it yourself)* |
| 3 | Last 30 characters of the captured hash | *(find it yourself)* |
| 4 | User's password | `<redacted-pw>` |
| 5 | 2nd & 3rd commands executed (`cmd1,cmd2`) | *(find it yourself)* |
| 6 | Flag | `THM{…}` |

## Attack chain (summary)

1. **Port scan** (`<ip>` -> `<ip>`): nmap-style SYN sweep enumerates an AD domain controller.
2. **User enumeration**: Kerbrute sprays AS-REQs of name permutations against realm `DIRECTORY.THM`;
   four accounts come back valid.
3. **AS-REP Roasting**: `larry.doe` has "do not require Kerberos pre-auth" set, so the KDC returns an
   AS-REP whose enc-part is encrypted with larry's own key -> an offline-crackable hash.
4. **Crack**: `<redacted-pw>` (rockyou).
5. **WinRM foothold**: evil-winrm to `5985` as `larry.doe` over NTLM.
6. **Loot + taunt**: `whoami /all`, dump `SAM`/`SYSTEM`/`SECURITY` hives with `reg save`, then drop the
   note on the Desktop containing the flag. `Ya_G0t_R0aSt3d` = pun on AS-REP Roasting.

## Q1 - initial open ports (the "initially" trap)

Attacker = whoever receives the SYN-ACKs; target = whoever sends them.

```
# scan direction (SYN, no ACK): <ip> -> <ip>
tshark -r t.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport
# open ports (SYN-ACK from the target), with first-open time
tshark -r t.pcap -Y "ip.src==<ip> && ip.dst==<ip> && tcp.flags.syn==1 && tcp.flags.ack==1" \
  -T fields -e frame.time_relative -e tcp.srcport
```

Fourteen ports answer open overall, but the initial sweep is a burst at **t = 0.10-0.17 s**. Port
**5985 (WinRM) does not open until t = 213 s** - that is the later command channel, not the scan. So the
*initial* scan = the 13 ports below (= the answer mask `**,**,**,***x7,****x3`):

```
*(find it yourself)* — the 13 ports from the initial SYN-ACK burst (run the tshark filter above)
```

## Q2 - valid users (Kerberos pre-auth enumeration)

```
tshark -r t.pcap -Y "kerberos.CNameString" -T fields \
  -e frame.time_relative -e kerberos.msg_type -e kerberos.CNameString
```

- `kerberos.msg_type` **10** = AS-REQ (name guesses), **11** = AS-REP (account exists / no pre-auth).
- Realm = `DIRECTORY.THM`. A second, clean burst re-queries exactly the four real accounts:
  `john.doe`, `ranith.kays`, `joan.ray`, `larry.doe`.
- Only `larry.doe` yields an AS-REP (msg_type 11) -> roastable -> the foothold. **(submit as `Domain.TLD\user` — *(find it yourself)*)**.

## Q3 - the captured hash (AS-REP enc-part)

The AS-REP (frame 4817) carries two cipher blobs; pick the right one:

- `kerberos.encryptedTicketData_cipher` (etype 18, AES256) = the **ticket**, encrypted with the krbtgt
  key -> NOT crackable, NOT the answer.
- `kerberos.encryptedKDCREPData_cipher` (etype 23, RC4) = the AS-REP enc-part encrypted with **larry's**
  key = the AS-REP-roast hash (hashcat mode 18200).

```
tshark -r t.pcap -Y "frame.number==4817" -T pdml | findstr cipher   # full value, no -V line wrap
```

Hashcat form: `$krb5asrep$23$larry.doe@DIRECTORY.THM:<first 32 hex=checksum>$<rest>`. The string ends
with the RC4 cipher, so its **last 30 characters** = *(find it yourself)*.

## Q4 - crack the hash -> password

No hashcat/john locally; wrote a pure-Python RC4-HMAC (etype 23) AS-REP cracker
(`scratchpad/crack_asrep.py`, reuses the pure-Python MD4 from the Metasploit room):

- `key = MD4(utf-16le(password))` (NTLM)
- `K1 = HMAC-MD5(key, LE32(keyusage))`, `K3 = HMAC-MD5(K1, checksum)`
- `plaintext = RC4(K3, data)`; **verify** `HMAC-MD5(K1, plaintext)[:8] == checksum`
- **key usage 8** for AS-REP RC4 (the MS-NLMP remap; the script also tries 3/7/2 as a safety net).

Only run MD4 on 10-char candidates (answer mask = 10). Hit at rockyou line ~175k:

```
FOUND: '<redacted-pw>'  (key usage 8)   decrypted-plaintext[8]=0x79  (valid AS-REP enc part)
```

`plaintext[8]==0x79` (ASN.1 `[APPLICATION 25]` = EncASRepPart) + the HMAC match = cryptographic proof,
not a dictionary guess.

## Q5 / Q6 - decrypt the WinRM session

WinRM (5985) auth was **NTLM** (NTLMSSP), not Kerberos. 787 SOAP messages were
`multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"`.

`tshark -o ntlmssp.nt_password:<redacted-pw>` **recovers the session keys** (expert info shows the derived
RandomSessionKeys) but this build does **not** re-dissect the sealed SOAP - it stays `mime_multipart`/
`data`. So unseal it manually (`scratchpad/decrypt_winrm.py`):

- RandomSessionKeys per TCP stream (from tshark expert info): stream 2032 =
  `<redacted-hash>`, stream 2033 = `<redacted-hash>`.
- Derive sealing/signing keys (NTLMv2 ESS):
  `SealKey = MD5(SK + "session key to {client-to-server|server-to-client} sealing key magic constant\0")`.
- **Connection-oriented** RC4: one RC4 handle per direction, continuous across all messages; per message
  decrypt the ciphertext then advance the stream 8 bytes (the sealed MAC checksum). Verify with
  `HMAC-MD5(SignKey, LE32(seq) || plaintext)[:8]` -> **787/787 both directions**.
- The plaintext SOAP carries PowerShell Remoting Protocol: typed commands live in `<rsp:Arguments>`
  base64 -> strip the 21-byte PSRP fragment headers -> CLIXML. evil-winrm wraps each command as
  `Invoke-Expression <cmd> | Out-String`; `<cmd>` is the `<S N="V">` value / the `-Command` script.

Attacker command sequence (evil-winrm's auto `(get-location).path` / `$ExecutionContext...Path` prompt
refreshes filtered out):

```
stream 2032: hostname
stream 2033: whoami /all                        # 1st on the box
             reg save HKLM\SYSTEM   C:\SYSTEM    # 2nd  <- Q5 cmd1
             reg save HKLM\SAM      C:\SAM       # 3rd  <- Q5 cmd2
             reg save HKLM\SECURITY C:\SECURITY
             (get-item 'C:\SAM').length ; (get-item 'C:\SYSTEM').length
             cd ..\Desktop\
             echo "THM{…}" > note.txt   # the note Larry found  <- Q6
```

- **Q5** = *(find it yourself)* (matches the mask and the
  "second and third" ordinal, counting `whoami /all` as the 1st command).
- **Q6** = `THM{…}` (matches `***{**_***_********}`; written into the Desktop note).

## Lessons learned

- **"Initially" means the scan burst, not every port that ever answered.** Timeline the first SYN-ACK per
  port; a service you connect to later (WinRM 5985 at t=213s) is not part of the initial scan even though
  it is "open". Timing split the 14 observed open ports down to the intended 13.
- **AS-REP has two ciphers - crack the right one.** The ticket enc-part (AES256, krbtgt key) is a decoy;
  the roastable hash is the KDC-REP enc-part (RC4/etype 23, user key) =
  `kerberos.encryptedKDCREPData_cipher`.
- **Use `-T pdml` (or `-T fields`) for long hex values** - `-V` wraps `cipher […]` across lines and
  corrupts copy/paste.
- **AS-REP RC4 key usage is 8**, not the RFC-4120 value 3 (MS-NLMP remap). Verifying via the embedded
  HMAC makes the crack self-proving - no false positives even when you are unsure of the usage.
- **You can decrypt NTLM-sealed WinRM with just the cracked password.** tshark computes the keys from
  `ntlmssp.nt_password`; if the CLI build won't re-dissect, reproduce NTLM connection-oriented sealing
  (continuous RC4 per direction + 8-byte MAC advance). The MAC doubles as a correctness check.
- **Know your tool's noise.** evil-winrm injects `(get-location).path` / `$ExecutionContext.SessionState.Path`
  after each command to refresh the prompt - filter them before counting "commands executed", and it wraps
  every command as `Invoke-Expression ... | Out-String` inside PSRP.

## Reproduction notes

- `tshark` at `C:\Program Files\Wireshark\tshark.exe` (no tshark on PATH). No hashcat/john; Python 3.12
  with `pycryptodome` (fast RC4) present, `hashlib` has no md4 -> pure-Python MD4.
- Scripts (kept separate from the untrusted pcap, run with `python -I`):
  `scratchpad/crack_asrep.py` (AS-REP RC4 cracker), `scratchpad/decrypt_winrm.py` (NTLM unseal + PSRP
  command/stream extraction). Intermediate `scratchpad/winrm_bodies.tsv`, `winrm_decoded.txt`.

## Related

- [metasploit-post-exploitation](metasploit-post-exploitation.md) - also ends in SYSTEM-level creds/hive
  theft; red-team side of the hive dump this room detects.
- [ps-eclipse](ps-eclipse.md) - sibling Splunk DFIR room (also decodes attacker PowerShell; here it is raw
  PCAP instead of Sysmon).
