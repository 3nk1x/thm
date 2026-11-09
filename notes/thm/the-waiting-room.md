# The Waiting Room (TryHackMe, Downtime Challenge 05)

- **Event/module:** Strange & Unusual Activity ("Downtime" / ShowDowntime) blue-team CTF, 22 to 26 Oct 2026.
  Mission 05 of 8 (Challenge 2 of 5). Attachment / malware / network forensics. Difficulty: Medium.
- **Date:** 2026-10-23.
- **Status:** SOLVED. All 6 answers correct; +1 Tombstone raffle ticket (+90 team points).
- **Lab:** in-browser Ubuntu analysis desktop at `<ip>` (SSH 22 + WebSockify VNC on 80). Artifacts in
  `~/Desktop/artifacts`: `vendor.eml`, `Sysmon-incident.evtx`, `incident.pcap`. Tools: `evtx_dump`, `tshark`,
  `python3`. Worked **headless from the lab Terminal** (no GUI).

## Reconstructed chain (host MERIDIAN, user `m.smith`)

1. **Phishing (T1566.001):** `vendor.eml` carried a OneNote attachment `Remittance.one`.
2. **Masquerading (T1036.002 / RLO):** inside the `.one`, the embedded payload was named
   `Remittance_<U+202E>fdp.hta`. The **Right-to-Left Override `U+202E`** flips `fdp.hta` so it *displays* as
   `Remittance_ath.pdf` (looks like a PDF, is an HTA). SHA-256 of the HTA =
   `<redacted-hash>`.
3. **User execution -> Mshta (T1204.002 / T1218.005):** `m.smith` ran the embedded file; `mshta.exe`
   (PID 4780) executed `Remittance_fdp.hta`.
4. **Obfuscated JScript loader (T1027):** the HTA hid every string as **XOR 0x39** and used **RC4**. It did a
   `GET http://portal.meridian.thm:8080/assets/remittance-v2.png`, **RC4-decrypted** it with key
   `<redacted-hash>`, and wrote `%LOCALAPPDATA%\Meridian\receipt.js` (prepending
   `var cacheToken="3c7a...";`). (T1105 Ingress Tool Transfer, stage disguised as a PNG.)
5. **Execution (T1059.007 JScript):** `cscript.exe //B //Nologo receipt.js MR-6106-028` ran as PID *(find it yourself)*
   (parent = mshta 4780).
6. **Collection + Exfil (T1560 / T1041):** `receipt.js` read
   `%USERPROFILE%\Documents\Finance\payment-register.csv`, **RC4-encrypted** it with the same `cacheToken`
   key, base64-encoded it, and `POST`ed a JSON envelope to `http://portal.meridian.thm:8080/api/receipt`.
   Server replied `{"accepted":true,"reference":"MR-6106-028"}`. Recovered plaintext CSV SHA-256 =
   `<redacted-hash>`.

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | SHA-256 of the embedded attachment | `<redacted-hash>` |
| 2 | Unicode code point disguising the filename | *(find it yourself)* |
| 3 | Hostname serving the downloaded stage | *(find it yourself)* |
| 4 | PID of the interpreter that ran the script | *(find it yourself)* |
| 5 | Encryption key protecting the transferred doc | `<redacted-hash>` |
| 6 | SHA-256 of the transferred document | `<redacted-hash>` |

## Method (headless)

```bash
# .eml: attachment hash + filename code points (RLO)
python3  # email.message_from_file -> walk parts, sha256 payload, [hex(ord(c)) for c in filename]
# OneNote carve: FileDataStoreObject GUID {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
#   bytes e716e3bd 6526 1145 a4c4 8d4d0b7a9eac ; cbLength at +16, data at +36
# HTA deobfuscation: each value() = XOR 0x39 of the hex pairs
# Sysmon: evtx_dump -o jsonl Sysmon-incident.evtx ; find cscript Image -> ProcessId
# pcap: tshark -r incident.pcap --export-objects http,/tmp/httpobj   (+ -Y http.request fields)
# Stage decrypt: RC4(remittance-v2.png, key=3c7a...) -> receipt.js
# Doc recover:  RC4(base64decode(POST.data), key=3c7a...) -> payment-register.csv -> sha256
```

## Lessons learned

- **OneNote `.one` is a phishing delivery vector.** The real payload is an *embedded* file, carved via the
  **FileDataStoreObject GUID** `{BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}` (watch the little-endian byte order:
  `e716e3bd 6526 1145 ...` - I first mistyped `6625` and the carve found nothing). Hash the *embedded* object,
  not the outer `.one`.
- **`U+202E` (RLO) filename spoofing = Masquerading T1036.002.** `Remittance_<RLO>fdp.hta` renders as
  `Remittance_ath.pdf`. To spot it, print the filename's **code points**; the bidi control (0x202a-0x202e,
  0x2066-0x2069) stands out against ASCII.
- **Deobfuscate first, hunt second.** The HTA was unreadable until each string was XOR-0x39 decoded. That one
  step handed over the URL, the interpreter, and the RC4 key at once.
- **One key, whole case.** `cacheToken` (`<redacted-hash>`) decrypted the *downloaded stage*
  AND was reused to encrypt the *exfiltrated document*. Recover one key and both the loader and the stolen CSV
  fall open.
- **Rebuild exfil from the pcap.** `tshark --export-objects http` pulled the encrypted stage, the POST body,
  and the server reply. base64-decode the JSON `data` -> RC4-decrypt -> original document -> SHA-256 to
  identify what actually left the host. (The POST `/api/receipt` body, not the GET, is "what left the
  workstation.")
- **`evtx_dump` + `tshark` + `python3` cover eml/evtx/pcap end to end** on a Linux box with no Windows GUI.

## Related

- [[downtime-event]] - event tracker (Challenge 05 of 8).
- [[handbook-for-the-recently-compromised]] - Challenge 04, the previous EVTX log-analysis challenge (same
  `evtx_dump | grep` workflow; both actors use LOLBin/script-host download cradles).
- [[repossessed]] / [[quiet-as-the-grave]] / [[deadmen-tell-no-logs]] - sim/hunt/tabletop of the same event.
- [[tryhackme-learning-buddy]] / [[ctf-workspace-dir]].
