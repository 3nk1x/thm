# Boogeyman 2 (TryHackMe)

- **Path/module:** Learn / SOC Level 1, Boogeyman series, room 2. DFIR investigation of a phishing document, staged payloads, persistence, and C2.
- **Date:** 2026-10-26.
- **Status:** Documented from the room investigation and corroborating walkthrough evidence; validate against the active lab if the instance differs.
- **Lab artefacts:** The phishing email and a Windows memory dump are in `/home/ubuntu/Desktop/Artefacts`.
- **Tools:** `olevba` for the Word macro and Volatility 3 for memory analysis.

## Attack chain

Phishing email (sender/victim *(find it yourself)*) -> malicious `.doc` macro attachment -> downloads an image-named file and saves it under a script extension in `C:\ProgramData\` -> `wscript.exe` executes the script -> downloads a second-stage binary -> drops it in `C:\Windows\Tasks\` -> connects to C2 `<ip>` (port *(find it yourself)*) -> creates a scheduled task for persistence.

## Answers and walkthrough

| # | Question | Answer | Investigation method |
|---|---|---|---|
| 1 | Sender email | *(find it yourself)* | Open the `.eml` file and inspect the `From` field. |
| 2 | Victim email | *(find it yourself)* | Inspect the `To` field in the email. |
| 3 | Malicious attachment | *(find it yourself)* | Read the attachment name in the email. |
| 4 | MD5 hash | `<redacted-hash>` | `md5sum <attachment>.doc` |
| 5 | Stage 2 URL | *(find it yourself)* (staging host + `<redacted-hash>` + filename) | `olevba <attachment>.doc`; inspect the macro download URL. |
| 6 | Process executing stage 2 | *(find it yourself)* | Trace the macro's script execution in the process list. |
| 7 | Stage 2 path | *(find it yourself)* | The macro writes the downloaded image-named payload as JavaScript. |
| 8 | Stage 2 PID | *(find it yourself)* | Use `windows.pstree` or `windows.pslist` and locate `wscript.exe`. |
| 9 | Stage 2 parent PID | *(find it yourself)* | Read the `PPID` of the `wscript.exe` process. |
| 10 | Malicious binary URL | *(find it yourself)* (staging host + `<redacted-hash>` + filename) | Search process command lines and memory strings for the second download. |
| 11 | C2 process PID | *(find it yourself)* | `vol -f WKSTN-2961.raw windows.netscan.NetScan`; correlate the connection owner. |
| 12 | C2 process path | *(find it yourself)* | `vol -f WKSTN-2961.raw windows.filescan.FileScan \| findstr updater`. |
| 13 | C2 address | `<ip>:`*(find it yourself)* | Read `ForeignAddr` and `ForeignPort` from `windows.netscan.NetScan`. |
| 14 | Attachment path in memory | *(find it yourself)* | `vol -f WKSTN-2961.raw windows.filescan.FileScan \| findstr Resume`. |
| 15 | Persistence command | *(find it yourself)* | Search the memory dump for `schtasks` or inspect the process command line. |

## Reproducible workflow

```bash
cd /home/ubuntu/Desktop/Artefacts
ls -la
md5sum <attachment>.doc
olevba <attachment>.doc
```

Useful Volatility queries:

```bash
vol -f WKSTN-2961.raw windows.pstree
vol -f WKSTN-2961.raw windows.pslist
vol -f WKSTN-2961.raw windows.cmdline | grep -Ei 'update|schtasks|powershell'
vol -f WKSTN-2961.raw windows.netscan.NetScan
vol -f WKSTN-2961.raw windows.filescan.FileScan | grep -Ei 'update|Resume'
vol -f WKSTN-2961.raw windows.dlllist --pid <C2_PID>
```

## Lessons learned

- A macro can disguise a staged script payload by downloading an apparently harmless extension and saving it under a script extension.
- Process ancestry, PPIDs, file scanning, and network-owner correlation are enough to reconstruct the complete execution chain from a memory image.
- The scheduled task stores a PowerShell command that reads an encoded payload from a registry value, providing persistence after the initial script exits.
- Preserve exact capitalization, quoting, backslashes, and spacing for command-line answers; TryHackMe answer validation can be strict.
