# Boogeyman 3 (TryHackMe)

- **Path/module:** Learn / SOC Level 1 (Boogeyman series, room 3). Premium. A **DFIR / threat-hunt**
  challenge: reconstruct the full intrusion of threat group "Boogeyman" against Quick Logistics LLC from
  **Elastic Stack (Sysmon)** logs.
- **Date:** 2026-10-26.
- **Status:** SOLVED. Task 2 "The Chaos Inside" = the entire investigation, all 15 questions answered and
  confirmed correct by THM.
- **Lab:** Elastic Stack, accessed in-browser (Kibana), creds `elastic` / `<redacted-pw>`. Pivot everything in
  **Discover**; set the time range to **29-30 Aug 2023** (the stated incident window) or the logs look
  empty. Can also be driven headless with `curl -su elastic:elastic http://<ip>:9200/...` (ES DSL) the same
  way as the Downtime Kibana room - see [[downtime-event]].
- **Prereqs:** Elastic Stack Basics, Boogeyman 1 & 2.

## The intrusion, end to end

Phishing email to the CEO -> ISO attachment in Downloads -> ISO mounts as `D:\` and holds
`review.dat` -> a `.lnk` runs **stage-1 PowerShell** (note its PID) -> it `xcopy`s the payload to `%TEMP%`,
proxy-executes it with **rundll32** (`DllRegisterServer`), drops a **scheduled task** for
persistence, and beacons **C2 `<ip>`** -> **UAC bypass via fodhelper.exe** -> downloads
**mimikatz** from GitHub and dumps creds -> **pass-the-hash** to a second host -> reads an
**automation `.ps1`** off a share, which leaks cleartext domain creds -> **WinRM
lateral movement** (parent `wsmprovhost.exe`) from the attacker box -> dumps local
**administrator** hash -> **DCSync** dumps `administrator` + a **backup-DA account** -> downloads and stages
**ransomware**.

## Answers, how each was found, and why it matters

Sysmon event codes used: **1** = process creation, **3** = network connection, **11** = file create,
**13** = registry. KQL below runs in Kibana Discover (ECS fields).

| # | Question | Answer | How (hunt) | Why |
|---|---|---|---|---|
| 1 | PID of process that executed stage 1 | *(find it yourself)* | `event.code:1 and process.command_line:*review.dat*` -> the `powershell.exe` launched by the `.lnk` | This PowerShell is the root of the whole tree; its PID parents every stage-1 action below |
| 2 | xcopy implant cmdline | *(find it yourself)* | `event.code:1 and process.parent.pid:<stage1_pid> and process.name:xcopy.exe` | Copies the payload off the removable ISO (`D:\`) to local disk so it survives the ISO unmounting |
| 3 | implanted-file execution cmdline | *(find it yourself)* | `event.code:1 and process.parent.pid:<stage1_pid> and process.name:rundll32.exe` | `review.dat` is really a DLL; `rundll32 ...,DllRegisterServer` is a LOLBin proxy-execution of it |
| 4 | scheduled task name | *(find it yourself)* | `event.code:1 and process.command_line:*schtasks*` (or Security 4698) | Persistence - re-launches the payload on a schedule |
| 5 | C2 IP:port | `<ip>:`*(find it yourself)* | `event.code:3 and process.name:rundll32.exe` -> `destination.ip` + `destination.port` | The implant's outbound beacon; an HTTP port to blend as web traffic |
| 6 | UAC-bypass process | *(find it yourself)* | `event.code:1 and process.name:fodhelper.exe` (preceded by `event.code:13` on `ms-settings\shell\open\command`) | `fodhelper` auto-elevates; hijacking its `ms-settings` registry handler runs code high-integrity with no prompt |
| 7 | GitHub cred-dump tool URL | *(find it yourself)* | `process.command_line:*github.com*` / `*mimikatz*` | Pulls mimikatz for OS Credential Dumping (T1003) |
| 8 | dumped cred pair (host 1) | `*(find it yourself)*:<redacted-hash>` | mimikatz output / the `-H` hash in the next lateral command | Local-admin NTLM hash enables Pass-the-Hash reuse |
| 9 | file read from remote share | *(find it yourself)* | `process.command_line` referencing the UNC share / SMB access events | The script held hardcoded domain creds (next row) |
| 10 | lateral cred pair | `QUICKLOGISTICS\allan.smith:<redacted-pw>` | contents of the automation `.ps1` (cleartext in the script) | Hardcoded domain creds in automation = free lateral movement |
| 11 | attacker lab hostname | *(find it yourself)* | logon/WinRM events - source workstation / client hostname on the lateral auth | Identifies the attacker-controlled pivot box |
| 12 | parent process on host 2 | *(find it yourself)* | `event.code:1` on host 2, inspect `process.parent.name` of the malicious cmd | Lateral move was **WinRM/PSRemoting**; `wsmprovhost.exe` is the signature parent of remoting-run processes |
| 13 | dumped creds (host 2) | `*(find it yourself)*:<redacted-hash>` | mimikatz/secretsdump output on host 2 | Local administrator hash to push toward the DC |
| 14 | DCSync account (besides admin) | *(find it yourself)* | `process.command_line:*dcsync*` / the replicated account list | DCSync (T1003.006) replicates secrets from the DC; the second account is a backup-DA account |
| 15 | ransomware download URL | *(find it yourself)* | `process.command_line` download referencing the binary | Final Impact - stage the ransomware binary |

## Lessons learned

- **One phishing click -> domain-wide ransomware is a tidy ATT&CK chain:** Initial Access (ISO/`.lnk`
  phish) -> Execution (PowerShell + `rundll32` LOLBin) -> Persistence (scheduled task) -> C2 ->
  Priv-Esc (fodhelper UAC bypass) -> Credential Access (mimikatz, DCSync) -> Lateral Movement (PtH +
  WinRM) -> Impact (ransomware). Each question is one link; answer them in order and the story writes
  itself.
- **The Sysmon event code tells you which question you're on:** process cmdlines (EID 1) carry the implant,
  rundll32, schtasks, UAC bypass, downloads and dumps; **EID 3** gives the C2 tuple; **EID 13** backs the
  fodhelper registry hijack. Pivot on `process.parent.pid` to walk a process tree from the stage-1 PID.
- **LOLBins everywhere:** `rundll32 review.dat,DllRegisterServer` (DLL disguised as `.dat`),
  `fodhelper.exe` (auto-elevate UAC bypass), `xcopy` (stage off removable media). Detections should alert
  on *unusual parents* (a PowerShell spawning `rundll32`/`xcopy`) rather than the binaries themselves.
- **`wsmprovhost.exe` as a parent = remote (WinRM) execution.** That single artifact distinguishes lateral
  movement from local activity on the second host - a high-value hunt pattern.
- **Secrets beget secrets:** local-admin hash (PtH) -> a share script with cleartext domain creds ->
  WinRM -> local admin hash -> DCSync of a backup DA. Credential hygiene (no hardcoded creds in scripts,
  LAPS, tiering) breaks the chain at several points.
- **Set the time range first.** The incident is 29-30 Aug 2023; the default Kibana window shows nothing.
  Same class of mistake as the Splunk "All time" trap in [[the-blue-team-perspective]].

## Related

- [[downtime-event]] - the other Elastic/Kibana blue-team work this month (same headless
  `curl`-to-Elasticsearch method). [[the-blue-team-perspective]] - SIEM/SOC concepts (Splunk side).
- [[tryhackme-learning-buddy]] / [[always-doc-rooms]] / [[ctf-workspace-dir]].
