# The Blue Team Perspective (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Specialized Domains (Module 13). Premium room. The defender's
  view of your own offensive activity: SOC tiers, SIEM/Splunk, log analysis, IR lifecycle, threat intel.
- **Date:** 2026-10-25.
- **Status:** SOLVED. Tasks 2 to 7 answered (Splunk answers verified live); Task 8 Debrief flag captured:
  **`THM{…}`**.
- **Lab:** Splunk **Enterprise** VM (in-browser split-screen, reverse-proxy
  `*.vm.tryhackme.com`), dataset `index=botsv1` (Splunk BOTSv1, the imreallynotbatman.com / Wayne Corp /
  po1s0n1vy defacement scenario, Aug 2016). **Not headless this time** - the SIEM is a GUI VM, so queries
  were run in the Splunk search bar, not via `curl`. A separate static "companion ops console" (the Task 8
  "View Site") holds four conceptual exercises + the final flag.

## Answers

| Task | Question | Answer | Source |
|---|---|---|---|
| 2 | Target failure = which SOC challenge | *(find it yourself)* | room text |
| 2 | Metric: compromise -> detection | *(find it yourself)* | room text |
| 3 | Field that classifies data format / parsing | *(find it yourself)* | room text |
| 3 | Distinct sourcetypes in `index=botsv1` | *(find it yourself)* | **verified** (`Statistics (N)` header) |
| 3 | When dataset was generated | *(find it yourself)* | room text |
| 4 | Top IPS-signature source IP | `<ip>` | **verified** (query) |
| 4 | IP generating >100 HTTP 404s | `<ip>` | **verified** (query) |
| 5 | NIST phase before any detection | *(find it yourself)* | room text |
| 5 | NIST phase that failed in SolarWinds | *(find it yourself)* | room text |
| 6 | Third level of specificity below techniques | *(find it yourself)* | room text |
| 6 | Pyramid of Pain layer that hurts attacker most | *(find it yourself)* | room text |
| 6 | ATT&CK technique for cmd.exe/PowerShell execution | *(find it yourself)* | room text |
| 7 | Primary external attacker IP (Suricata) | `<ip>` | **verified** (query) |
| 7 | URI with most POST requests | *(find it yourself)* | room text |
| 8 | Companion "View Site" Debrief flag | `THM{…}` | **verified** (companion site) |

Every attacker IOC in the room converges on one external host: **`<ip>`** (po1s0n1vy). It tops the
FortiGate IPS count, the IIS 404 count, and the Suricata external-alert count.

## Splunk queries (run in the search bar, time picker = All time)

```spl
index=botsv1 | stats count by sourcetype
```
Observed: read the `Statistics (N)` header for the distinct count -> *(find it yourself)* sourcetypes (fgt_event, fgt_traffic, fgt_utm, iis, nessus:scan,
stream:dhcp/dns/http/icmp/ip/ldap/mapi/sip/smb/snmp/tcp, suricata, wineventlog:application/security/system,
+ more on a second page). Biggest volumes: `suricata` 125,584; `stream:smb` 151,568; `wineventlog:security` 87,430.

```spl
index=botsv1 sourcetype=fgt_utm subtype=ips | stats count by srcip | sort -count | head 1
```
-> top `srcip` = `<ip>` (IPS signatures from the automated scanner/brute-forcer).

```spl
index=botsv1 sourcetype=iis sc_status=404 | stats count by c_ip | where count>100 | sort -count
```
-> `<ip>` = **2009** 404s (web directory brute-force); internal `<ip>` = 110 (noise). The
attacker is the top row.

```spl
index=botsv1 sourcetype=suricata NOT src_ip=192.168.* NOT src_ip=10.* | stats count by src_ip | sort -count | head 1
```
-> external attacker `src_ip` = `<ip>`.

## Companion site ("View Site") - the four exercises behind the Task 8 flag

- **SOC Alert Triage Simulator** - triage 4 live alerts. Rubric that solved alert #1 (4 failed logons from
  one internal IP in 20 min, baseline 3-5) = **Close as false positive**. General calls: hundreds of
  4625/404 from one IP, or any Event 1102 (log cleared) = true positive -> escalate L2; single mistyped
  password or scattered 404s = false positive -> close; a 7045 service install from a temp path / odd name
  = investigate.
- **IR Lifecycle Phase Mapper** (SANS PICERL -> NIST SP 800-61 Rev 2):
  - Preparation -> Preparation
  - Identification -> Detection and Analysis
  - Containment -> Containment, Eradication, and Recovery
  - Eradication -> Containment, Eradication, and Recovery
  - Recovery -> Containment, Eradication, and Recovery
  - Lessons Learned -> Post-Incident Activity
  (The C/E/R phase is the one that "carries the operational load" - holds 3 cards.)
- **Pyramid of Pain Builder** (indicator -> tier):
  - TTPs (brute force T1110) -> Tough
  - Tools (po1s0n1vy exploit framework) -> Challenging
  - Network or Host Artifacts (URI patterns) -> Annoying
  - Domain Names (avsvmcloud.com C2) -> Simple
  - IP Addresses (attacker source IP) -> Easy
  - Hash Values (MD5 of malware) -> Trivial
- **Wayne Corp Attack Chain Explorer** - click all four stages (Reconnaissance -> Initial Exploitation ->
  Credential Access -> Impact); informational, unlocks the Debrief.
- The **Debrief** tab reveals the Task 8 flag once the exercises are done: `THM{…}`.

## Lessons learned

- **The Splunk "Time Picker Trap" is the #1 gotcha and it blocked every query here.** BOTSv1 events are from
  **August 2016**; the default `Last 24 hours` returns `0 events` with a perfectly correct query. Set the
  time picker (dropdown at the right end of the search bar, left of the green magnifier) to **All time**
  before anything. Four separate "no results" screenshots were all just this.
- **Each SPL search needs its full prefix** `index=botsv1 sourcetype=<type>`. `iis sc_status=404` alone
  treats `iis` as a free-text term, not a sourcetype filter.
- **Run one query at a time.** Splunk executes the whole search box as a single pipeline, so pasting three
  queries on three lines makes line 2's `index=botsv1` land mid-`stats` -> `"The argument 'index=botsv1' is
  invalid."`
- **Threshold detection is one pattern reused across log sources:** aggregate by source (`srcip` / `c_ip` /
  `src_ip`), `sort -count`, flag the outlier. Same logic for IPS brute-force, web 404 enumeration, and
  Suricata external alerts - only the sourcetype/field names change.
- **`Statistics (N)` tab header = the row count** for an aggregation; read it directly instead of counting
  paginated rows (20/page here).
- **Pyramid of Pain = prioritize detections by attacker cost.** Hashes/IPs/domains are cheap for the
  attacker to rotate (Trivial/Easy/Simple); artifacts, tools and TTPs force real redesign
  (Annoying/Challenging/Tough). Blue-team ROI is highest at the top; as a pentester, the behaviours that
  earn a TTP-level detection are the ones to vary to stay quiet.
- **Blue-team value for the red-teamer (room's thesis):** knowing the alert thresholds (e.g. a burst of
  `4625` from one IP lights up every SIEM) lets you throttle/spray below detection, write findings mapped to
  sourcetype + Event ID + ATT&CK ID that the SOC can action, and scope engagements for the real IR cost.
- Key Event IDs: `4624` logon (Type 2 console / 3 network / 10 RDP), `4625` failed logon, `4672` special
  privileges, `4720` account created, `4732` added to local group, `4688` new process, `7045` new service,
  `1102` audit log cleared (survives the clear - high-confidence post-compromise signal).

## Related

- [[cloud-security-fundamentals]] / [[llm-pentesting]] - the other Specialized Domains rooms done this week
  (both headless with `curl`; this one was a GUI Splunk VM instead).
- [[tryhackme-learning-buddy]] - study-buddy context. [[always-doc-rooms]] - why this note exists.
- Next in Module 13 per the room: **DevSecOps 101** (shift-left / CI-CD security).
