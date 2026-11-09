# Host-Server Configuration Reviews (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Privilege Escalation (room 1 - the conceptual foundation for
  the module; later rooms apply it hands-on to Linux and Windows).
- **Room:** Host-Server Configuration Reviews (~60 min, free). Concept room on config-based privilege
  escalation, security baselines (CIS / STIG), compliance tooling, misconfiguration categories, and a
  structured enumeration methodology; Task 8 is a practical against a static CIS-audit report for 3 hosts.
- **Date:** 2026-10-16.
- **Status:** SOLVED - Tasks 2-6 (concepts) + Task 8 practical (5 of 6 values verified against the site;
  Q6 not captured in session - see note under the table). No shell/target; the "practical" is a static
  report you read.

## Answers

| Task | Question | Answer |
|------|----------|--------|
| 2 | Passing a vuln scan guarantees a secure config? (Yay/Nay) | *(find it yourself)* |
| 3 | DISA STIG severity category = highest risk | *(find it yourself)* |
| 4 | Tenable's commercial scanner w/ CIS compliance auditing | *(find it yourself)* |
| 5 | Linux bit that runs an executable as the file's owner | *(find it yourself)* |
| 6 | First methodology phase before specific-misconfig checks | *(find it yourself)* |
| 8 | linux-web-01 7.1.5 - actual perm on `/etc/shadow` | *(find it yourself)* (expected `0640`) |
| 8 | linux-web-01 7.1.11 - world-writable file count | *(find it yourself)* |
| 8 | linux-web-01 7.1.13 - unexpected SUID binary path | *(find it yourself)* |
| 8 | win-dc-01 1.1.4 - minimum password length | *(find it yourself)* (baseline 14) |
| 8 | win-dc-01 <ip> - `FilterAdministratorToken` value | *(find it yourself)* (expected `0x1`) |
| 8 | linux-db-02 - total checks passed | *not recorded in session* - it is the ALL-PASS host; read the "Total checks / Passed" number on its own summary (single digit; don't assume linux-web-01's 8) |

## Core concepts

- **Two kinds of privesc.** *Vulnerability-based* (kernel bugs, CVEs, buffer overflows - patching removes
  the vector) vs *configuration-based* (SUID, weak service/file ACLs, plaintext creds - works on a fully
  patched box). **Config-based is more common and more reliable in mature, well-patched environments**,
  because patching tends to be consistent but hardening is not. This room is entirely the second kind.
- **A config review != a vuln scan.** A host can score zero findings on Nessus/Qualys and still fail a
  config review (excessive service privileges, broad file perms, stored creds). Review asks "what is set
  up *incorrectly*?", not "what software is *broken*?".
- **Same checklist, mirrored intent.** The admin's hardening checklist *is* the attacker's enumeration
  guide - defenders identify -> assess -> remediate; attackers identify -> prioritise -> escalate. Learning
  the secure baseline simultaneously teaches you what the insecure one looks like. Config review usually
  happens in the **post-exploitation** phase (or as a standalone authenticated audit).

## Baselines & frameworks

- **CIS Benchmarks** (Center for Internet Security): consensus-built, per-OS/app/cloud. Each recommendation
  = description + rationale + audit procedure + remediation. **Level 1** = broadly safe, low-impact;
  **Level 2** = defence-in-depth, may break functionality. Example: Ubuntu `PermitRootLogin no` in
  `sshd_config` is a L1 rec.
- **DISA STIGs** (U.S. DoD): more prescriptive, *mandatory* on government networks. Severity **CAT I**
  (highest - direct loss of C/I/A) > **CAT II** (medium) > **CAT III** (low). Categories help both admins
  and testers prioritise.
- **Compliance frameworks reference them:** PCI-DSS, ISO 27001, NIST 800-53 often cite CIS/STIG as the
  concrete hardening to implement. For a tester, a baseline deviation is the **most defensible finding** in
  a report, and gives a structured checklist beating ad-hoc enumeration.

## Tooling

- **Compliance / defensive:** **Nessus** (Tenable, commercial - vuln scanner that *also* does CIS/STIG
  compliance audits), **Lynis** (open-source, runs *locally* on Linux/Unix, hardening-index score),
  **OpenSCAP** (SCAP standard, machine-readable, gov/enterprise), **CIS-CAT** (CIS's own, Lite/Pro, maps
  straight to benchmark recs). A shared Nessus/Lynis compliance report in a grey/white-box engagement is a
  **pre-built list of misconfigs** - each FAIL is a candidate escalation vector.
- **Offensive enumeration:** **LinPEAS / WinPEAS / PowerUp** - run on a compromised host, check the same
  issues (writable files, weak service perms, stored creds) but output for *exploitation*. Two sides of the
  same coin. Caveat: uploading/running tools on target risks detection and may breach the RoE - weigh
  against scope and OPSEC.

## Six misconfiguration categories

1. **Users & groups** - least-privilege violations: users in admin groups, over-privileged service
   accounts, enabled default accounts, weak/absent password policy.
2. **File & directory permissions** - Linux: unnecessary **SUID/SGID** root binaries, world-writable
   scripts run by privileged processes, broad read on `/etc/shadow` / SSH keys. Windows: weak ACLs,
   **writable PATH dirs**, loose install-dir / registry-key perms.
3. **Service configs** - services as root/LocalSystem needlessly, writable service binary/config, and the
   Windows **unquoted service path** (`C:\Program Files\My App\service.exe` -> SCM tries `C:\Program.exe`,
   `C:\Program Files\My.exe`, ... ; writable intermediate dir = run your binary as the service account).
4. **Scheduled tasks / cron** - privileged job referencing a user-writable script/binary; plus **wildcard
   injection** (`tar cf archive.tar *` + attacker files named `--checkpoint=1`,
   `--checkpoint-action=exec=sh shell.sh`).
5. **Credential storage** - Linux: `~/.bash_history`, env vars, app config (DB strings/API keys), loose SSH
   keys. Windows: Credential Manager (`cmdkey /list`), `runas /savecred`, registry cleartext,
   `Unattend.xml`/Sysprep, PowerShell history, `web.config`. Direct escalation, no technical bug needed.
6. **Network config** - (completeness, not a module focus) service bound `0.0.0.0` vs `127.0.0.1`
   (e.g. MySQL `INTO OUTFILE`, PostgreSQL `COPY TO PROGRAM`), extra open ports, loose firewall rules,
   cleartext mgmt protocols. More about lateral movement than local escalation.

## Enumeration methodology

- **Phase 1 - Situational Awareness** (do this *first*): current user + groups + privileges; OS/version/arch;
  hostname + host role (workstation / web / DB / DC); domain-joined? This shapes everything after.
- **Phase 2 - Category-based enumeration:** walk all six categories above in a consistent order so nothing
  is missed.
- **Phase 3 - Prioritise & exploit:** rank by *directness to highest privilege*. Stored root/admin creds >
  an hourly writable cron. **Watch for cross-category chains** - a root cron job (scheduled task) running a
  world-writable script (file perms) is the canonical one: neither matters alone, together = instant root.
- Automated tools (PEAS/PowerUp) and compliance output (Nessus/Lynis) *supplement* the methodology - a
  failed CIS service-perms check points straight at the Service Configurations category.

## Task 8 - practical (static CIS-audit report, 3 hosts)

- Hosts: `linux-web-01` <ip> (Ubuntu 24.04, Apache - **4 FAIL / 8 checks / 50%**), `linux-db-02`
  <ip> (Ubuntu 24.04 - **ALL PASS**), `win-dc-01` <ip> (Win Server 2022 - **3 FAIL**).
- **7.1.5** `/etc/shadow` actual *(find it yourself)* root:root vs expected `0640` root:**shadow** -> any local
  user reads every hash for offline cracking.
- **7.1.11** world-writable: `/opt/scripts/backup.sh`, `/opt/scripts/cleanup.sh`, `/var/www/html/config.php`
  (count: *(find it yourself)*). The report itself flags `backup.sh` as run by a **root cron job every 5 min** -> the chain.
- **7.1.13** unexpected SUID root binary *(find it yourself)* (outside standard paths - possible
  backdoor / direct escalation if it reads files or runs commands).
- **1.1.4** (`net accounts`) min password length *(find it yourself)*, below the 14 baseline.
- **<ip>** `FilterAdministratorToken` *(find it yourself)* -> Admin Approval Mode *disabled* for the built-in
  Administrator, so that account runs everything fully elevated with no prompt; any process compromise in
  its context is already admin.

## Lessons learned

- **"Patched" is not "hardened".** A clean vuln scan says nothing about configuration; config-based privesc
  is the more common real-world path precisely in well-patched shops. Always run a config review even when
  there are zero CVEs.
- **The hardening checklist is the attack map.** CIS/STIG recs give an exact, defensible list of what to
  enumerate; a failed compliance check = a named escalation lead, mapped to one of the six categories.
- **Severity language matters in the report.** Cite the baseline: STIG **CAT I** / CIS Level, with the
  audit command, expected vs actual, and remediation - that's the format the Task 8 panels model and the
  format findings should take.
- **Chains beat single findings.** The world-writable `backup.sh` + root cron (every 5 min) is the textbook
  file-perms x scheduled-task combo. Train yourself to connect a benign finding in one category with a
  benign finding in another.
- **Read the actual value, don't assume.** A *failing* `/etc/shadow` check means a mode *looser* than the
  `0640` baseline (here *(find it yourself)*); the SUID answer is a non-standard path, not one of the expected
  `passwd`/`sudo`/`chfn`/`newgrp`. The site is built so each answer is in the "Actual output" field - verify,
  don't infer.

## Related

- [[privesc-module-plan]] - this is room 1 of the Privilege Escalation module; the Linux/Windows hands-on
  rooms apply these six categories and the methodology.
- [[metasploit-payload-generation]] / [[shell-payload-generation-and-delivery]] - the prior module ended at
  a SYSTEM/root foothold; config review is the systematic next step once you have that shell.
