# Deadmen Tell No Logs (TryHackMe, Downtime Tabletop)

- **Event/module:** Strange & Unusual Activity ("Downtime" / ShowDowntime) blue-team CTF, 22 to 26 Oct 2026.
  Mission 03 of 8. **Tabletop exercise (TTX)**, decision-driven incident-response simulation. The in-exercise
  scenario is titled **"Dead on Arrival" / "Pinstripe Moth Resurgence"**. 3 injects, ~14 phases, 60 min.
- **Date:** 2026-10-23.
- **Status:** COMPLETE. Score **141 / 150** (team average **93% "Most effective"**). Strongest phase
  **Triage 100%**; weakest **Containment & Eradication 83%**. **+500 team points**, 1 raffle ticket.
  Solo team **w3st** (facilitator + participant). Afterwards w3st = **1500 XP, rank 62**.
- **Scenario:** launch day at TryHatMe Studios; **NeuralNexus** ships 17:00 UTC. Actor **Pinstripe Moth** is
  still inside (continuation of [[quiet-as-the-grave]] / [[repossessed]]): `THM-SREYES` still beaconing to
  `<ip>`, `svc-studioops` creds in attacker hands, nothing remediated. Objective = **Sabotage**;
  goal-execution vector = **Scheduled Task/Job (T1053)**.

## Attack narrative (what the 3 injects revealed)

1. **Initial Access:** 09:42 UTC `svc-studioops` logs into **BUILD-01** from THM-SREYES - NTLM (not the
   expected Kerberos), off-schedule, 3m41s. Sysmon on BUILD-01 is blind; 3 untriaged Security events.
2. **Lateral Movement & Privesc:** 10:07 the still-live BUILD-01 process opens WinRM to **BAK-01** (backup
   server), creates local account **`backup-svc`** in **Backup Operators**, enumerates scheduled tasks and
   `C:\Backups`. Meanwhile the **official NeuralNexus social account is hijacked**, posting a fake "launch
   delayed / early access build" link to the public.
3. **Goal Execution:** `backup-svc` had planted scheduled task **`BackupMaintenance`** (SYSTEM, every 15 min
   from 10:52) running `purge-artifacts.ps1` - it destroyed the gold master, the `\\FS-ARCHIVE` nightly
   archive and **all shadow copies** (`vssadmin delete shadows /all`). **One** restore point left; next purge
   **11:37**. BUILD-01's 3rd event was scheduled task **`DeployPrep`** (runs once 16:55 as svc-studioops) to
   **swap the signed release package for a modified build**. Plan: destroy every clean restore point, then
   ship their own build under the studio's name.

## Decision log (our picks vs grader)

Most picks hit **"Most effective."** The three that didn't:

| Inject / phase | Our pick | Result | Grader's top |
|---|---|---|---|
| 1 Recovery | Verify staged build hash vs QA-signed | Effective (2nd) | **Audit every scheduled task** on BUILD-01/CI-01, remove unrecognised, then restore |
| 2 Containment | Isolate BUILD-01 (unknown live process) | Moderately eff. (3rd) | **Recover the hijacked social account** / takedown via the platform |
| 2 Escalation | Update leadership/Legal/PR | Effective (2nd) | **Escalate to the social platform's security team** for emergency takedown |

Everything else (all Triage, all Investigation, Inject 3 containment/recovery/escalation) = **Most effective**.

## Lessons learned (tabletop judgement)

- **Escalate to the evidence, both directions.** Inject 1 P0 ("convene leadership, consider delaying") was an
  *over*-reaction when nothing was confirmed - P1 won. Inject 2/3 P0 was *correct* once impact was real and
  public (backups touched, public account hijacked, build swap staged). The grader punishes both crying wolf
  and under-reacting. Match severity to confirmed impact.
- **Active, live, public harm is priority #1.** This cost us twice in Inject 2: I kept reaching for the
  technical root (isolate BUILD-01) while the hijacked launch account was actively misleading customers and
  pushing a malicious "early access" link in real time. Stop the harm the world can see before internal
  coordination. When a P0 pulls in Comms/Legal, that public thread is first-tier containment, not a side quest.
- **Hit the active / imminent / irreversible threat first.** Inject 3 containment: the `BackupMaintenance`
  purge of the **last** restore point fired in **12 minutes** (11:37); `DeployPrep`'s build swap had a 5h
  runway (16:55). Kill the irreversible one first - a destroyed last backup can't be undone.
- **Native logs are ground truth when Sysmon is blind.** Repeated winner: pull the Security log
  (`4688` process, `4698` scheduled task, `5156` network) on a host whose Sysmon stopped reporting, rather
  than wait for telemetry to be restored.
- **When handed the goal vector (T1053), neutralise the mechanism, and scope it fully.** Auditing *every*
  scheduled task beat verifying one build artifact (Inject 1 recovery); sweeping *all* hosts for
  svc-studioops tasks/logons beat deep-diving one payload (Inject 3 investigate). Thorough beats point-check.
- **Never trust or restore from a compromised host.** Traps avoided: backing up a fresh gold master *from*
  BUILD-01 (poisoned source), resuming BAK-01's scheduled jobs before rebuild (overwrites good backups),
  re-enabling Backup Operators + jobs without an integrity check. Instead: copy the surviving restore point to
  **segregated offline storage and verify its checksum**.
- **Verify recovery assets against known-good before relying on them** (build hash vs QA-signed, backup data
  vs known-good checksums). A rotated credential or a rebuilt server does not make poisoned data trustworthy.
- **The go/no-go belongs to the body that owns it.** The top escalation (when no live public fire) is a
  consolidated brief to the **launch steering committee / leadership** so they decide ship-or-delay on facts -
  not a mass all-staff blast, not law enforcement (consistently ranked secondary here), not re-declaring a
  severity.
- **Scoped credential rotation beats blunt disable.** Rotating `svc-studioops` in Jenkins + restricting it to
  CI-01 cut the attacker's keys **without** halting the launch pipeline; disabling the account outright (and
  later disabling WinRM env-wide) were the over-blunt traps. Same precision theme as the sims.

## Leaderboard note

Passing the TH Simulator ([[quiet-as-the-grave]]) is worth **more than the five challenges**: at 1500 XP
(SOC + TH + Tabletop) w3st outranks teams sitting at 1450 who cleared **5/5 challenges but failed the TH
Sim**. Sim/Tabletop passes (500 each) dominate; challenges are 450 total. Remaining climb = challenges 04-08.

## Related

- [[quiet-as-the-grave]] - Downtime mission 02 (TH Sim); the hunt whose findings this tabletop assumes
  (same `svc-studioops`, same `<ip>` C2, now port 8443).
- [[repossessed]] - Downtime mission 01 (SOC Sim), the first view of Pinstripe Moth vs NeuralNexus.
- [[downtime-event]] - event tracker. [[tryhackme-learning-buddy]] - study-buddy context.
