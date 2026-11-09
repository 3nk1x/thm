# Planning and Scoping (TryHackMe)

- **Path/module:** Jr Penetration Tester -> **Pentesting Methodologies and Reporting** (room after
  [[threat-modeling-for-pentesters]]). Premium. Pure theory on the **pre-engagement** phase: what a pentest
  is, testing types/approaches, scope, legal documents, Rules of Engagement, and regulatory compliance.
  Framed around a fictional e-commerce client, **BrightCart** (PCI DSS + GDPR, AWS us-east-1).
- **Date:** 2026-10-26.
- **Status:** SOLVED. All concept questions answered from the task text; Task 8 flag captured via the
  "View Site" static exercise: **`THM{…}`**.
- **Lab:** no attack box. Tasks 1-7 are reading questions; Task 8 is a guided "View Site" that applies the
  whole room to the BrightCart client brief and ends in a flag.

## Answers

| Task | Question | Answer |
|---|---|---|
| 1 | Keyword separating a pentest from a criminal attack | *(find it yourself)* |
| 2 | Number of PTES phases | *(find it yourself)* |
| 2 | Broad, automated assessment -> categorized list of known weaknesses | *(find it yourself)* |
| 2 | PTES phase defining scope/rules/legal before testing | *(find it yourself)* |
| 3 | Only company name + IP range, no docs -> approach | *(find it yourself)* |
| 3 | Attacker already inside, reach DB servers -> which test | *(find it yourself)* |
| 4 | Term for the list of assets you ARE authorized to test | *(find it yourself)* |
| 4 | Tested only the portal, skipped API + cloud -> scope error | *(find it yourself)* |
| 5 | Abbreviation of the doc protecting confidential info | *(find it yourself)* |
| 5 | Client asks for a DoS test against their EC2 - proceed? | *(find it yourself)* |
| 6 | Defined process for reporting critical findings mid-engagement | *(find it yourself)* |
| 6 | Unauthenticated API actively leaking card numbers -> tier | *(find it yourself)* |
| 6 | Encryption standard for evidence at rest | *(find it yourself)* |
| 7 | PCI DSS requirement that addresses penetration testing | *(find it yourself)* |
| 7 | GDPR role when a tester accesses EU personal data | *(find it yourself)* |
| 8 | Shares diagrams/docs/test accounts -> approach | *(find it yourself)* |
| 8 | Doc required before sharing technical documentation | *(find it yourself)* |
| 8 | Reach payment DB from corp network -> test type | *(find it yourself)* |
| 8 | Flag | `THM{…}` |

## Key concepts

- **Pentest vs vulnerability assessment:** a pentest is **authorized + simulated**, narrow-but-deep,
  manual, chains findings to show real impact (output = narrative of what was achieved). A vulnerability
  assessment is broad-but-shallow, automated (Nessus/OpenVAS/Qualys), output = categorized list of known
  weaknesses. Run VAs often (monthly/quarterly), pentests periodically (annually / after major change).
- **PTES = 7 phases** (last updated 2014, still the most-cited, referenced by PCI DSS): Pre-engagement
  Interactions -> Intelligence Gathering -> Threat Modeling -> Vulnerability Analysis -> Exploitation ->
  Post Exploitation -> Reporting. Only **2** phases (Exploitation + Post Exploitation) are the hands-on
  "hacking"; the rest is planning, analysis, reporting.
- **Testing approaches (knowledge level):** **Known environment** = white box (full diagrams/source/creds,
  maximises discovery); **Partially-known** = grey box (partial, e.g. a user account - balances realism +
  efficiency); **Unknown** = black box (just a name/IP range, simulates an external attacker). Industry is
  shifting from colour "box" labels to "environment" labels - know both.
- **Internal vs external:** external = "can an outsider get in?" (internet-facing assets); internal = "once
  inside, how far can they go?" (lateral movement / priv-esc). **PCI DSS requires both annually.**
- **Pentest vs red team:** pentest = defined scope, 1-3 weeks, client-aware, find/report as many vulns as
  possible. Red team = org-wide, weeks-months, stealthy (tests the blue team's detection), uses
  social-engineering + physical + technical. Maturity progression: VA -> pentest -> red team.
- **Scope** = the boundaries: **allowlist** (in-scope, authorised) vs **blocklist** (out-of-scope, hands
  off). Covers target IPs/domains/subnets/cloud, apps/APIs, wireless SSIDs, cloud accounts/regions/IAM,
  test accounts + privilege levels. Out-of-scope reasons: production DBs, third-party systems (can't
  authorise), shared infra, change-freeze windows.
  - **Too broad** = shallow testing, higher cost, delayed reports. **Too narrow** = dangerous blind spot,
    false sense of security, compliance failure (PCI expects the whole **CDE**). **Scope creep** (mid-test
    "while you're at it...") must be a **written, signed scope amendment**, not a verbal add-on.
- **Legal documents (executed roughly in order):**
  1. **NDA** - signed first, protects confidential info (vuln data, architecture, creds, results); duration
     typically 2-5 years.
  2. **MSA** (Master Service Agreement) - the overarching relationship (liability, IP, dispute resolution,
     insurance); negotiated **once**, governs all future engagements.
  3. **SOW** (Statement of Work) - **per-engagement**: scope, methodology, timeline, deliverables, cost.
  4. **Authorization letter** - the "get-out-of-jail-free" letter: tester's legal name/company, exact date
     range, covered systems, permitted activities, 2+ client contacts; signed by someone with **undisputed
     legal authority** over the assets. (**Coalfire 2019**: testers arrested doing an authorised physical
     test because the sheriff wasn't informed and authority over the courthouse was ambiguous - Dallas
     County later paid $600k to settle.)
- **Laws:** **CFAA** (US, 18 U.S.C. 1030; *Van Buren 2021* narrowed "exceeds authorized access"); **UK
  Computer Misuse Act 1990** (3 offenses, no statutory security-testing defense). Written authorization is
  not optional - it's existential.
- **Cloud testing (2025):** AWS / Azure / GCP all permit testing your own resources with **no prior
  approval**, but **all prohibit DoS** and any testing of other tenants' resources (hence Task 5 = `Nay`).
- **Rules of Engagement (RoE)** - how you conduct yourself: timing/duration (avoid peak + batch windows),
  communication protocols (contact matrix + channels), **escalation procedures** (Informational / Urgent /
  **Critical**), confidentiality + data handling (**data minimization**, **AES-256** at rest, 30-90 day
  retention then secure wipe), and permitted/prohibited activities (if the RoE is silent on a technique,
  assume it is **not** authorised).
- **Regulatory compliance:**
  - **PCI DSS v4.0.1** (sole active version since 31 Dec 2024) - **Requirement 11.4**: external + internal
    pentests **annually + after significant change**, industry-accepted methodology (NIST SP 800-115, PTES,
    OSSTMM, OWASP), cover the whole **CDE**, and **remediate + retest** (the only framework that explicitly
    requires proving the fix).
  - **HIPAA** - not currently explicit (proposed 2024 HHS rule would require annual); watch ePHI handling.
  - **GDPR** - Article 32(1)(d); accessing EU personal data makes the tester a **Data Processor** (needs a
    **DPA**, data minimization, encryption; fines up to EUR 20M or 4% turnover).
  - **SOC 2** (AICPA, CC4.1) and **ISO 27001:2022** (A.8.8, A.8.29) - not mandated but routinely expected.

## Task 8 - BrightCart brief (the mapping)

- **Approach:** shares diagrams/architecture/AWS config + test accounts at various privilege levels, wants
  "every advantage" -> **Known environment** (white box).
- **Legal:** NDA **not yet signed** (required before sharing docs - execute first); **MSA already in
  place**; SOW drafted per-engagement; authorization letter still required.
- **Types:** web app (www + internal portal) + network (external + internal) + cloud (AWS us-east-1) +
  mobile (iOS/Android). The board's "can an attacker reach the payment DB from the corporate network?" =
  an **internal penetration test** (lateral movement + priv-esc).
- **Scope out:** ShipFast (third-party, can't authorise), eu-west-1 DR (change freeze), any DoS.
- **RoE:** avoid weekday 6-10 PM EST + 2 AM batch; DoS prohibited; daily updates to a single POC; critical
  findings -> immediate phone call to the VP of Engineering; report due **>=3 weeks before 15 Jun 2026**
  (by **25 May 2026**).
- **Compliance:** PCI DSS v4.0.1 (cover the CDE + retest) and GDPR (EU customers -> data-processor
  obligations).

## Lessons learned

- **Answer-blank length nails the exact term:** *(find it yourself)* (13+10),
  *(find it yourself)* (14+12, keep the hyphen as the room writes it), *(find it yourself)*
  (7+11), *(find it yourself)* (10+10), *(find it yourself)* (8+11+4), *(find it yourself)* (4+9).
- **The "authorization" through-line:** Task 1's answer is **`*(find it yourself)*`** (13-char blank, the noun -
  not "authorized"); it is the single thing that makes a pentest legal rather than criminal, threading from
  Task 1 -> the authorization letter (Task 5) -> the RoE (Task 6).
- **Cloud = no DoS, ever:** all three majors ban it, so a client asking for a DoS test against their own
  EC2 is still a *(find it yourself)* (it would violate the provider's AUP, not just the RoE).
- Pure-reading room; the only practical is the Task 8 static "View Site" whose flag unlocks on completion.
  Next room in the module: **Writing Pentest Reports**.

## Related

- [[threat-modeling-for-pentesters]] (previous room - PTES Phase 3) and this (PTES Phase 1). Legal/authz
  through-line echoes the ethics gates in [[the-blue-team-perspective]] and the Python Pentesting Scripts
  room. [[tryhackme-learning-buddy]] / [[always-doc-rooms]] / [[pentesting-methodologies-rooms]] (tracker).
