# DevSecOps Basics (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Specialized Domains. Also the **first room of the new DevSecOps
  learning path**. Premium. Theory room: history of software-development models and how security "shifts
  left".
- **Date:** 2026-10-26.
- **Status:** SOLVED. All concept tasks answered; Task 7 "Fuel Trouble" exercise done, flag captured:
  **`THM{…}`**.
- **Lab:** no attack box. Tasks 2 to 6 are reading questions; Task 7 is a static "View Site" comic exercise
  (match each comic to a software-development model, flag revealed on completion).

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Self-organising teams, constructive collaboration | *(find it yourself)* |
| 2 | Automation + integration to drive cultural change | *(find it yourself)* |
| 2 | Traditional model that bred mistrust / poor comms | *(find it yourself)* |
| 2 | What DevOps emphasizes | *(find it yourself)* |
| 3 | Automated tests + frequent small-change merging | *(find it yourself)* |
| 3 | Collecting data on performance/stability of services | *(find it yourself)* |
| 3 | Provision infrastructure via reusable, consistent code | *(find it yourself)* |
| 4 | Term: security from the earliest stages | *(find it yourself)* |
| 4 | Approach: security early through to final stages | *(find it yourself)* |
| 5 | Challenge -> siloed culture | *(find it yourself)* |
| 5 | Challenge -> wrong risk prioritisation | *(find it yourself)* |
| 5 | Challenge -> needlessly overcomplicated processes | *(find it yourself)* |
| 6 | Make security scalable in hypergrowth / large orgs | *(find it yourself)* |
| 6 | Support teams understanding/educating on risk | *(find it yourself)* |
| 6 | Key factors for flexibility | *(find it yourself)* |
| 7 | Comic 1 model | *(find it yourself)* |
| 7 | Comic 2 model | *(find it yourself)* |
| 7 | Comic 3 model | *(find it yourself)* |
| 7 | Flag | `THM{…}` |

## Task 7 - Fuel Trouble (the reasoning)

Premise: travel to the planet with the **least risk**; fuel = 130,000 LY. Planets: Testooine 125k, Hackboo
100k, TryHothMe 80k, Dagobug (Dagobah) 60k.

- **Comic 1 = *(find it yourself)*.** One upfront decision (Testooine), tests run at the end, course never changes.
  Linear, "follow the plan", testing bolted on last.
- **Comic 2 = *(find it yourself)*.** Tests flag Testooine as high risk, so the course is **changed** mid-flight to Hoth.
  "Responding to change over following a plan" - a single adaptive pivot.
- **Comic 3 = *(find it yourself)*.** Multiple teams iterate **together and continuously** - SEC3PO re-analyses the
  trajectory and sets new test parameters, Chewba-QA re-tests and re-orbits - converging on Dagobah
  (60k LY = closest = least risk, well inside the 130k fuel budget). Cross-team collaboration + automation +
  continuous feedback.

Answer-blank lengths confirm the three models (9 / 5 / 6 = *(find it yourself)*).

## Key concepts (for the path ahead)

- **Model evolution:** Waterfall (70s, rigid hierarchy, test-at-end, blame games) -> Agile (early 2000s,
  Agile Manifesto's 4 values, self-organising teams, respond to change) -> DevOps (2008 Debois/Clay;
  "DevOpsDays" 2009) which unites Dev + QA + Sysadmin through **integration and automation** to drive
  **cultural change**.
- **DevOps infinite loop / tooling:** CI/CD, Infrastructure as Code (Terraform, Vagrant), Configuration
  Management, Orchestration, Monitoring, Microservices.
- **Declarative vs imperative IaC:** declarative = specify the end state, software builds it with no human
  interaction; imperative/procedural = ordered steps you trigger at the end via a **"gate"** (e.g. a
  "deploy changes" button) after automated checks pass.
- **Shift Left = DevSecOps:** fold security in from the earliest stages instead of a final-stage gate;
  catching flaws early cuts remediation cost and avoids rollbacks. Security is a design feature, not an
  add-on.
- **DevSecOps challenges:** Security Silos (security treated as a separate specialist entity = not
  scalable), Lack of Visibility & Prioritisation (can't rank the right risks at the right time), Stringent
  Processes (over-gating low-risk work; give devs **Sandbox** environments - isolated, no internal-network
  access, no customer data).
- **DevSecOps culture levers:** promote team autonomy (make security tests just another test), Visibility &
  Transparency (dashboards, give devs access to the scanner UI that flags the finding), and Understanding &
  Empathy (risk means different things to different teams; tune scanners / triage to their context to earn
  buy-in instead of "crying wolf").

## Lessons learned

- **Length-of-blank is the fastest disambiguator** on these theory rooms: "Shift Left" (5+4) not "Shifting
  Left"; "Lack of Visibility" (4+2+10) not the full "Lack of Visibility & Prioritisation"; "Visibility and
  Transparency" (10+3+12). Match the underscores, not just the concept.
- **DevOps-vs-Agile tell:** Agile = responding to change (iterate/pivot); DevOps = many teams collaborating
  continuously with automation. In the comics, a single course-change = Agile; multi-team iterative
  re-analysis to the optimum = DevOps.
- Pure-reading room, no headless work needed; the only "practical" is a static comic-matching page whose
  flag unlocks once the models are correct.

## Related

- [[specialized-domains-rooms]] - module tracker (Cloud Security, LLM Pentesting, The Blue Team Perspective,
  now DevSecOps Basics). This room also kicks off the dedicated **DevSecOps learning path** (next topics:
  pipeline security, source-code security, dependency management, IaC security - Terraform/Vagrant/Docker).
- [[tryhackme-learning-buddy]] / [[always-doc-rooms]].
