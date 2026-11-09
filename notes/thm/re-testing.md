# Re-Testing (TryHackMe)

- **Path/module:** Jr Penetration Tester -> **Pentesting Methodologies and Reporting** (room after
  [[writing-pentest-reports]]). Remediation verification: confirm fixes actually addressed the root cause,
  spot incomplete fixes with variant payloads, and produce a re-test report.
- **Date:** 2026-10-26.
- **Status:** SOLVED. All concept questions from the task text; Task 6 verified **empirically, headless**
  against the live target from `C:\CTF`.
- **Lab:** web app target `retesting1.1` at **<ip>** (Flask + gunicorn). Task 6 re-tests the
  original engagement's F-01 SQLi on `/login`.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Rebuilt entire platform -> re-test or reassessment | *(find it yourself)* |
| 2 | Document governing whether re-test is included (abbr.) | *(find it yourself)* |
| 3 | Period between report delivery and the re-test | *(find it yourself)* |
| 3 | Signed "won't fix, business constraints" recorded as | *(find it yourself)* |
| 4 | Original blocked but variant dumps records -> outcome | *(find it yourself)* |
| 5 | CVE-2023-43208 came from an incomplete patch for... | *(find it yourself)* |
| 5 | Vendor patch incomplete -> which pitfall | *(find it yourself)* |
| 6 | HTTP code for original `' OR '1'='1` | *(find it yourself)* |
| 6 | Variant `' OR 1=1--` redirect path on success | *(find it yourself)* |
| 6 | Overall re-test result for F-01 | *(find it yourself)* |
| 7 | Column capturing the specific fix applied | *(find it yourself)* |

## Task 6 - empirical verification (headless from C:\CTF)

```bash
# original PoC - blocked symptom, but 200 (not fixed)
curl -s -i -X POST http://<ip>/login \
  --data-urlencode "username=' OR '1'='1" --data-urlencode "password=x"
# -> HTTP/1.1 200 OK, 7291-byte body ("Invalid input detected")

# variant - root cause intact, auth bypass succeeds
curl -s -i -X POST http://<ip>/login \
  --data-urlencode "username=' OR 1=1--" --data-urlencode "password=x"
# -> HTTP/1.1 302 FOUND, Location: /dashboard, Set-Cookie: session=...
```

The original string-comparison payload (`'1'='1`) hits the denylist and returns a **200** "Invalid input
detected" page. The variant uses integer comparison (`1=1`) + the `--` comment terminator, dodges the
denylist, and the still-concatenated query executes -> **302 -> /dashboard**. Denylist = symptom patch;
**F-01 fails re-test**. (The room drives this through Burp Repeater; `curl --data-urlencode` from `C:\CTF`
gets the same result faster.)

## Key concepts

- **Re-test vs full reassessment** (clients say "re-test" for both; clarifying is a communication skill):
  | | Re-test | Full reassessment |
  |---|---|---|
  | Scope | original report's findings only | full attack surface |
  | Baseline | original report + PoC notes | treat environment as new |
  | Duration | ~30% of original | full engagement |
  | Trigger | client remediated findings | major change / M&A / code rewrite |
  | Output | addendum / updated report | new pentest report |
  | Answers | "are the known issues fixed?" | "what vulns exist now?" |
  - "Rebuilt everything" -> **reassessment** (attack surface changed; old findings aren't a baseline).
  - Re-test is **not** a PTES phase; it is a **separate engagement** needing its own pre-engagement docs
    (authorisation/SOW/scope) - the original engagement is closed.
- **Scoping:** the **remediation window** (time to implement fixes) must be in the original **SOW**, not
  negotiated after delivery (15-30d hotfixes / 30-60d standard / 60-90d complex / 90+d infra). Watch scope
  language: "re-test the SQLi finding" != "re-test the login form" != "re-test authentication". New attack
  surface found mid-re-test -> **document it in a separate memo/observation letter**, do **not** test it
  without written authorisation (legal/compliance boundary).
- **Outcomes:** **Pass** (original PoC blocked + obvious variants fail + root cause fixed + no regression),
  **Fail** (original still works, OR a variant succeeds, OR the same pattern exists in adjacent code),
  **Partial/Conditional Pass** (mitigated not eliminated; residual risk documented), **Risk Accepted**
  (client formally accepts in writing - not tested as fixed). Distinct: **Compensating Control / Mitigated**
  (client reduced exposure without fixing root cause, e.g. network-restrict a legacy box) - recorded as
  "Compensating Control", *not* "Risk Accepted". Labels vary by firm; **criteria matter more than labels**
  (no standardised scheme in PTES/OWASP/CREST/NIST SP 800-115).
- **Verifying by fix type:** *patch* -> confirm version changed AND re-run the PoC (version-check != re-test;
  check all cluster nodes; confirm it addresses the specific CVE). *Code fix* -> original payload, then
  encoding variations + alternative parameter paths; review the commit diff for root cause + adjacent code
  reusing the vulnerable pattern (injection root cause = **parameterised queries**). *Architectural* ->
  map the new architecture, confirm the old attack path is gone (WAF: original endpoint unreachable AND
  rules correct; segmentation: attacker subnet can't reach target); highest risk of new attack surface.
- **5 pitfalls (cause false passes):**
  1. **Testing the symptom, not the root cause** - blocking the exact payload (the most common failure; the
     Task 6 scenario). Real example: SAP **CVE-2025-31324** patched the upload path but Visual Composer
     still had insecure deserialization (**CVE-2025-42999**) - chainable to unauth RCE.
  2. **Missing instances** - same vulnerable pattern on adjacent surfaces (login SQLi fixed, password-reset
     form still concatenates). An unreported adjacent instance = **out-of-scope observation** (memo it).
  3. **Patch applied but wrong version / wrong environment** - test the authorised prod system, not
     staging/build server.
  4. **Incomplete vendor patches** - e.g. **CVE-2023-43208** arose from the incomplete patch for
     **CVE-2023-37679** (Mirth Connect XStream deser; 4.4.0 denylist bypassable, full fix in 4.4.1).
  5. **False confidence from automated scanners** - a changed version banner or changed error-response
     format makes the scanner's signature miss while the root cause remains.
- **Evidence + report:** re-test report **supplements** the original (per-finding verification only; no new
  exec summary). Capture full request/response pairs (not just status codes) for **both** fixed and failed
  findings; label tool/date/target/finding-ID; organise by finding ID with timestamps. Structure: (1)
  Re-Test Summary (re-test dates, counts, pass/fail breakdown), (2) **Findings Status Table** (the core
  deliverable; the **Notes** column holds the specific fix + failure observation), (3) Per-finding details
  for failures, (4) Evidence appendix. Out-of-scope observations go in a **separate memo**, never in the
  re-test report.

## Lessons learned

- **Answer-blank length disambiguates:** *(find it yourself)* (4+12), *(find it yourself)* (11+6),
  *(find it yourself)* (4+8), *(find it yourself)* (10+6+7), *(find it yourself)* (14).
- **The whole room in one line:** a fix that stops the reported payload but leaves the root cause is a
  *symptom patch*, not a fix - always run the original PoC first, then **variants** (encoding, alternative
  syntax, adjacent endpoints). Here `' OR 1=1--` beats the `' OR '1'='1` denylist because the query is
  still string-concatenated.
- **This room was headless-friendly:** the Burp Repeater walkthrough is fully reproducible with
  `curl --data-urlencode` from `C:\CTF` over the THM VPN - 200 for the blocked original, 302 -> /dashboard
  for the working variant. Same empirical method as the cloud/LLM rooms. See [[ctf-workspace-dir]].

## Related

- [[writing-pentest-reports]] (previous room) - the re-test report supplements that report's findings.
  [[planning-and-scoping]] - re-test needs its own SOW/authorisation. [[pentesting-methodologies-rooms]]
  (module tracker). [[tryhackme-learning-buddy]] / [[always-doc-rooms]] / [[ctf-workspace-dir]].
