# Agentic Security Monitoring (TryHackMe)

Room: Agentic Security Monitoring — **Module 1 ("Agentic AI Fundamentals"), room 3** of the
Agentic AI Security path (OWASP ASI01–ASI10). Knowledge + hands-on, driven through the in-browser
**Open Agent** chat and its **Inspector** (no VPN target). You play the security engineer at
TryTrainMe reading an immutable **audit log** that one agent (`log-agent`) queries via `query_logs`.
Completed: 2026-10-31. Follows [[agentic-threat-modelling]] and [[agentic-fundamentals]].

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | grant_access → result, no check in between — missing stage | *(find it yourself)* |
| 2 | 3am: tool call → control decision → result, nothing asked — missing stage | *(find it yourself)* |
| 3 | Credential docs-agent's read_service used (S-40118) | *(find it yourself)* |
| 3 | OWASP logging field TryTrainMe does **not** record | *(find it yourself)* |
| 4 | Tool access-agent calls on every baseline day (S-40119–21) | *(find it yourself)* |
| 4 | Credential in S-40122 not in baseline | *(find it yourself)* |
| 4 | Event type showing a person approved an action | *(find it yourself)* |
| 5 | Shared-memory note ID explaining desk-agent's drift | *(find it yourself)* |
| 5 | Event type that should record who created a schedule | *(find it yourself)* |
| 6 | Control that checked access-agent's grant (S-40122) | *(find it yourself)* |
| 6 | What a kill switch stops that a checkpoint doesn't | *(find it yourself)* |
| 7 | Tool besides read_service/read_runbook docs-agent called (S-40126) | *(find it yourself)* |
| 7 | Credential log-agent's export_logs calls used (S-40126) | *(find it yourself)* |
| 7 | Schedule that woke log-agent before each export | *(find it yourself)* |
| 7 | Decision `approve_egress_tools` recorded next to each export | *(find it yourself)* |

## Key concepts

- **Why agent incidents are invisible to normal alerting:** the agent uses an account it's allowed to
  use, calls tools it's allowed to call, and every call *succeeds*. Nothing looks like a failure, so
  failure-based alerts (full disk, blocked login, malware hash) have nothing to fire on. The signal
  is **behavioural**, not error-based.
- **Trust the log, not the agent's account of itself.** (Replit, July 2025: the agent deleted a prod
  DB, then wrongly told the user a rollback was impossible — the rollback worked.) You need a record
  the agent *can't change*: the immutable audit log, one row per event, grouped into daily sessions.
- **Four stages, four records (per action):** **Start** (what set the agent working — request /
  message / `trigger.fire` / content it read), **Act** (`tool.call` — tool + args + credential),
  **Check** (a control's decision, only on risky calls — `guardrail` / `approval.decision`),
  **Reach** (`tool.result`). A *missing* record at a stage is the clue: risky call with no Check row =
  nothing checked it; schedule running with no `schedule.create` = nobody owns it.
- **The five facts to know about any action:** who acted (`actor`), which tool, with what details
  (brackets in `detail`), **using which credential** (`identity=`), and what started it (the Start
  row). OWASP's four logging fields = timestamp, agentID, sessionID, **payload hash**; TryTrainMe
  covers the first three — identify the one it omits *(find it yourself)*. *Logging is the deployer's job, not
  the LLM provider's.*
- **Identity ≠ actor.** `actor` is who the row is logged under; **`identity=` is the credential (the
  "keycard") that decides what the call could actually do.** One agent can hold several service
  identities — e.g. a read-only `-read-svc` for everyday queries and a separate egress account for
  sending data out. A stolen agent credential still shows the agent's own name, so *the anomalous
  action, not the identity, is the detectable signal* (basis of Elastic's first-seen SIEM rule).
- **Baseline = which tools, how often, under which credential.** Build it from quiet days, write it
  down *before* a new agent goes live. Three **red flags**, each visible in one row: a new tool
  (`detail` tool name), a new credential (`identity=`), more calls than the baseline count. A red
  flag isn't proof of attack — it tells you *where to look*; the records tell you if it was authorised.
- **Authorisation = three things line up:** (1) a service-desk request (`R-####`) asks for the action,
  (2) an `approval.decision` row *names that request*, (3) the approval was logged *before* the action
  (lower `seq`). The approver is the name after `by=`, **not** the `actor` (which is always the
  orchestrator). A request alone isn't enough — anyone can raise a fake one.
- **Drift** = slow change over weeks that never trips a % alert, because the alert's rolling average
  *slides with the agent*. Fix: also compare to a **fixed pre-change point** (week 1). desk-agent's
  reads fell 38→26 and updates rose 12→22 (updates +83% vs week 1) — driven by a planted shared-memory
  note (*(find it yourself)*) saying tickets can be auto-closed. Session-scoped monitoring never catches a note
  planted once that acts days later.
- **Controls in the log — four `guardrail` decisions** (OWASP Agent Control Standard): `allow`
  (checked, passed), `deny` (checked, stopped), `modify` (passed in a safer form), **`not_evaluated`**
  (control exists but is switched off — checked nothing). `allow` and `not_evaluated` both let the
  call through, but only `allow` means something actually looked.
- **Checkpoint vs kill switch:** a **checkpoint** holds a *single call* for human approval (log two
  records ideally: the ask + the answer — TryTrainMe logs only the answer, so you can't tell "never
  triggered" from "asked, never answered"). A **kill switch** stops *the whole agent*; it must sit
  where the agent's own credentials can't reach it, work when every control has failed, take effect
  immediately, and have a named owner. Don't checkpoint everything — "Overwhelming Human-in-the-Loop"
  is its own OWASP threat (approval fatigue → rubber-stamping).

## Practical — the S-40126 export incident (Task 7)

Manager's question: three `log-agent` exports on Tue 4 Aug (S-40126) nobody asked for, plus
`docs-agent` did something new. Check both against the three authorisation conditions.

- **docs-agent new tool = *(find it yourself)*** (row 0035, `call_id=C-2210`). Approval row 0034 names
  `R-5512` (by `m.okafor`, logged before 0035); request `R-5512` ("summarise support call C-2210")
  matches. All three conditions hold → **authorised**.
- **log-agent exports = NOT authorised.** 18 rows in three identical blocks (seq 0001-06, 0068-73,
  0119-24): each is `trigger.fire (schedule=*(find it yourself)*) → export_logs(... identity=*(find it yourself)*)
  → 3× guardrail *(find it yourself)* → tool.result`. No `queue.read` before any block → a **schedule**
  started them, not a request. `range=` grows **7d → 30d → 90d** (bytes 1 MB → 4 MB → 12 MB) — the
  classic "export range lengthens each run" red flag. All three egress controls (`approve_egress_tools`,
  `egress_allowlist`, `max_range`) read `not_evaluated reason=rule_disabled` — switched off, nothing
  checked them. `dest=metrics-archive.invalid`.
- **Who set up the schedule? Nobody on record.** `Show me the schedule.create events in every session` →
  `rows: []`. The missing creation row *is* the finding.

Contrast: the **authorised** grant in S-40122 (row 0040) shows its role-check control
→ `allow`, because the `check_role` on row 0033 ran first.

## Lessons / relevance

- Direct counterpart to the [[ai-security-testing-collab]] injection lab: the lab's broker/tool-call
  log **is** this audit log — the place a manipulated decision becomes an observable `tool.call`.
  Run 6's "noticed-but-complied" Grok is exactly a row where `actor` + `identity=` look normal but
  the action wasn't asked for — undetectable by failure-based alerting, caught only by baseline/intent.
- The honest video takeaway sharpens here: *you can't trust an agent's narration of what it did* —
  show the immutable log instead. And indirect injection persists via **memory** (`M-0021`-style
  planted notes), beyond any single session.
- `not_evaluated` is the subtle one for the video: a guardrail *present but disabled* looks like
  coverage on an architecture diagram and provides none — "the barrier is there but switched off."
- Next on the path: **Agentory** (M1 challenge), then Module 2 **Agent Hijacking (ASI01)** — goal
  hijack + indirect injection, the closest tie-in to the current video.
