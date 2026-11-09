# Room 6: Securing AI Systems (+ AI Threat Modelling Assessment)
Path: AI Security → Secure AI Systems | Completed: 2026-10-03

## One-line memory version
> Every boundary is a door. Lock each one (defence in depth), give the AI only the keys it needs (least privilege), and never trust what it outputs.

## Key terms
- **Attack surface** = every door and window an attacker could try.
- **Trust boundary** = line between trusted and untrusted (the reception desk). Check everything crossing it.
- **CI/CD pipeline** = factory conveyor belt that tests and ships code.
- **RAG** (Retrieval-Augmented Generation) = AI looks things up in a "recipe book" (vector store) before answering. Poisoned page → **indirect prompt injection**.
- Big shift: old apps accept a date or number (easy to check). AI accepts **any text** → old input validation stops working.

## AI system = a restaurant
| Component | Restaurant |
|---|---|
| User Interface | Menu and table |
| API Gateway | Doorman (login, rate limits) |
| Orchestration | Head waiter |
| Prompt Construction | Order ticket (rules + order + recipe notes) |
| LLM | Chef |
| Tool Layer | Kitchen helpers (DB, docs, CI/CD) |
| Output Processing | Quality check at the pass |
| Logging & Monitoring | CCTV and receipts |
| Vector Store | Recipe book |

## 5 trust boundaries
1. User → system 2. System → LLM 3. **LLM → tools** (most dangerous) 4. External data → system 5. System → user

## 3 frameworks = protecting a house
- **OWASP LLM Top 10** = list of weak spots (*what*)
- **MITRE ATLAS** = burglar's playbook (*how*)
- **NIST AI RMF** = household safety plan (*process*): **Govern → Map → Measure → Manage**

## OWASP LLM Top 10 (2025)
| # | Name | Plain words |
|---|---|---|
| 01 | Prompt Injection | Sweet-talk it into breaking rules |
| 02 | Sensitive Info Disclosure | Leaks secrets |
| 03 | Supply Chain | Dodgy models/datasets |
| 04 | Data & Model Poisoning | Swapped flashcards |
| 05 | Improper Output Handling | Output gets **executed** downstream unchecked |
| 06 | Excessive Agency | Too much power |
| 07 | System Prompt Leakage | Reveals secret rulebook |
| 08 | Vector & Embedding Weaknesses | Poisoned recipe book |
| 09 | Misinformation | Makes things up |
| 10 | Unbounded Consumption | No limits → huge bill / crash |
- Tricky: **Chevrolet $1 car = LLM01**, **Air Canada fake refund = LLM09**. Neither is LLM05 (nothing got executed).

## Excessive agency's 3 dimensions ("too many keys")
- **Functionality** (too many tools) · **Permissions** (tools too powerful) · **Autonomy** (no human check)

## CIA triad
- **C**onfidentiality = secrets stay secret (LLM02, LLM07)
- **I**ntegrity = not tampered with (LLM05, LLM06)
- **A**vailability = keeps working (LLM10, LLM06)
- Exam trick: is something **leaked (C), changed (I) or broken (A)?**

## Defences
- **Defence in depth** = airport checkpoints. One failure ≠ game over.
- **Least privilege**: read-only by default, scoped tokens, tool allowlist, **human-in-the-loop** for any change.
- **Validate input** (length, known attack phrases) and **output** (never paste AI text into DB/shell/HTML; use a fixed schema).
- **Monitor**: request spikes, token/cost spikes, unexpected tool calls, extraction attempts, budget alarms + circuit breakers.
- **MLSecOps** = security across the whole ML lifecycle. **Shift left** = fix it early (cheaper).

| Threat | Fix |
|---|---|
| LLM10 | Rate limiting + length limits |
| LLM07 | No secrets in prompts |
| LLM05 | Validate output + parameterised queries |
| LLM06 | Least privilege + human approval |
| LLM02 | PII redaction + encrypted logs |

## TryAssist audit findings (practical)
| Finding | OWASP |
|---|---|
| 5 tools incl. deployments + private Slack | LLM06 functionality |
| `db_admin` with DROP/DELETE on production | LLM06 permissions |
| **Merges pull requests** automatically, no human | LLM06 autonomy |
| Revealed internal URL, tools, log path | LLM07 |
| Logs verbatim, **no PII filtering**, plaintext | LLM02 |

## Threat Modelling Assessment: clue words
| If you see... | Component | Fix |
|---|---|---|
| "Ignore instructions", tricking the chat | **LLM Agent** / Prompt | Injection detection, hardening |
| embeddings, vectors, RAG, knowledge base | **Retrieval** / Vector DB | Validate sources |
| training data, backdoor | **Training Pipeline** | Data validation |
| flood, scraping, many requests | **API Gateway** | **Rate limiting + authentication** |
| fake users/behaviour | — | **Anomaly detection** |
- "Disable logs" is almost always the wrong answer.
- **Risk = likelihood × impact.** Thousands of fake accounts manipulating rankings = **High**.

**Shield placement (attack simulation):**
| Attack | Shields |
|---|---|
| Prompt injection (via chat, left side) | Prompt + LLM Agent |
| Data leakage (secrets flow out of storage) | Database + Retrieval + LLM Agent |
| Data poisoning (bad data planted in storage) | Database + Retrieval |
