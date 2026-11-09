# Room 8: AI Threat Modelling
Path: AI Security → Secure AI Systems | Completed: 2026-10-04

## One-line memory version
> STRIDE = *what* type of threat (wide angle). ATLAS = *how* exactly (close-up). OWASP = *where* it lives and how bad (point the camera).

## Threat modelling = thinking like a burglar before the house is built
1. What are we protecting? (assets) 2. What could go wrong? (threats) 3. What do we do about it? (defences) 4. Did it work? (check)

## 6 AI-specific assets (restaurant)
| Asset | Restaurant | If attacked |
|---|---|---|
| **Training data** | Cookery lessons | Chef cooks wrong forever (poisoning) |
| **Model weights** | Chef's brain | Clone of your chef. Can't "rotate" a stolen model |
| **Embedding vectors** | Recipe book index (RAG) | Pulls up the wrong recipe |
| **System prompts** | House rules on the wall | Map to bypass the rules |
| **Feature stores** | Today's prepped ingredients | Changes the dish without touching the chef |
| **Model registry / artifacts** | Staff room of approved chefs | Impostor chef swapped in (backdoor) |
- Plus: **non-deterministic** + **black box** → hard to test, audit, reproduce.

## AI data supply chain (ready-meal factory)
1. **Data collection** (buy ingredients) ← poisoning enters here
2. Cleaning & labelling (wrong labels quietly teach wrong lessons)
3. Training (poison baked in → retrain from scratch)
4. Validation & packaging (registry swap; backdoor passes checks because the trigger isn't tested)
5. Inference (RAG fetches live content = another injection point)
- Key difference: **time**. Bad package = found in hours. Poisoned data = hidden for weeks/months.
- MegaCorp: fraud model retrained monthly → fake transactions slowly teach it to ignore fraud.

## STRIDE (Some Trolls Really Insist on Destroying Everything)
| Letter | Property | Traditional | **AI version** | MegaCorp |
|---|---|---|---|---|
| **S** Spoofing | Authenticity | Fake ID | **Data source impersonation** (RAG injection) | Fake policy docs in chatbot KB |
| **T** Tampering | Integrity | Change data | **Data poisoning** (+ model swap, prompt injection, feature tampering) | Fraud model taught to ignore fraud |
| **R** Repudiation | Non-repudiability | "Wasn't me" | **No decision audit trail** | Can't explain why fraud model approved a payment |
| **I** Info Disclosure | Confidentiality | Leaked files | **Model extraction** (+ training data extraction, prompt leakage, embedding inversion) | Competitor clones recommendation engine |
| **D** Denial of Service | Availability | Crash it | **Denial of Wallet** (+ GPU exhaustion, sponge examples) | Bill $15k → $180k, status still green |
| **E** Elevation of Privilege | Authorisation | Become admin | **Jailbreak / guardrail bypass** (+ excessive agency) | Jailbroken chatbot pulls PII via DB tool |
- STRIDE gaps: **Tampering** can't capture slow, hidden poisoning; adversarial examples span S+T+E; bias; emergent behaviour.

## MITRE ATLAS = burglar's encyclopedia for AI
- Adversarial Threat Landscape for Artificial-Intelligence Systems. AI version of ATT&CK.
- **Tactic** (why) → **Technique** (how) → **Sub-technique** (exactly how) → **Mitigation** (what stops it)
| ID | Technique | STRIDE |
|---|---|---|
| AML.T0020 | Data Poisoning | T |
| AML.T0024 | Extract ML Model | I |
| AML.T0025 | Infer Training Data Membership | I |
| AML.T0015 | Evade ML Model (disguise to fool it) | T+S+E |
| AML.T0051 | LLM Prompt Injection | T |
| AML.T0018 | Backdoor ML Model (logic bomb in the brain) | T |
- **Direct** injection = you type it. **Indirect** = hidden in a doc/email/webpage the AI reads (MegaCorp's main risk).
- Case studies: **ShadowRay** (real attack on AI training servers via Ray), **Morris II** (self-spreading prompt-injection worm via RAG email).

## OWASP mapping: read it both ways
- **Risk → component**: "where does prompt injection hit?"
- **Component → risk**: "we're adding a vector DB, what could go wrong?" (LLM01, LLM08, LLM09)
| Component | Risks | Count |
|---|---|---|
| **LLM inference endpoint** (the chef) | 01, 02, 05, 06, 07, 09, 10 | **7** 🔥 |
| Vector DB / RAG | 01, 08, 09 | 3 |
| **Training pipeline** (supply chain LLM03) | 02, 03, 04 | 3 |
- Output rendered in browser unsanitised = **Improper Output Handling** (LLM05) → **XSS**.

## Practical: MegaCorp chatbot (all correct first try, +10 bonus)
| Risk | Component | Severity |
|---|---|---|
| LLM01 Prompt Injection | LLM Inference | Critical/High |
| LLM04 Poisoning | Training Pipeline | High |
| LLM06 Excessive Agency | LLM Inference | Critical/High |
| LLM08 Vector & Embedding | Knowledge Base | High/Medium |
| LLM10 Unbounded Consumption | API Gateway | Medium/High |
- Trust boundaries on the diagram: 🔴 external access, 🟢 internal services, 🔵 ML operations.
- Severity tiebreak: "Does it leak or change customer data?" Yes → go higher.

## The repeatable workflow
Assets → supply chain → STRIDE-AI → enrich with ATLAS → map with OWASP → prioritise → mitigate. Re-run for every new AI system or model update.
