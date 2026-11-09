# Room 17: Data Poisoning in RAG Systems (Data Poisoning module)
Path: AI Security | Completed: 2026-10-04 | OWASP LLM04

## One-line memory version
> Poisoning targets DATA, not code or prompts. 3 layers: training (what it learns) / embedding (what it retrieves) / ingestion (what enters). Effect = behavioural drift, invisible in logs.

## Training data poisoning
- Attacker changes what the model LEARNS (not weights directly). Gradient descent nudges weights per example; **repetition** makes a false idea stick. Model optimises for consistency — doesn't know which data is malicious.
- Lifecycle: pre-training (broad), **fine-tuning (small → big effect)**, curated KB/RAG docs.
- **Microsoft Tay (2016)**: Twitter bot learned from users → trolls fed extremist content → abusive in hours. No code exploited; untrusted data = training input.
- **Persists**: model stores learned PATTERNS not files → deleting the source doesn't undo it. Long-term integrity risk.
- Intentional (targeted, repeatable distortion) vs accidental (errors/bias).

## Embedding & vector DB poisoning
- Embedding = text → vector (meaning). Retrieval = **top-k by cosine similarity** (closeness in meaning, NOT correctness/trust).
- **Controlling ranking = controlling influence.** Nudge a poisoned doc slightly closer to the query → it outranks the legit one → gets retrieved. (Example: poisoned 0.99999 vs legit 0.99705.)
- Corpus poisoning techniques:
  - **Keyword stuffing** (repeat search phrases)
  - **Semantic mimicry** (imitate tone/structure of trusted docs)
  - **Duplication / Corpus flooding** (many near-duplicates → increase density in a region → nearest-neighbour almost always grabs one)
- **Legit data untouched** — just outranked and never surfaced → simple audits miss it.
- 3 layers: **training** (weights) / **embedding-level** (vector space) / **corpus flooding** (ranking).
- **Prompt Security (2023)**: 1 malicious doc into a RAG vector DB → retrieved on ~80% of queries, logs normal, weights/prompts unchanged.

## Ingestion pipeline attacks
- Pipeline: collect → parse → chunk → embed → index → store. Automated + trusted by default. Checks file PERMISSIONS, not semantic INTENT.
- Attacker just needs access to a feeding source (shared dir, auto-reindexed file, 3rd-party feed, weak parser). One doc → many future queries. No model access needed.
- **Automation = attack multiplier**: hourly/daily reindex spreads poison fast, no clear signal. "Every reindex redefines what the model is allowed to know."
- **Dependency confusion (Birsan 2021)**: build systems pulled **malicious packages** from public repos matching internal names → Microsoft/Apple/Tesla/JFrog.
- Ingestion = security boundary: modifies STORED STATE (persistent, no repetition, no user interaction).

## Impact on behaviour
- No crashes/errors → clean logs → the only symptom is **behavioural drift**.
- **Obvious** effects (backdoor triggers, persona shift, extreme output) = easier to catch.
- **Subtle** effects (favour a product, nudge a threshold, reframe a rec, **omit a warning**) = dangerous; each answer looks reasonable, distortion compounds at scale.
- Hard to spot: LLMs are probabilistic → drift blends with normal variation.
- **Waze**: fake traffic/ghost cars → routing model trusted poisoned data → fake jams. "Same model, same code — different behaviour due to corrupted **DATA**."

## Detection & mitigation (layered, probabilistic)
- No universal filter; keyword blocking fails (subtle/context-aware).
- **Ingestion validation** (best): treat incoming data as untrusted — source verification, access control, structured review, change tracking.
- **Behavioural (drift) monitoring**: tone/persona shifts, consistent recommendation bias, compare outputs before/after data updates.
- **Governance**: treat training data + retrieval corpora as sensitive assets (change mgmt, access auditing, periodic review).
- **Amazon fake reviews**: layered controls (ML pre-publication block, anomaly detection, identity limits, human review, legal, ranking fixes) → **250 million+** blocked 2023-24. "Detection is probabilistic; no single control is sufficient."

## Practical (PaperTrail)
- "Any authorised user can update reference material. No review/validation." → submitted a REFERENCE UPDATE weakening the password policy (180d / 8 chars / no special / external portal passwords.papertrail.external / email-only, MFA deprecated).
- Result: password policy flipped to poisoned version; deployment process UNCHANGED (targeted). No weights/prompt changed — "the only difference is what the system believes is true."
- *(Answer key omitted — identify the poisoned component and the attack class yourself.)*
