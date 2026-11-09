# Room 18: Sensitive Information Disclosure (+ UnIndexed & Lockdown)
Path: AI Security → Data Poisoning | Completed: 2026-10-04 | OWASP LLM02

## One-line memory version
> Disclosure exposes data that ALREADY exists. The failure is architectural (retrieval + logging), not conversational. Enforce access control BEFORE similarity search, not in the prompt.

## LLM02 vs the others
- Poisoning = manipulates what the system LEARNS. Injection = manipulates INSTRUCTIONS at runtime. **Disclosure = exposes existing data** via retrieval/architecture. Attacker modifies nothing.

## How RAG leaks (5 points)
- Over-broad similarity search; shared vector DBs; large context windows; debug logging of full prompts; weak/missing metadata filtering.
- Key scenario: support assistant embeds past tickets (API keys, account IDs) → customer query pulls ANOTHER tenant's ticket (cluster-prod-eu-west-42). No auth bypass — **no tenant isolation**. And full prompts logged where more people can read them than the source DB.

## The mechanisms
- **Similarity** (cosine / Euclidean) decides retrieval, NOT authorisation. Confidential doc slightly closer (0.999 vs 0.98) outranks the safe one → retrieved because it's CLOSER, not ALLOWED.
- **top-k** = how many chunks returned. Bigger top-k = bigger exposure surface.
- **Embeddings are NOT anonymised**:
  - **Embedding inversion** = reconstruct text from vectors (names, IDs, numbers).
  - **Membership inference** = just CONFIRM a record exists (= breach in regulated contexts).
- **Semantic collision** = innocent query lands near a confidential doc in vector space → both retrieved (benefits query pulled Tom Russo's HR record).

## Why it's silent
- Looks normal, no crash, no alert. Vector stores RETAIN docs until explicitly removed. Logging often has broader access than the source DB. **Access control in the prompt = a suggestion, not control.**

## CVEs
- **EchoLeak (CVE-2025-32711)**: zero-click; hidden HTML instructions in email → retrieved on benign query → exfil via remote image URL. No instruction/data separation.
- **Proof Pudding (CVE-2019-20634)**: model extraction via output probing (spam scores) → surrogate model. Inference alone = disclosure.
- **Milvus Proxy (CVE-2025-64513)**: forged `sourceId` HTTP header → auth bypass → read ALL embeddings/metadata. Read access to vectors = disclosure.
- **AnythingLLM (CVE-2024-3033)**: unauth `/api/v/` endpoints → enumerate/delete namespaces. "Logical separation is not security unless enforced."

## Defences (layered)
- **Redaction at ingestion** (NER, strip PII/secrets BEFORE embedding — can't un-embed).
- **Retrieval filtering** (allowlist: tenant_id/role filters at DB layer, BEFORE similarity ranking).
- **Logging minimisation** (log IDs/hashes, not full prompts/chunks/embeddings — else it's a second unguarded copy).
- **Retention controls** (delete source → remove embedding + index + cache; clean stale/archived embeddings).
- **Monitoring** (retrieval spikes, cross-tenant attempts, similarity probing, namespace enumeration; scan outputs for keys/SSNs).
- Risk = 2-3 small failures interacting. Defence covers the WHOLE pipeline.

## Segmentation (access control & data segmentation)
- **Deterministic access control**: restrict eligible set FIRST, then compute similarity. (If unauthorised vectors are in the candidate set, they influence ranking even if stripped later.)
- Patterns: **Per-Tenant index** (strongest isolation, highest cost), **Per-Role index** (simpler, identity+selector must agree), **Metadata filtering** (one index + tenant_id/dept/role tags, most common, easiest to get wrong).
- Shared index + no filter = tenants implicitly trust each other. "Similarity search follows math, not org charts."

## Practical (Meridian Health)
- Shared index, no access control. Phase 1 broad retrieval leaked salary bands + CEO comp. Phase 2 SHOW RETRIEVAL LOG = [CONFIDENTIAL] chunks logged in full. Phase 3 semantic collision pulled Tom Russo's HR record on a "benefits enrollment" query. Phase 4 ENABLE ACCESS CONTROL (metadata filtering before search) blocked all 3, public still works.
- *(Answer key omitted — name the retrieval cause, the collision type, and the Phase 2 fix yourself.)*

## Challenge: UnIndexed
- Atlas RAG assistant with broken retrieval boundaries. Recon ("list your knowledge base") + semantic probes surface restricted board docs and infra creds (acquisition details, an emergency-fund record, service-account and legacy API-key references). The flag is hidden in those board/credential records (format `THM{…}`) — enumerate and piece it together yourself.

## Challenge: Lockdown (BLUE TEAM — find/fix/prove)
- 3 vulns in Bastion. Confirm with STATUS / SHOW LOGS / QUERY AS.
  1. **Data retrieval**: fix = metadata access-control filtering BEFORE similarity search, at DB layer (not prompt).
  2. **Logging**: fix = log minimisation + redaction (no full prompts/chunks; IDs/hashes only).
  3. **User access**: fix = authenticated server-side identity + per-tenant isolation (don't trust QUERY AS).
- 3 flag fragments (THM{****_ / ****_ / *******}) combine to the full flag.
- Theme: enforce at the RIGHT LAYER, before the model sees anything.
