# Room 16: RAG Security Fundamentals (Data Poisoning module)
Path: AI Security | Completed: 2026-10-04

## One-line memory version
> RAG = the chef looks things up in a recipe book at question-time. Poison a page and the chef follows it. Retrieval is a trust boundary, and "working as designed" ≠ secure.

## RAG components (the restaurant)
| Component | Job |
|---|---|
| **Embedding model** | text (query + docs) → **vectors** (numbers = meaning) |
| **Vector store** | holds document embeddings (the recipe book) |
| **Retriever** | finds most **similar** docs (meaning, not keywords) — selects what the LLM sees |
| **LLM** | writes the answer using retrieved docs as context |

Flow: `query → embed → search vector store → top matches → injected into LLM context → answer`.
**At no point is retrieved data verified for correctness/safety.** = **inference-time data poisoning** (no retraining needed).

## 4 attack surfaces
- **Ingestion**: weak validation → malicious/stale docs enter, become "trusted".
- **Embedding generation**: strips **context** (authorship, approval) → malicious & legit look equally valid (mathematically indistinguishable).
- **Similarity-based retrieval**: picks on **semantic relevance**, not trust/correctness → attacker just makes content "sound relevant".
- **Context injection**: retrieved docs go straight into the prompt; model can't tell instructions from data.
- **Retrieval = highest-risk** (automatic, invisible; LLM can't see source/intent/rankings).

## Retrieval abuse
- **Passive poisoning**: drop one bad doc, wait for normal queries to retrieve it (= pre-planted CalBot event).
- **Active manipulation**: craft content to **rank highly** for sensitive queries (= planting your own event, LLMborghini).
- Neither needs continuous access. Hard to detect: outputs look logical, no visible injection, logs just say "relevant documents retrieved".

## Real-world failures
| Case | What | Cause |
|---|---|---|
| M365 Copilot (2026) | instructions hidden in emails retrieved → data leak | email trusted at ingestion |
| ChatGPT Plugins (2023) | external web/API content with instructions → model obeyed | indirect injection via retrieval |
| Web assistants (stale) | outdated guidance served as current | **no freshness/lifecycle controls** in the **retrieval pipeline** (NO attacker needed) |

## Defences (layered — no single control works)
- **Ingestion validation** (best place): review sources, approval workflows, track ownership. Once in the vector store, detection is much harder.
- **Guardrails on retrieved content**: separate data from instructions, flag instruction-like patterns. Imperfect (rephrasing bypasses).
- **Behavioural monitoring**: watch **output drift** = slow shift in responses = **gradual influence** from poisoned data (not a sudden failure). Most effective detector because there's no single bad input to catch.

## Framework mapping
- OWASP: **LLM01** (indirect prompt injection via retrieval), **LLM04** (data & model poisoning at inference), LLM07 (insecure monitoring).
- NIST AI RMF: Map (identify knowledge sources) → Measure (how retrieved data affects outputs) → Manage (controls across ingestion/retrieval/monitoring).
- Retrieval risks = **system-level trust failures**, not model defects.
