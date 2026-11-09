# Agentic Fundamentals (TryHackMe)

Room: Agentic Fundamentals — **Module 1 ("Agentic AI Fundamentals") of the new Agentic AI Security
path**, the sequel to the AI Security path, structured around the **OWASP Top 10 for Agentic
Applications (ASI01–ASI10)**. Knowledge room + one hands-on practical on THM's agentic platform.
Completed: 2026-10-29. No attack machine/VPN target — Task 7 uses the in-browser "Open Agent".
Unlocked via the earlier [[the-thm-bounty-hunt]] bounty receipt (early access).

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Capability so each moment isn't a blank slate | *(find it yourself)* |
| 2 | Capability that works out the order of things | *(find it yourself)* |
| 2 | Capability = something happening in the real world | *(find it yourself)* |
| 3 | What agents use to perform actions | *(find it yourself)* |
| 3 | Practice for designing apps agents use efficiently | *(find it yourself)* |
| 4 | Times more tokens a multi-agent system can use | *(find it yourself)* |
| 4 | Agent all sub-agents report back to | *(find it yourself)* |
| 5 | Shared standard connecting an agent to tools/data | *(find it yourself)* |
| 5 | The three MCP roles, in order | *(find it yourself)* |
| 5 | Term for engaging an external agent | *(find it yourself)* |
| 6 | OWASP term expanding Least-Privilege + Excessive Agency | *(find it yourself)* |
| 6 | Control = permission only for the window needed | *(find it yourself)* |
| 7 | Agent the orchestrator delegated to / Inspector label | *(find it yourself)* |
| 7 | Tool the specialist called for the shipment record | *(find it yourself)* |
| 7 | Shipment awaiting clearance | *(find it yourself)* |
| 7 | Cargo of the critical-handling shipment | *(find it yourself)* |

## Key concepts

- **What makes a system "agentic":** not the model but the *architecture around it*. A plain LLM
  answers from what it knows; a workflow adds hardcoded routes (still has a ceiling); it becomes
  **agentic** when the hardcoded routes are *deleted* and the model is simply told what tools/
  sub-agents exist and left to decide autonomously. The line crossed is live model decisions → real
  actions. Three OWASP capabilities make the perceive→reason→decide→act loop run: Planning &
  Reasoning, Memory & Statefulness, Action & Tool Use.
- **The loop (ReAct, 2023):** reasoning alone is an ungrounded black box; acting alone lacks working
  memory. Interleave them — the model proposes an action, gets *ground truth* back from the tool
  result, and feeds that into the next reasoning step.
- **Tools:** name + description (what/when) + parameter schema. The model doesn't execute; it emits a
  structured `tool_use` request; the app runs the code and returns a `tool_result`. Designing tools
  well for models = **ACI (Agent-Computer Interface)**, the agent analogue of HCI — and it has
  security relevance later in the path.
- **Multi-agent (orchestrator-workers / Coordinating Agent):** one orchestrator delegates to
  specialist sub-agents that report back to it, not to each other. Delegation reuses the same
  `tool_use`/`tool_result` round trip — a sub-agent is wrapped as a tool (OpenAI `transfer_to_*`,
  LangChain supervisor). Benefits: scoped identity/blast radius, reduced path dependency,
  specialisation, speed. Costs: up to **15×** tokens, coordination overhead, harder debugging.
- **Reaching outside your app:** **MCP** (Host/Client/Server) standardises agent→tool discovery and
  connection (the "USB port" for tools). **A2A** standardises agent→agent: Discovery (fetch the
  **Agent Card** from an HTTP endpoint) → Authentication → `sendMessage` → optional
  `sendMessageStream`. MCP = agent-to-tool; A2A = agent-to-agent; an agent can use both.
- **Least Agency (the security thesis):** OWASP's amalgam of Least-Privilege + Excessive Agency
  (LLM06). It's new because Least-Privilege assumes a *human* provisions and reviews access ahead of
  time; in agentic systems the model reaches for access *live, in the moment*. In practice:
  time-boxed not standing access; one credential per agent not one shared across a pipeline; identity
  bound to specific tools not broad accounts; inheritance tracked not assumed to stop.

## Practical — Task 7 (OrbitEx cargo ops)

You chat only with the orchestrator (`ops-lead`); the **Inspector** (list-with-pencil icon) exposes
every delegation/tool call/result. Running the three starter prompts, `ops-lead` used `delegate_task`
→ `*(find it yourself)*` (the specialist sub-agent), which called `*(find it yourself)*` (the
shipment-manifest lookup tool, filtering by `shipmentId` / `status` / `handlingClass`). The Inspector's
tool-result rows list each shipment with its cargo, handling class and status — read off the one that is
Awaiting Clearance, and the critical-handling shipment's cargo, *(find them yourself)*.

## Lessons / relevance

- First room of the path that underpins the prompt-injection video work ([[ai-security-testing-collab]]):
  it frames exactly *why* agentic injection is worse than LLM injection — with a plain LLM "the damage
  stopped at the words on the screen"; an agent turns the manipulated decision into a real tool call.
- The Inspector (full delegation + tool-call chain made visible) is the agentic equivalent of the
  broker/tool-call log in the injection lab — the place attacks become observable.
- Next on the path: Module 2 **Agent Hijacking (ASI01)** — goal hijack + indirect injection, the
  closest tie-in to the current video.
