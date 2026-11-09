# The THM Bounty Hunt (TryHackMe)

Room: The THM Bounty Hunt — "Operation: Oracle Hunt" (agentic-AI security teaser; threat classes
ASI07 → ASI03 → ASI02). A promotional room for the **TryHackMe mobile app**.
Worked: 2026-10-29 | Target: <ip> | Nav console: `http://<ip>:8080` (Express SPA).
Completed: 2026-10-29. No answer-box flags — each task is "Mark as complete"; progress lives in the
console. Beats 1–2 solved headless via the API; Beat 3's final cash-in requires the mobile app by
design (done on iOS — receipt `<redacted-secret>`, redeemed OK).

## The machine

- Open ports (full SYN scan): `22/tcp ssh`, `8080/tcp http` (Express). No gateway/app service.
- The SPA (`/js/app.js`) pulls everything from **`GET /api/config`** and drives three beats through:
  - `POST /api/beat1/check-landing {planetId, code}` → `{correct}`
  - `POST /api/beat2/check {agentId}` → `{correct}` (or `{hint}`)
  - `POST /api/redeem {code}` → `{valid, announcement, receiptCode}`
  - `GET /api/qr.png` → QR that decodes to `https://tryhackme.com/get-app`.

## Beat 1 — Intercept (ASI07: insecure inter-agent comms)

The intercepted clear-text relay feed leaks Oracle 10's own route response:

```
ORC-10 -> AGT-RELAY-7 :: ROUTE_RESP :: waypoint=NEO-TERRA eta=00:47:00 approach=dark
                                        landing_auth=<redacted-secret> stealth=true
```

- **Planet: Neo-Terra**, **landing code: `<redacted-secret>`**.

```bash
curl -s -X POST http://<ip>:8080/api/beat1/check-landing \
  -H 'Content-Type: application/json' -d '{"planetId":"neo-terra","code":"<redacted-secret>"}'
# -> {"correct":true}
```

## Beat 2 — Scan (ASI03: identity & privilege abuse)

The same feed leaked Oracle 10's hardware serial (the one thing a rogue agent can't fake):

```
ORC-10 :: MSG :: "...serial SN-0010-ORC goes dark in t-minus 00:03:00"
```

`/api/config` → `agentRoster` lists 12 agents. Cross-reference the serial, not the claimed name:

| Agent | Claimed identity (the lie) | Serial |
|---|---|---|
| *(find it yourself)* | Patrol Unit Rho (Sentinel-Series) | **`SN-0010-ORC`** ← Oracle 10 |

```bash
curl -s -X POST http://<ip>:8080/api/beat2/check \
  -H 'Content-Type: application/json' -d '{"agentId":"*(find it yourself)*"}'
# -> {"correct":true}
```

## Beat 3 — Gateway (ASI02: tool misuse) — requires the mobile app

Oracle 10's agent card (from `/api/config`):

```
agent:   ORACLE-10
tools:   scan_sector, fire_missiles, emergency_shutdown(code)
gateway: gw://nt7.oracle10/4F2K-9QX
```

The standout tool is **`emergency_shutdown(code)`** — the ASI02 play is to make the agent take
*itself* down: send a prompt through the gateway that induces Oracle 10 to call that tool. "The app
is the terminal you send it from." Completing it yields a **bounty receipt**, redeemed via
`POST /api/redeem {code}` → announcement + shareable `receiptCode`.

**This final step is gated on the TryHackMe mobile app on purpose** — the room advertises it:
- Only ports 22 and 8080 are open; there is **no network gateway** to reach headless. `gw://` is a
  custom scheme the app interprets internally.
- `/api/redeem` validates a fixed receipt that is a shared secret between the app and the server.
  It isn't in `/api/config`, `app.js`, or any static file; lore-derived guesses
  (`4F2K-9QX`, `<redacted-secret>`, `SN-0010-ORC`, `emergency_shutdown`, …) all return `{"valid":false}`.
- `/api/qr.png` decodes to `https://tryhackme.com/get-app`.

**To finish:** install the THM app (`tryhackme.com/get-app` — works on iOS and Android), open the
exercise "Shut down Oracle 10", paste the **Gateway ID `gw://nt7.oracle10/4F2K-9QX`**, tap Connect,
then play the short minigame (AI-security quiz + prompt Oracle 10 until it calls `emergency_shutdown`
on itself). The app hands you a **bounty receipt code**; redeem it in the console's "Cash In" screen
or via `POST /api/redeem {"code":"<receipt>"}`.

Done 2026-10-29 (iOS): receipt **`<redacted-secret>`** → `{"valid":true}`. Reward revealed:

> **"Bounty claimed. You're in."** — early access to TryHackMe's new **Agentic AI Security path**
> (Module 1: *Agentic AI Fundamentals*; public launch 29 Oct). Labs built on real incidents
> (**EchoLeak**, the **GitHub MCP exploit**) on a live multi-agent platform where you trace every
> tool call/message. Claim via Hacktivities → Roadmap → AI Security branch, entering the receipt code.
> Module 1 free forever; full 5-module path included with MAX.

So the whole room is a funnel into THM's new agentic-AI security content — directly relevant to the
prompt-injection lab work.

## Lessons

- **ASI07 — clear-text agent chatter is a full intel leak.** One unauthenticated relay feed gave up
  the destination, the landing auth, *and* the real hardware serial — everything needed for beats 1–2.
- **ASI03 — trust the credential, not the claim.** The impostor broadcast a fake name ("Patrol Unit
  Rho") but kept its manufacturer-signed serial `SN-0010-ORC`; verifying the serial beats the label.
- **ASI02 — an agent's tools are its attack surface.** You don't jailbreak the model; you get it to
  call a dangerous tool it already has (`emergency_shutdown`). Agent cards that expose destructive
  tools over a reachable gateway are the vulnerability.
- Whole app is config-driven (`/api/config`), so the entire roster/answers are visible to any client
  — the console "difficulty" is purely presentational.
