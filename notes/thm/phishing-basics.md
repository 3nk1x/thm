# Phishing Basics (TryHackMe)

- **Path:** Jr Penetration Tester - module "Password Attacks".
- **Room:** Phishing Basics (beginner, ~45 min).
- **Date:** 2026-10-13.
- **Target (Task 6 practical):** `<ip>` (VM hostname `tryhackme-2404`), SSH as
  `attacker` / `<redacted-pw>`.
- **Status:** SOLVED. Theory tasks (2-5) answered; Task 6 spear-phishing practical performed
  end to end live (SET credential harvester + Rainloop spoofed email). The captured password flag
  printed in the live SET terminal but was not logged here; format recorded below.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Primary channel for a smishing attack | *(find it yourself)* |
| 2 | CEO gets a phishing email sent only to them | *(find it yourself)* |
| 3 | iPhone offer expires in 24 hours | *(find it yourself)* |
| 3 | Executive requests data, emphasises their position | *(find it yourself)* |
| 3 | Exclusive access to a product no one else knows about | *(find it yourself)* |
| 3 | Email says your credentials were in a data breach | *(find it yourself)* |
| 4 | Technique relying on a typo | *(find it yourself)* |
| 4 | Three anti-spoofing measures (alphabetical) | *(find it yourself)* |
| 5 | Credential entry rate of 6% | *(find it yourself)* |
| 5 | Metric for opening an attachment | *(find it yourself)* |
| 5 | Recommendation for a 10% click rate | *(find it yourself)* |
| 6 | Captured password flag | `THM{…}` (captured live, value not logged) |

## Theory (Tasks 2-5)

### Phishing 101 (Task 2)

Phishing is social engineering: impersonate a trusted source to get a victim to reveal data or run
malware. Channels and their names:

- **Email** - the classic vector.
- **SMS** - "smishing".
- **Voice calls** - "vishing".
- **Fake websites** - credential-harvesting clones.

Types by targeting:

- **Phishing** - broad, cast-a-wide-net, generic message to many.
- **Spear phishing** - tailored to a specific individual.
- **Whaling** - spear phishing aimed at senior executives (CEO/CFO). A phishing email sent only to
  a CEO is whaling.

### Psychology (Task 3)

Six social-engineering principles. Mapping the quiz scenarios:

- **Urgency** - a countdown ("expires in 24 hours", "act now"). The iPhone-offer scenario.
- **Authority** - leans on status/role ("as your director, send me..."). The executive scenario.
- **Curiosity** - promises interesting/exclusive info to close an information gap. The
  "exclusive access no one else knows about" scenario.
- **Fear** - threat/alarm to force a protective reaction ("your credentials were breached").
- Scarcity (rarity/FOMO) and Trust (familiar brand/colleague) are the other two.

Relevant cognitive biases: overconfidence, confirmation, authority bias.

### Techniques (Task 4)

- **URL masking** - friendly link text hiding a hostile href.
- **Homograph** - look-alike characters (`go0gle.com`, Cyrillic).
- **Typosquatting** - register misspellings users fat-finger (`tryhacme.com`). The typo answer.
- **Email spoofing** - forge the `From` header; SMTP has no built-in sender auth. Display-name
  spoofing shows "IT Support" while hiding a Gmail address (effective on mobile clients).
- **Credential harvesting / login cloning** - copy a real login page, POST creds to the attacker,
  then redirect to the real site so the victim sees only a "failed login".
- **Payload delivery** - a `.docm` with a VBA macro behind an "Enable Content" prompt.

Defences against spoofing: **DKIM, DMARC, SPF** (alphabetical). Tools named: GoPhish (campaign
framework), EvilNginx (reverse-proxy, MFA/session-token theft), SET (Social-Engineer Toolkit).

### Anatomy of a campaign (Task 5)

Lifecycle: Planning & Scoping -> Reconnaissance (OSINT only) -> Scenario & Payload Development
(harmless lures, simulated login pages) -> Exploitation & Post-Exploitation (run with a kill
switch) -> Reporting & Debriefing (no naming individuals).

Metric benchmarks used in the quiz:

- **Credential Entry Rate** - `<2%` low, `2-5%` moderate, `>5%` high. So 6% = **High risk**.
- **Attachment Detonation Rate** - the metric for who opened/executed an attachment.
- **Click Rate** - `8-14%` acceptable; recommendation at 10% is
  **Focused security awareness training**.

## Task 6 - SET credential harvester (practical)

Scenario: spear-phish Bob (head of finance, `bob@tryaccounting.thm`). Pretext from OSINT: strict
password policy; target uses email security, so basic spoofing is needed. Goal: harvest Bob's
credentials with a cloned login page.

### Steps (reproduced live)

1. `ssh attacker@<ip>` (password `<redacted-pw>`).
2. Launch the toolkit with the alias `SET` (uppercase - lowercase `set` is the bash builtin that
   just dumps shell functions/vars; that tripped me up first).
3. SET menu path: `1` Social-Engineering Attacks -> `2` Website Attack Vectors ->
   `3` Credential Harvester Attack Method -> `3` Custom Import.
   - Note: option `1` at the Social-Engineering submenu (Spear-Phishing Attack Vectors) errors with
     "not supported in Windows or Metasploit was not found" because Metasploit is not installed on
     this box, and it bounces back to the main menu. Credential Harvester lives under Website
     Attack Vectors (`2`) and does not need Metasploit.
4. Prompts:
   - POST-back IP: `<ip>` (the default in brackets was already the machine IP; Enter
     accepts it).
   - Path to website: `/home/attacker/setoolkit/` (trailing slash required; must contain
     `index.html`).
   - Copy choice: `1` (just index.html).
   - Imported URL: `http://tryacounting.thm` (deliberate typosquat - one "c").
   - Result: `Credential Harvester is running on port 80`. Leave the terminal open.
5. Send the lure from Rainloop webmail (`http://<ip>:8080`, login
   `attacker@phisher.thm` / `<redacted-pw>`):
   - New message; change the `From` to the alias **`support@tryaccounting.thm`** (this is the
     spoof - sending as `attacker@phisher.thm` is blocked by the target's email security).
   - To: `bob@tryaccounting.thm`; subject e.g. "Action Required: Password Expiration Notice";
     body is the password-expiry notice linking to `http://tryacounting.thm`.
6. The simulated Bob clicks the link, submits on the cloned page, and SET prints:

```
[*] WE GOT A HIT! Printing the output:
POSSIBLE USERNAME FIELD FOUND: username=bob.wilkinson
POSSIBLE PASSWORD FIELD FOUND: password=THM{…}
```

The `password=` value is the flag (format `THM{…}`). Captured live during the session;
exact value not logged in these notes.

## Lessons learned

- `SET` is case-sensitive on this box: uppercase launches setoolkit, lowercase `set` is the shell
  builtin. Watch case on aliases.
- Spear-Phishing Attack Vectors needs Metasploit; without it, use Website Attack Vectors for
  credential harvesting. The "not supported in Windows" message is SET's generic "Metasploit not
  found" error, not an actual OS problem.
- The whole attack is a login-cloning credential harvester: clone the page, capture the POST,
  and the only real difference from the legit site is where the credentials go.
- Spoofing here is alias-based (a permitted internal `From`), illustrating why SPF/DKIM/DMARC
  matter - without sender authentication, the forged internal sender sailed through.
- The typosquatted domain (`tryacounting.thm`, missing a "c") is what makes the link look
  plausible while pointing at the attacker's harvester.
- Related: phishing as MITRE ATT&CK `T1566` and the Cyber Kill Chain Delivery phase
  ([pentest-frameworks-and-kill-chain](pentest-frameworks-and-kill-chain.md)).

## Status

Room complete. Theory answers verified against the task content; Task 6 performed end to end on the
live VM. Only the captured password flag value is missing from these notes (it printed in the SET
terminal during the run).
