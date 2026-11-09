# Room 4: Prompt Engineering (room name TBC)
Path: AI Security | Completed: 2026-10-03 | Challenge: 48/40

## One-line memory version
> Tokens = LEGO chunks. Temperature = creativity dial. Context window = short-term memory. 4 pillars = cake order. System prompt = manager's rulebook, but it's all one stream of text.

## LLM fundamentals
- **Tokens**: chunks the AI reads (~4 letters, ~¾ of a word). "butterfly" → "butter" + "fly". Each becomes a number.
- **Nondeterminism**: same question ≠ same answer. A defence may block an attack once and miss it next time → **if an injection fails, retry it**.
- **Temperature**: creativity dial. 0 = reliable (code/facts), ~1 = creative, 1.5+ = "drunk".
- **Top-p**: only pick from the most likely words adding up to X%. Use temperature OR top-p, not both.
- **Max tokens**: length ceiling (not a target).
- **Context window**: short-term memory. Overflow = silently forgets the start (including safety rules?).

## The 4 pillars = ordering a cake
| Pillar | Cake | Prompt |
|---|---|---|
| **Instruction** | "Bake a cake" | "Summarise this log" |
| **Context** | "7th birthday, loves unicorns" | "You are a SOC analyst..." |
| **Output format** | "Round, 2 layers, name on top" | "3 bullets, under 50 words" |
| **Constraints** | "No nuts, ready Saturday" | "Only use the data given, don't guess" |
- Specific beats vague, and concise beats rambling.

## System vs user prompts = manager vs customer
- **System prompt**: developer's rulebook, constant. **User prompt**: what each user types.
- **Instruction hierarchy**: rulebook should beat user. But it's all **one stream of tokens**, and the labels are soft sticky notes, not locked doors.
- That's why prompt injection works (MENTOR in Room 2 = the hierarchy breaking).

## Advanced techniques = teaching an intern
| Technique | What | Use when |
|---|---|---|
| **Zero-shot** | No examples | Simple, obvious task |
| **One-shot** | **Exactly 1** example | Format matters |
| **Few-shot** | 2-5 varied examples, same layout | Tricky patterns |
| **Chain-of-Thought** | "Show your working". Magic phrase: **"Let's think step by step"** | Multi-step reasoning |
| **Prompt template** | Reusable form with `[PLACEHOLDERS]` | Repeated team tasks |
- CoT only works well on big models (100B+ params); small ones produce convincing wrong reasoning.
- Few-shot can also be an attack (**many-shot jailbreaking**).

## Challenge lessons (PromptSec grader)
- **Match the exact task** asked. Don't reuse a prompt about a different topic.
- Use **real sample data**, not `[PLACEHOLDER]` (except in templates, where placeholders ARE the point).
- **One-shot = exactly one** example (3 examples scored 2/10).
- Separate data from instructions with markers like `--- ALERT DETAILS ---` (also helps against prompt injection).
- Templates: keep them as a clean reusable form, light on instruction text.

## Security terms picked up
- **IOC** (Indicator of Compromise): clues like IPs, domains, file hashes, filenames.
- **Defanging**: `evil[.]com` so links can't be clicked by accident.
- **DDoS**: many computers flooding one target. **SYN flood**: thousands of unfinished handshakes.
- **PCAP**: recording of network traffic.
- **SQL injection**: user input pasted into a database query lets the attacker rewrite it. Fix = **parameterised queries**.
- **True / false positive**: real burglar vs. the cat set off the alarm.
- **Double extension**: `invoice.pdf.exe` disguises a program as a PDF.
