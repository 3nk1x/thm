# Room 7: LLM Security
Path: AI Security → Secure AI Systems | Completed: 2026-10-04

## One-line memory version
> 4 ways to attack an LLM: steal what it **learned** (data), steal **it** (model), mess with its **notepad** (system), or use it to fool **people** (user).

## The 4 threat families
| Family | Plain words | Threats |
|---|---|---|
| **Data-based** | Get the student to recite the textbook | Training data extraction, membership inference, prompt leakage |
| **Model-based** | Steal or reverse the chef's recipe | Model extraction, model inversion |
| **System-based** | Mess with the shared notepad (context window) | Prompt injection, context overflow, memory poisoning |
| **User-based** | Use AI to fool humans | LLM social engineering, trust exploitation |

## Don't mix these up (exam favourite)
| Attack | Attacker starts with | Gets |
|---|---|---|
| **Training data extraction** | Nothing | Memorised text recited back (emails, keys) |
| **Membership inference** | The **full sample** already | **Yes/no**: was it used in training? (look for suspiciously high confidence) |
| **Model inversion** | Partial / no data | **Rebuilt hidden data** (fill in the ████) |
| **Model extraction** | Just API access | A **copy of the model** (GPT-3.5 copied for $50) |
| **Prompt leakage** (LLM07) | Nothing | The system prompt (Bing "Sydney") |
- Memory trick: **Inversion = reversing** learning (model → data). **Extraction (model) = copying** the model.
- **Overfitting** (memorising) is what makes data attacks work.

## System-based: one notepad, no lines between authors
- The **context window** holds system rules + user messages + retrieved docs in the **same ink**. The model can't tell who wrote what.
- **Prompt injection** (LLM01) = "context-window poisoning": write "ignore the rules above" on the notepad.
- **Context overflow** (LLM10) = fill the notepad until the first page (the rules) falls off. **FIFO** = First In, First Out.
- **Denial of Wallet (DoW)** = flood with huge prompts to run up the bill.
- **Memory poisoning** = plant a false "fact" early and it sticks across turns. (I did: cat = dog → "Sphynx is a hairless dog" → `CONFIRM_STORE` → flag.)

## User-based
- **LLM social engineering**: perfect, personalised phishing. Amplifies **phishing**. Worse when combined with leaked internal AI data + OSINT.
- **Trust exploitation** (LLM09): people believe confident AI.
- **Package hallucination**: AI invents a package name → attacker publishes malware under that name → developer installs it.
  - Practical: AI recommended `requests` ✅, `rich` ✅, **`robbco-llm-audit`** ❌ (fake). Trick = wrap one lie between two truths.
  - Check real registries (pypi.org / npmjs.com): downloads, publisher, age. Watch for **typosquatting** (`reqeusts`).

## Defences recap
- Never put secrets in the system prompt; assume it'll be extracted.
- Rate limiting + API auth → stops model extraction and Denial of Wallet.
- Token budgets + cost alerts → context overflow.
- Always verify AI advice before acting.

## Answer-box lesson
- "Not in English" error = usually just a **wrong answer**. If your answer fits the letter pattern but fails, look for **another phrase with the same counts** ("LLM context window" ✗ → "**The context window**" ✓).
