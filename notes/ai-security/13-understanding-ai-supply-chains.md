# Room 13: Understanding AI Supply Chains (AI Supply Chain Security module)
Path: AI Security | Completed: 2026-10-04 | OWASP LLM03 / MITRE ATLAS AML.T0010

## One-line memory version
> Model files are code in disguise. Loading a model = running code. You trust a chain (models, datasets, frameworks, dependencies) built by people you never vetted — one bad link owns you.

## Supply chain basics
- Supply chain = network of dependencies (house: bricks/wiring/plumbing from different suppliers). Only as secure as the weakest link.
- Attacks exploit **trust**, not defences — compromise something you already trust, upstream.
- **SolarWinds (2020)**: backdoor in the **build process** → ~18,000 orgs. **Log4Shell (2021)**: millions of apps.
- **Transitive dependency** = a package pulled in by your packages (e.g. `pip install torch` drags in `filelock`). You own every one, not just what you listed.

## The AI twist: models are a new artefact
- A model = architecture + training data + training process + **serialised weights**.
- Game-save analogy: weights capture what the model "learned", but a save from a stranger can hide something extra, invisible until it matters.
- **Pickle-based files contain serialised objects that execute code on `model.load()`.**
- **Transfer learning / fine-tuning**: you build on unknown weights. **Backdoors inserted in pre-training survive fine-tuning.** LoRA adapter = a 2nd trust dependency (clean base + malicious adapter = compromised).

## 4 components
Models (HF/TF/PyTorch Hub) · Datasets (HF/Kaggle) · Frameworks (PyTorch/TF, PyPI) · Dependencies (NumPy/Pillow). Every arrow = a trust relationship.

## Two ways to consume AI (both are supply chains)
- **Download**: you host, can scan weights, pin a file hash. Risk = pickle/code-exec.
- **API**: provider hosts; can't inspect weights, training data undisclosed, provider can swap the model behind the same endpoint. Supply chain is just hidden behind the API call.

## File formats (THE audit cheat sheet)
| Format | Pickle? | Code-exec on load | Note |
|---|---|---|---|
| `.pkl` / `.pt` / `.bin` | yes | 🔴 YES | avoid from untrusted sources |
| `.safetensors` | no | 🟢 no | raw weights only — safe choice |
| `.h5` (Keras) | no | 🟠 maybe | code in layers |
| `.gguf` (LLaMA/Mistral/Qwen, Ollama) | no | 🟢 no | but weight backdoors apply; usually **quantised** (unverified transform) |

## 4 attack layers
1. **Model**: pickle code-exec; 3 levels → **serialisation** (on load, killed by SafeTensors), **architecture** (every prediction), **weights** (specific inputs). SafeTensors only kills serialisation-level!
2. **Dependency**: typosquatting, dependency confusion.
3. **Data**: poisoning — **0.1%** → reliable backdoor (no accuracy drop); 0.001% for DoS.
4. **Infrastructure**: repo/account takeover, poisoned CI/CD, stolen maintainer creds.
- Compounding: one malicious HF upload can hit all 4 → one `model.load()` = compromise everywhere.

## Real incidents
| Incident | Trick | Layer |
|---|---|---|
| PyTorch torchtriton (2022) | dependency confusion → stole SSH keys, exfil via DNS | Dependency |
| HuggingFace (2023-24) | 1,500 exposed tokens (655 write) + ~100 malicious pickle models | Infra + Model |
| Ultralytics/YOLO (2024) | poisoned GitHub Actions build → cryptominer in PyPI | Infra (build) |
| @solana/web3.js (2024) | stolen npm maintainer creds → ~$180k stolen | Infra (creds) |
| **NullifAI (2025)** | corrupted pickle **bypasses HF scanners** but still executes | Model |

## Practical: trojaned model audit
- Suspicious: `trustworthy-ai-models/bert-sentiment-classifier` — unverified org, tiny downloads, **pickle** format → DON'T approve.
- Verified baseline: `google-bert/bert-base-uncased` — verified, millions of downloads, **SafeTensors**, thorough card.
- **Verdict: never load a pickle from an unverified new account, even if the scanner says clean (NullifAI).** Trust = track record + SafeTensors + real model card, not a green check.
