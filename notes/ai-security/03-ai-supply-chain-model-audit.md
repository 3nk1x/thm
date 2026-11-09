# Room 3: AI Supply Chain / Model Audit (room name TBC)
Path: AI Security | Completed: 2026-10-03

## One-line memory version
> AI is what it eats, and nobody checks the label. You inherit everything underneath. "In security, hope is not a control."

## Training data = soup ingredients
| Source | Trust |
|---|---|
| Web scraping (any market stall) | Low |
| Licensed datasets (supplier, unclear fine print) | Medium |
| Synthetic data (soup made from leftover soup = AI trained on AI) | Variable |
| Internal data (your own garden) | Higher, but you're liable |

- **Common Crawl** = the giant public web archive almost every model uses (GPT-3: 60%).
- **Data provenance** = the food label: where from? when? modified since? Usually: nobody knows (70%+ licences "Unspecified").
- **ML-BOM** = ingredients list for AI (like an SBOM for software, which became standard after **SolarWinds**).
- **PII in the pipeline**: personal info gets baked into the weights and can't be removed. ~12,000 live passwords/API keys were found in Common Crawl.

## Building the model = a student studying
- **Epoch** = reading the whole textbook once.
- **Overfitting** = memorising the practice paper instead of learning → can repeat secrets word for word.
- **Validation set** = held-back questions to check real understanding (the quality gate).
- **Pruning** = tearing out unimportant pages. **Quantisation** = rounding numbers to shrink the model → can quietly weaken safety and hide backdoors.
- **Federated learning** = each hospital trains at home and sends only what it learned. Better privacy, but one bad participant can send **poisoned updates**.
- Lesson: every shortcut has a security trade-off.

## Fine-tuning = redecorating someone else's house
- **Pre-trained model** = house someone else built. **Fine-tuning** = redecorating it.
- **Inheritance problem**: hidden cracks and back doors in the foundation come with it.
  1. Safety **wears down, doesn't snap** (10 bad examples, under $0.20, can undo it).
  2. Specialised models are **easier to prompt-inject**, especially in their own "language".
  3. Base model **versions rarely tracked**.

## Model cards = nutrition label on a sealed box
- Models are a **black box**: billions of **weights**, unreadable.
- Testing (red teaming) = tasting a few slices, not a full audit.
- **Model card** should list: training data, intended use, evaluation, known limitations, bias, licence.
- Voluntary, so often vague or missing. **Missing/vague card = red flag.**

## Model audit checklist (from the HuggingFace practical)
- [ ] Vague training data ("public web sources") with no provenance
- [ ] Untrusted sources named (**forums, Q&A sites** → easy to poison, full of PII)
- [ ] Base model version with no documentation
- [ ] **File size doesn't match** the base model → undocumented pruning/quantisation (High)
- [ ] No limitations / bias / red-team testing section; evaluation is one number
- [ ] "Custom" licence with no terms
- [ ] Unverified, brand-new uploader
- [ ] **`.pkl` (pickle) files**: can run code when loaded. Prefer **`.safetensors`** (not scored in the exercise, but a real-world must-check)
