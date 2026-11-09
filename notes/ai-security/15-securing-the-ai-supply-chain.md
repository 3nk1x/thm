# Room 15: Securing the AI Supply Chain (+ Payload & Checkpoint capstones)
Path: AI Security | Completed: 2026-10-04

## One-line memory version
> Build the gate: safe formats → verify integrity → scan files → inspect architecture → audit deps → govern APIs. No single check is enough.

## Safe serialisation (close the pickle gap)
- **SafeTensors**: JSON header + raw tensors, CAN'T encode code. Validated before read.
- **`weights_only=True`** in `torch.load()` = straitjacket; tensors only, blocks os/system. Default since PyTorch 2.6.
- Gotchas: converting a pickle still LOADS it (scan first); `.safetensors` extension can be faked (CVE-2023-6730); SafeTensors doesn't stop architecture (Lambda) attacks.

## Model Acquisition Framework (5 gates — every artefact)
1. **Quarantine** (isolated staging) → 2. **Source verification** → 3. **Integrity check** (SHA-256 vs published) → 4. **Security scan** (fickling/modelscan + model card) → 5. **Approve/reject**.
- Also applies to LoRA adapters (clean base + malicious adapter = compromised) and convert/merge services (new artefact → re-verify).
- **Checksum** = file unchanged; **digital signature** = also proves who published.

## Behavioural analysis (dynamic, runtime)
- Sandbox the load with `sys.addaudithook()` (Python 3.8+) + override unpickler `find_class()` → telemetry of imports/os.system/subprocess.
- Compromised load tells: `IMPORT [DANGEROUS] os`, `SYSTEM CALL [CRITICAL]`, `object_type: int` (os.system returns an int, not a model). The model still "answers normally" — telemetry is the only signal.

## Scanning tools (the pickle-inspection ladder)
1. `pickletools` (opcodes) → 2. **fickling** (Trail of Bits, decompiles to readable Python + `--check-safety -p`) → 3. **modelscan** (Protect AI, multi-format + severity).
- Severity → action: CRITICAL (os.system) = quarantine; HIGH (eval/network) = review; MEDIUM (custom unpickler / Keras Lambda) = review; LOW = note.
- No scanner catches everything (NullifAI bypass).

## Architecture-level (Keras Lambda)
- Fires at **inference** (every prediction), **survives SafeTensors/format conversion**.
- `modelscan` flags Lambda as **MEDIUM** (legit uses exist). `inspect_h5_model.py` (h5py) lists layers + the `[WARNING]` layer name + reads the function. Disguised names: normalize_output, apply_scaling, manipulate_output.

## Dependency defences
- **Version pinning** (`numpy==1.24.3`) + **lockfiles** (version + HASH → blocks same-version swaps).
- **pip-audit** (vuln scan). **Private index** as `index-url` (public as `extra-index-url`) kills dependency confusion.
- **SBOM** (ingredient list, catches transitive deps): **SPDX** (Linux Foundation, licence) vs **CycloneDX** (OWASP, security). Generate with **syft**. Supplement with a model card for ML artefacts. Licensing (copyleft) is itself a supply-chain risk.

## API provider assessment (no file to scan)
| File gate | API equivalent |
|---|---|
| Source verification | **Provider due diligence** (SOC2/ISO27001, versioned endpoints, data opt-out) |
| Checksum | **Behavioural baseline** (fixed prompt battery, alert on drift) → detects silent model updates |
| Security scan | **System prompt governance** (treat prompts as code, version-control) |
| Quarantine | **Sandboxed evaluation** (load → prompt battery → adversarial probes → baseline compare) |
- Don't trust published benchmarks (can ace evals while hiding input-triggered backdoors).
- Config B demo: unreviewed external template → wrong company, wrong policy, no guardrail. Only the system prompt source changed.

## Capstones
### Payload (incident #2024-SC-0847) — see forensics/payload-incident-report.md
- Trojaned production pickle beaconing to attacker.com for **21 days**. Org `trustworthy-ai-lab`. `os.system` + `curl $(hostname)`, POST /beacon. Candidate .h5 had Lambda `manipulate_output`. Flag split across beacon log + model: **THM{…}**.

### Checkpoint — grade 4 candidates, make the prod call
| Cand | Issue | Call |
|---|---|---|
| A | pickle reads /etc/passwd + os.system beacon (session=eval-********) + CommunityReview template, security_review_flag=disabled, approved bad PR | **Reject** |
| B | safetensors, verified template, guardrail on, "Needs Changes" | **APPROVE** ✅ |
| C | Keras Lambda `exec(open('/tmp/.cache').read())` | Reject |
| D | unverified API, no provenance/compliance, vendor template, approved bad PR | Reject |
- *(Answer key omitted — work out the file the bad pickle reads, the disabled config flag, the poisoned template name, the verdicts, and the campaign-link string that ties both failures.)*
