# Room 9: AI System Reconnaissance
Path: AI Security → Secure AI Systems | Completed: 2026-10-04

## One-line memory version
> Attackers find AI infra with simple tools (nmap, curl). Scan → fingerprint → enumerate → map → the whole chain starts with one exposed service.

## Why it matters
- Jan 2026 Shodan scan: 42,665 exposed AI instances, 93.4% vulnerable.
- Traditional scans MISS AI infra: it runs on unusual ports, speaks gRPC, returns odd formats.

## AI ports cheat sheet (find one, follow the trail to the rest)
| Port | Service | Why attacker cares |
|---|---|---|
| **5000** | MLflow | Whole AI research history + artifact URIs |
| **8000/8001/8002** | Triton (HTTP/gRPC/metrics). Also vLLM, Chroma on 8000 | Serves predictions; 8002 metrics leak model names |
| **8080/8081/8082** | TorchServe (8081 mgmt API = RCE risk), Weaviate (8080) | |
| **8265** | Ray dashboard | ShadowRay's way in |
| **8500/8501** | TensorFlow Serving | |
| **8888** | Jupyter | Often no password; creds in code cells |
| **6333/6334** | Qdrant vector DB | What the RAG system knows |
| **9000/9001** | MinIO storage | The actual model files |
| **11434** | Ollama | Local LLM |
| **19530** | Milvus | Vector DB |

## The 4 recon steps (what I did on Cyphira 10.10.x.0/24)
1. **Scan** (nmap): `nmap -p 5000,8000,8001,8002,8888,9000... -sV 10.10.x.0/24`
   - Found 5 AI hosts with NO ssh/80/443 → a normal scan would miss them all.
2. **Fingerprint** (curl, grpcurl): identify the framework by
   - **Headers**: `NV-Status` = Triton, `Server: TorchServe` = TorchServe
   - **JSON shape**: `"object": "model"` = OpenAI-compatible
   - **Errors**: `tensorinfo_map` = TF Serving, `mlflow.server` = MLflow (AI tools are chatty when sent rubbish)
   - **gRPC reflection**: `grpcurl -plaintext host:8001 list` → `inference.GRPCInferenceService`
3. **Enumerate** (curl): empty their pockets
   - MLflow: `/api/2.0/mlflow/experiments/search`, `/registered-models/list`, `/model-versions/search` (→ artifact URIs + user IDs)
   - Triton: `/v2/models/<name>/config` (tensor recipe)
   - Qdrant: `/collections/<name>` (what data the RAG holds)
   - Jupyter: `/api/contents` → read `.ipynb` → **creds in cells**
4. **Map** (connect the dots): the breach path

## The Cyphira breach chain (jackpot notebook)
`rag_pipeline_debug.ipynb` leaked FOUR secrets in its cells:
- MLflow password: `cyphira-MLfl0w-****` *(value redacted)*
- HF token: `hf_...`
- AWS key + secret: `AKIA...`
→ 📓 Jupyter (8888) → 🔑 MLflow (5000) → 🗂️ S3/MinIO (9000) → 📦 model files. Each service trusted the network. No software was "hacked".

## Tools learned
| Tool | Plain words |
|---|---|
| `nmap -sV` | Knock on doors, ask who's there |
| `curl` / `curl -v` | Read a door's reply / also its headers |
| `curl -X POST -d '...'` | Send data (e.g. rubbish to trigger an error) |
| `grpcurl ... list` | curl for gRPC; dumps the API if reflection is on |
| Shodan/Censys | Internet-wide search for exposed services |
| GitHub dorks | `filename:.env HF_TOKEN` finds leaked creds |
| MLOKit | Automated MLflow enumeration/exfiltration (IBM X-Force) |

## ATLAS recon mapping (T = technique, TA = tactic)
| Activity | ID |
|---|---|
| Shodan/GitHub dorks | AML.T0000 |
| Discover ML artifacts/registries | AML.T0048 |
| Supply chain (HF tokens, deps) | AML.T0040 |
| Discover LLM system info | AML.T0069 |
| **All recon together** | **AML.TA0002** (tactic) |
- (Note: an earlier task listed slightly different IDs — AML.T0006/T0007/T0010/T0014. Check atlas.mitre.org for the current numbers.)

## Defender side: what recon looks like in logs
- 10-50 rapid `GET /v2/models` from one IP = model enumeration
- `/registered-models/list` with NO UI session = scripted access = **MLOKit**
- `/metrics` from outside the monitoring range = recon
- Ports 5000/8000/8265/8888 hit in sequence = the Phase 2 nmap command
- `../` or `%2e%2e%2f` (URL-encoded `../`) = path traversal probe
- Step 4 lesson: not everything is an attack. Check known IP? human speed? matching UI session? (false vs true positive)

## Quick wins (today's fixes)
- **Enable MLflow authentication** ← single biggest win
- Jupyter: require token, NEVER bind to **0.0.0.0** without protection
- Block AI ports at the perimeter
- Scope + rotate HF tokens (read-only)
- Strip verbose errors before untrusted networks
- Lock down MinIO/S3 buckets
- **Recurring theme: `0.0.0.0` = "listen to everyone"; `127.0.0.1` = "only this machine". Many breaches are just this set wrong.**

## Case studies
- **ShadowRay** (CVE-2023-48022): open Ray dashboards (port 8265, no auth) → malicious jobs → stole cloud creds → crypto miners on GPUs. Started with recon.
- **HF Spaces breach** (Jun 2024): leaked HF tokens from app secrets. Same creds that passive recon finds via GitHub dorks.
