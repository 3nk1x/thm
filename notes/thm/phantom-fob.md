# Phantom Fob (TryHackMe)

- **Type:** Automotive / CAN bus security (car hacking). Standalone "Learn" challenge room.
- **Room:** Phantom Fob (~60 min). A demo vehicle's CAN bus is exposed; the key fob can Lock and Horn but
  has no Unlock. "Codes change every second, forge the signal; don't replay it" -> defeat a rolling-code
  door lock by reverse-engineering the command, not replaying it.
- **Date:** 2026-10-17.
- **Status:** SOLVED - forged the Unlock frame live and captured the flag.
- **Flag:** `THM{…}`
- **Lab:** target `<ip>`. Reached over the THM VPN from the Windows PC. Two services:
  **TCP 8080** = Flask instrument-cluster dashboard (fob buttons `POST /press`, live state via SSE
  `/events`); **TCP 29536** = **socketcand** (CAN-over-TCP) exposing CAN interface `vcan0`. SSH (22) was
  public-key-only (no shell), so the whole attack ran through socketcand.

## Bus inventory (socketcand rawmode, `vcan0`)

| CAN ID | Role |
|--------|------|
| `18F`,`2FE`,`6A0`,`68A` | engine/telemetry counters (noise) |
| `199` | turn-signal state (`02`=right, blinks) |
| `2D5` | **door/immob status** `[locked][immob][horn][a5]...` (locked=byte0, immob=byte1) |
| `579` | **rolling code** - fires ~1/sec: `[code_hi][code_lo][counter]00000000`; code changes each tick |
| `2BF` | **key-fob command** (only when a button is pressed) |

## The `2BF` command frame (reverse-engineered)

8 bytes: `b0 b1 b2 b3 7E 26 <action> 82`

- **`b4 b5` = `7E 26`** and **`b7` = `82`** - fixed framing.
- **`b6` = action** (stable per action): `LOCK=7A`, `HORN=B8`, `IMMOB_ARM=FD`, `IMMOB_DISARM=72`,
  and the undocumented **`UNLOCK=E8`**.
- **`b1` = anti-replay counter** - increments per command; the car rejects a counter it has already seen
  (replay of a stale frame does nothing - verified).
- **`b0`,`b3` = a function of the current `579` rolling code only** - they are *identical* for different
  actions at the same code (proved: LOCK vs HORN at code `db9f` both gave `b0=97,b3=6a`; ARM vs DISARM at
  `a693` both gave `19..96`). They change every second with the code, so they can't be replayed - but they
  can be *read live* by pressing any button.
- **`b2` = checksum**: **`XOR of all 8 bytes == 0xEB`**. (Found by XORing every captured frame - LOCK, HORN,
  ARM, DISARM, every rolling code - they all equalled `0xEB`.) So
  `b2 = b0 ^ b1 ^ b3 ^ 0x7E ^ 0x26 ^ action ^ 0x82 ^ 0xEB`.

## The forge (what breaks it)

The rolling code (`b0`,`b3`) is unforgeable *in the abstract*, but the design leaks it: it only depends on
the current `579` broadcast, and **the authenticator does not cover the action byte**, while the only
integrity check on the rest is a trivial XOR checksum. So:

1. Press any button (e.g. LOCK) and read the resulting `2BF` frame -> gives `b0`,`b3` for the **current**
   rolling code and the latest counter `L`.
2. Build the Unlock frame for the same code, a fresh counter, and the Unlock action:
   ```
   b0 = <from the press>        # valid for the current 579 code
   b1 = (L + 1) & 0xff          # beat the anti-replay counter
   b3 = <from the press>
   b6 = 0xE8                    # UNLOCK
   b2 = b0 ^ b1 ^ b3 ^ 0x7E ^ 0x26 ^ 0xE8 ^ 0x82 ^ 0xEB   # make XOR == 0xEB
   frame = b0 b1 b2 b3 7E 26 E8 82
   ```
3. Inject it over socketcand (`< send 2BF 8 b0 b1 b2 b3 7e 26 e8 82 >`) **within the same second** (before
   the code ticks). Doors unlock -> `2D5` byte0 -> `00` -> flag released on `/events`.

`UNLOCK = 0xE8` was found by brute-forcing the action byte (`0x00..0xFF`): for each candidate, forge a
*valid* frame (correct live `b0`/`b3`, fresh counter, correct `0xEB` checksum) and watch `2D5` locked-byte;
only `0xE8` flipped it to unlocked. Method validated first by forging a `DISARM` (`72`) and watching the
immobiliser disarm.

## socketcand protocol (how to talk to the bus over TCP)

```
connect tcp <ip>:29536
server> < hi >
client< < open vcan0 >     server> < ok >
client< < rawmode >        server> < ok >
# receive:  < frame 2BF <bus_ts> b0b1b2b3...  >
# send:     < send 2BF 8 b0 b1 b2 b3 7e 26 e8 82 >
```
Frames carry a **bus timestamp** - essential for pairing each `2BF` command with the exact `579` code that
preceded it (thread-scheduling jitter made naive pairing wrong).

## Lessons learned

- **Enumerate the transport, not just the app.** The dashboard (8080) only exposed Lock/Horn/Immob; the win
  was port **29536 = socketcand**, which gave raw read+write to the CAN bus. SSH was pubkey-only - a locked
  front door while the side window (CAN-over-TCP) was wide open.
- **"Don't replay" != "can't forge".** A rolling code stops replay, but this one's freshness value only
  depended on the per-second broadcast (`579`) and was readable live by pressing a button; the message
  authenticator didn't bind the command, and integrity was a 1-byte XOR. Those three together collapse the
  scheme. Real keyless-entry rolling codes (KeeLoq/HITAG) use a secret key + crypto counter - none here.
- **XOR every captured frame first.** Constant-XOR across all frames (`0xEB`) instantly reveals a checksum
  byte and which byte is derived vs. free. That one observation turned "uncrackable PRNG" into "compute the
  parity byte."
- **Isolate each field by controlled pressing.** Rapid-fire same-action presses within one rolling-code
  second showed `b0`/`b3` constant (code-only) and `b2` counter-driven; pressing different actions at the
  same code proved `b0`/`b3` are action-independent. Changing one variable at a time beats trying to crack
  the whole blob.
- **Use the bus timestamps for correlation**, and verify the exploit on a *reversible, observable* channel
  (the immobiliser) before firing the real one (the doors).

## Reproduction notes

- No `can-utils`/`python-can` needed; a plain Python socket speaking socketcand's text protocol worked
  (`scratchpad/thm_socketcand.py` capture, `thm_pair.py` ts-pairing, `thm_solve.py`/`thm_brute.py` forge).
- A pasted community write-up described a *different variant* (CAN ID `0x296`, prefix `00 F4 1C 00`,
  checksum const `0xD2`, action byte `0x22`, unlock in `0x70..0x7F`). **The per-deployment constants differ**
  - this instance was ID `0x2BF`, framing `7E 26 .. 82`, XOR const `0xEB`, unlock `0xE8` - so the values
  had to be derived from the live bus, not copied.
- Flag is a disposable THM lab value.

## Related

- [[host-server-configuration-reviews]] / [[linux-privilege-escalation-enumeration]] - same method:
  enumerate the real attack surface, change one variable at a time, verify empirically before acting.
- [[directory]] - another "reverse the protocol from a capture" problem (NTLM-sealed WinRM there, CAN here).
