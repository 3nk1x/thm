# Scheme Catcher - Payload Storage heap service (TryHackMe)

- **Path:** TryHackMe challenge room (binary exploitation / heap, themed around "Hopper" and
  "King Malhare's" command and control copy).
- **Date:** 2026-10-11 - **Target:** <ip> (standard THM VPN, DCO adapter <ip>).
- **Status:** PARTIAL. Recon and vulnerability analysis done live from own Windows PC. The lab
  machine went unresponsive (all three ports dropped at once while the VPN tunnel stayed healthy)
  before the heap exploit could be fired, so the shell-level solve was not completed in this
  session. Valentino had already recovered the hidden path and the final flag values from a public
  write-up; the exploit itself (the part the write-up skipped) was not reproduced end to end here.

## Flags (formats; values captured by Valentino, not recorded here)
| Question | Format |
|---|---|
| Flag hidden in the file | THM{…} |
| foothold.txt | THM{…} |
| user.txt | THM{…} |
| root.txt | THM{…} |

## Recon (observed)
Fast full-range TCP scan (own threaded Python scanner; local nmap on this host needs `-Pn -sT -n`
for the npcap issue). Three ports open:
- 22  OpenSSH 9.6p1 Ubuntu-3ubuntu13.14 (Ubuntu 24.04, current, not an entry point by itself).
- 80  Apache/2.4.58 (Ubuntu). Serves only a static "Under Construction" bunny page - a decoy.
- 9004 custom "Payload Storage Malhare's v4.2.0" service - the real target.

Web content worth noting: a `/dev/` directory existed with an auto-index (HTTP 200, ~937 bytes),
seen in a quick requests-based sweep but not read before the box dropped. The actual second stage
lived under a reverse-engineered hidden path (recovered by Valentino from a public write-up):
`/7ln6Z1X9EF/`, which exposed `foothold.txt` and a second-stage ZIP containing the challenge files:
`server`, `libc.so.6`, `ld-linux-x86-64.so.2`.

## The 9004 service (observed behaviour)
Unsolicited banner on connect, then a menu. The drive letters are a disguise for the usual
menu-heap verbs Create / Use / Delete / Exit:
```
Payload Storage Malhare's
Version 4.2.0
[1] C:    -> Create : prompts "size:"              (allocates a chunk, stores its pointer, count++)
[2] U:    -> Use    : prompts "idx:" "offset:" "data:"   (writes your bytes at chunk[idx] + offset)
[3] D:    -> Delete : prompts "idx:"               (frees chunk[idx])
[4] E:    -> Exit   : prints "Bye"
>>
```
Wire behaviour: plain line-based text over TCP. Create takes only a size (no content read at
create time). Use is the interesting one: it asks for an index, then an offset, then a line of
data.

Minimal client used to map the menu (one socket, read until the `>>` prompt):
```python
import socket, time
def recv_until(s, p=b'>>', t=6.0):
    s.settimeout(t); b=b''
    try:
        while True:
            d=s.recv(4096)
            if not d: break
            b+=d
            if p and b.rstrip().endswith(p): break
    except socket.timeout: pass
    return b
def session(cmds, host='<ip>', port=9004):
    s=socket.socket(); s.connect((host,port)); print(recv_until(s).decode(errors='replace'))
    for c in cmds:
        s.sendall((c+'\n').encode()); time.sleep(0.2)
        print(repr(c), '->', recv_until(s).decode(errors='replace'))
    s.close()
# session(['1','64','2','0','0','AAAA'])  # create 64, use idx0 at offset0, write "AAAA"
```

## The vulnerability (analysis)
- The index is bounds-checked: `Use`/`Delete` on an out-of-range or not-yet-created index returns
  `Invalid idx`. So the index is not the bug.
- The **offset in `Use` is NOT validated**. The write is effectively
  `write(chunk[idx] + offset, data)` with a fully attacker-controlled `offset` (negative or far
  beyond the chunk). That is an arbitrary relative write anchored on a heap pointer: an
  out-of-bounds write primitive.
- There is NO view/read option anywhere in the menu. A write primitive with no read is the classic
  shape of a challenge you beat either without a leak (fixed addresses) or by using the write to
  bootstrap a leak through another channel. The provided `libc.so.6` + `ld-linux-x86-64.so.2`
  strongly imply the intended path ends in a libc `system("/bin/sh")` or one-gadget, i.e. a
  ret2libc / hook-style finish rather than a simple built-in win function.

## Intended exploitation (plan; not executed to completion here)
With `server` + the exact `libc` in hand, the offline steps would be:
1. checksec the binary (PIE, RELRO, canary, NX) and recover the chunk-pointer array location and
   the exact number of bytes the `data:` step reads. Statically with pyelftools + capstone, same
   approach as the Jackpot ELF, no Linux runtime needed.
2. Use the unchecked-offset write to corrupt heap metadata or an adjacent stored pointer, turning
   the relative write into an arbitrary write (and, if needed, bootstrap a libc address leak).
3. Redirect control flow to a libc one-gadget or `system("/bin/sh")`, pinning offsets to the exact
   shipped `libc.so.6` (version read from its `.gnu.version_d` / banner string).
4. Fire against 9004 to land a shell = the `foothold.txt` user, then do the local privesc chain for
   `user.txt` and `root.txt`.

Question 1 ("flag hidden in the file") is almost certainly a string compiled into `server`; running
`strings` / a `.rodata` scan over the binary should surface the `THM{…}` directly, no exploitation
required.

## Lessons learned
- Behind a cutesy or disguised menu (drive letters C/U/D/E here), identify the real verbs first:
  a size prompt = Create, an index prompt = Use/Delete, an exit greeting = Exit. Prompt shapes map
  the program faster than guessing.
- When one input is validated and an adjacent one is not (index checked, offset unchecked), the
  unchecked one is the bug. An unchecked offset on a heap pointer is an out-of-bounds write.
- A write primitive with no read, shipped alongside a specific `libc` + `ld`, points to a
  ret2libc / hook finish rather than a built-in win function; grab the exact libc for offset work.
- Pwn rooms ship the target binary (and libc/ld) as Download Task Files, often behind a
  reverse-engineered hidden web path. Getting those files is the intended workflow; the heap work
  is meant to be done offline against the real binary, then fired at the live service.

## Env / blockers note
This room is on the standard THM premium VPN (DCO adapter <ip>). The target became
unreachable on all three ports simultaneously while the tunnel stayed up (so it was the lab machine
cycling, not local connectivity); THM boxes also block ICMP, so ping is not a reliable liveness
check here. curl over this link was flaky and timed out repeatedly where Python sockets/requests
succeeded; prefer the Python client for both the web pulls and the 9004 interaction. To finish:
re-start the lab machine, drop the Task Files ZIP into the scratchpad, build the exploit offline,
then run it against 9004.
