# Hydra (TryHackMe)

- **Path:** Jr Penetration Tester - module "Password Attacks".
- **Room:** Hydra (beginner, ~45 min) - fast network logon cracker.
- **Date:** 2026-10-13.
- **Target (Lab Machine):** `<ip>` (ports 80 web login, 22 SSH).
- **Attacker:** TryHackMe AttackBox (`<ip>`), which ships Hydra and
  `/usr/share/wordlists/rockyou.txt` preinstalled.
- **Status:** SOLVED. Both passwords cracked live with Hydra on the AttackBox. The two `THM{…}`
  flag values printed on the box during the run but were not logged into these notes; formats
  recorded below.

## Results

| Flag | Service | Username | Password cracked | Flag value |
|---|---|---|---|---|
| 1 | Web form (`POST /login`) | molly | `<redacted-pw>` | `THM{…}` (captured, not logged) |
| 2 | SSH | molly | `<redacted-pw>` | `THM{…}` (captured, not logged) |

## What Hydra is

Hydra is an **online** password brute-forcer: it sends login guesses to a live service and reads
the real responses to tell which one works. This is the opposite of **offline** cracking (John the
Ripper, Hashcat), which works on a stolen hash with no network involved. Hydra supports many
protocols (SSH, FTP, SMTP, RDP, SMB, HTTP forms, and more); you give it a username (or list) and a
password list and it tries each combination, in parallel, until it finds a valid pair.

The skill is describing the login accurately to Hydra: **where** to send the attempt, **how** the
credentials are formatted in the request, and **how to distinguish a failed login from a success**.

### Key options

| Option | Meaning |
|---|---|
| `-l <name>` | single login name. `-L <file>` = list of names |
| `-P <file>` | password list. `-p <pass>` = a single password |
| `-t <n>` | parallel threads (`-t 4` for SSH; keep SSH low or it drops connections) |
| `-s <port>` | target a non-default port |
| `-V` | verbose: print every attempt |
| `-f` | stop at the first valid pair |

The final argument is the service: a bare module like `ssh`, or `http-post-form` with a
colon-separated string.

### The http-post-form string

```
"<path>:<body>:<failure-marker>"
```

- **path** - where the form POSTs, e.g. `/login`.
- **body** - the POST data with `^USER^` and `^PASS^` placeholders Hydra substitutes, e.g.
  `username=^USER^&password=^PASS^`.
- **failure-marker** - `F=` plus a string that appears only on a failed login (e.g. `F=incorrect`).
  Hydra treats the attempt as failed while that string is present; when it disappears, that is a
  hit. Use `S=` to match on a success string instead.

Find the path, exact field names, and failure text from the browser DevTools Network tab: submit a
wrong login once and read the POST request and the response body.

## Task 2 - cracking molly

### Flag 1: web form

```
hydra -l molly -P /usr/share/wordlists/rockyou.txt <ip> \
  http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V
```

Result:

```
[80][http-post-form] host: <ip>   login: molly   password: <redacted-pw>
```

Then log in at `http://<ip>` as `molly` / `<redacted-pw>`; the dashboard shows flag 1.
(Terminal alternative: `curl -s -L -c /tmp/c -d "username=molly&password=<redacted-pw>"
http://<ip>/login | grep -io "THM{…}]*}"`.)

### Flag 2: SSH

```
hydra -l molly -P /usr/share/wordlists/rockyou.txt <ip> -t 4 ssh
```

Result:

```
[22][ssh] host: <ip>   login: molly   password: <redacted-pw>
1 of 1 target successfully completed, 1 valid password found
```

Then `ssh molly@<ip>` (password `<redacted-pw>`) and `cat flag2.txt` in molly's home directory.

## Gotchas hit this session

- **`<IP>` is a placeholder, not literal.** Typing the command with the angle brackets gave
  `bash: IP: No such file or directory`, because bash read `<IP>` as input redirection from a file
  named `IP`. Replace the whole `<IP>` token (brackets included) with the real address.
- **VPN dropped mid-session.** The standard TryHackMe VPN tunnel went down (all OpenVPN adapters
  showed "Media disconnected", no `10.x` address, no route to `<ip>/...`), so the box was
  unreachable from the local Windows PC. Fix was to pivot to the AttackBox, which is already on the
  THM network and has Hydra plus rockyou, so no VPN is needed. Diagnose VPN state with
  `ipconfig | findstr /i "10."` - a `10.x` address means the tunnel is up.
- The lab machine keeps the same THM IP whether reached via personal VPN or the AttackBox.

## Lessons learned

- Hydra is online brute force (noisy, network-bound, rate-limited by the service); offline cracking
  (John/Hashcat) is for hashes you already have. Pick the tool by what you hold: a live login vs. a
  hash.
- The whole trick with `http-post-form` is the failure marker. Get it wrong and Hydra either
  reports every password as valid (marker never matched) or never finds the real one (marker
  matches even on success). Verify it against a real failed login in DevTools first.
- Keep SSH threads low (`-t 4`); high concurrency makes sshd drop connections and produces false
  negatives.
- Weak, common passwords (`<redacted-pw>`, `<redacted-pw>`) fall to a wordlist in seconds. This is the
  practical argument for long, unique, non-dictionary passwords and for lockout/rate limiting.
- Related: these are credential attacks against the authentication layer - compare with the
  OWASP A07 Authentication Failures work in
  [owasp-2025-iaaa-failures](owasp-2025-iaaa-failures.md), and the credential-harvesting angle in
  [phishing-basics](phishing-basics.md).

## Status

Room complete. Both passwords cracked and both flags retrieved live on the AttackBox; only the
exact `THM{…}` flag strings are missing from these notes (they displayed on the box during the
run). Paste them to fill the two placeholders in the results table.
