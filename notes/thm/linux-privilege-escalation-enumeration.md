# Linux Privilege Escalation: Enumeration (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Privilege Escalation (room 2; first hands-on Linux room,
  applying the enumeration methodology from [[host-server-configuration-reviews]]).
- **Room:** Linux Privilege Escalation: Enumeration (~60 min, free). Manual enumeration only - OS, users,
  network, files - no exploitation yet. Each task is self-contained.
- **Date:** 2026-10-16.
- **Status:** SOLVED - all 13 answers (Tasks 3-6), every value read live off the target, not guessed.
- **Lab:** target `<ip>` (`Linux_Privesc_enum_v2`), SSH `john : john`. Host is
  `linux-enumeration`, Ubuntu 24.04.1 LTS on AWS (kernel `6.8.0-1017-aws`). Connected over the THM VPN
  (TAP `<ip>`) from the Windows PC using Python `paramiko` for a non-interactive login.

## Answers

| Task | Question | Answer | Source |
|------|----------|--------|--------|
| 3 | Hostname | *(find it yourself)* | `hostname` |
| 3 | Kernel version | *(find it yourself)* | `uname -r` |
| 3 | Ubuntu version | *(find it yourself)* | `cat /etc/issue` |
| 3 | Script run by root every 5 min | *(find it yourself)* | `/etc/crontab` (`*/5 * * * * root ...`) |
| 3 | Full AppArmor version | *(find it yourself)* | `dpkg -l | grep apparmor` |
| 4 | `LANG` value | *(find it yourself)* | `env` / `echo $LANG` |
| 4 | Flag in history | `THM{…}` | `~/.bash_history` |
| 4 | Command allowed via sudo | *(find it yourself)* | `sudo -l` (`NOPASSWD`) |
| 4 | Mailing List Manager username | *(find it yourself)* | `/etc/passwd` (GECOS field) |
| 5 | Interface (not loopback) | *(find it yourself)* | `ip addr` / `ifconfig` |
| 5 | Port (other than 22) listening | *(find it yourself)* | `ss -tlnp` (systemd-resolved) |
| 6 | Secret file in home folder | `THM{…}` | `~/.hidden_secret.txt` |
| 6 | File with "TryHackMe" in its name | `THM{…}` | `/var/local/TryHackMe-flag.txt` |

## Enumeration commands (what produced each answer)

```bash
# --- OS (Task 3) ---
hostname                      # linux-enumeration
uname -a ; uname -r           # 6.8.0-1017-aws  (kernel -> search kernel exploits)
cat /etc/issue                # Ubuntu 24.04.1 LTS  (also /etc/os-release, /proc/version)
cat /etc/crontab              # */5 * * * * root /root/backup.sh   <- root cron, 5-min
ls -la /etc/cron.d/ ; cat /etc/cron.d/*    # other scheduled jobs
dpkg -l | grep -i apparmor    # 4.0.1really4.0.1-0ubuntu0.24.04.3  (full package version)

# --- Users (Task 4) ---
id                            # uid/gid/groups of john (1001)
env | grep -i lang            # LANG=C.UTF-8
cat ~/.bash_history           # echo THM{…}
sudo -l                       # (ALL) NOPASSWD: /usr/bin/nmap   <- escalation path!
cat /etc/passwd               # user list; GECOS of 'list' = "Mailing List Manager"
grep -i 'mailing list' /etc/passwd    # list:x:38:38:Mailing List Manager:/var/list:...

# --- Network (Task 5) ---
ip -brief addr                # lo + ens5 (<ip>/18)
ss -tlnp                      # :22 (sshd), :53 (systemd-resolved)

# --- Files (Task 6) ---
ls -la ~                      # reveals dotfiles: .hidden_secret.txt  (ls/ls -l hide it)
cat ~/.hidden_secret.txt      # THM{…}
find / -iname '*tryhackme*' -type f 2>/dev/null   # /var/local/TryHackMe-flag.txt
```

Command notes from the tasks:
- **OS fingerprint** feeds kernel-exploit search: `uname -a`, `/proc/version`, `/etc/issue` (any of these
  can be edited, so cross-check). `dpkg -l` lists installed packages/versions for vulnerable-binary hunting.
- **`ps aux`** (all users, with owner, incl. non-TTY) and **`ps axjf`** (process tree) show what's running
  and as whom.
- **`netstat -ano`** / modern **`ss -tlnp`** for listeners; a port bound to `0.0.0.0` vs `127.0.0.1` tells
  you local-only vs network-exposed. On 24.04, `ifconfig`/`netstat` are the legacy `net-tools`; `ip`/`ss`
  are the defaults.
- **`ls -la`** is mandatory - the whole point of Task 6 is that `.hidden_secret.txt` is invisible to plain
  `ls`/`ls -l`.
- **`find`** recipes worth keeping: `-perm -u=s -type f` (SUID), `-writable -type d` (world-writable dirs),
  `-perm -4000`/`-2000` (SUID/SGID), `-name 'pass*.txt'`, size/time filters; always append `2>/dev/null`.

## Lessons learned

- **Enumeration *is* the exploit-finding.** `sudo -l` immediately returned `(ALL) NOPASSWD: /usr/bin/nmap`
  - a direct root path (GTFOBins: old `nmap --interactive` -> `!sh`, or `--script`/`-oG` tricks) before any
  "exploitation" task. The `/root/backup.sh` root cron every 5 min is the other lead to come back to (check
  whether it, or anything it sources, is writable). Map findings to privesc categories as you go.
- **Read values off the host; never trust the mask.** The AppArmor answer is the *dpkg* version
  `4.0.1really4.0.1-0ubuntu0.24.04.3` (Ubuntu's "really" downgrade-guard string), not the
  `apparmor_parser --version` "4.0.1" - the long answer mask disambiguates which one the room wants, but the
  value still came from `dpkg -l`.
- **Hidden files hide in plain sight.** `ls`/`ls -l` showed nothing; `ls -la` exposed `.hidden_secret.txt`
  and `.bash_history` (which held a flag). History files are a real credential-leak source in the wild.
- **`/etc/passwd` is a mini-inventory.** `cut -d: -f1` for a brute-force userlist; `grep /home` for real
  humans (here `matt` 1002, `ubuntu` 1000, `john` 1001); the GECOS/comment field answers the "Mailing List
  Manager" question (`list`, uid 38).
- **net-tools is legacy on modern Ubuntu.** `ifconfig`->`ip addr`, `netstat`->`ss`. Know both; blog
  write-ups still use `netstat -ano`/`netstat -tulpn`.

## Reproduction notes

- Reached the lab over the THM OpenVPN TAP (`<ip>`); confirmed `<ip>:22` banner
  (`OpenSSH_9.6p1 Ubuntu`) before connecting. No `sshpass`/`plink` on the Windows box, so drove SSH with
  Python `paramiko` 5.0.0 (`scratchpad/thm_enum.py`, host/user/pass as argv).
- **Gotcha:** naming the script `enum.py` shadowed the stdlib `enum` module (Python's `re` imports it ->
  circular-import crash). Renamed to `thm_enum.py`. (The classic "don't name a script after a stdlib
  module" trap, same hazard as a planted `json.py`.)
- `sudo -l` run non-interactively via `echo 'john' | sudo -S -l`.
- Flags above are disposable THM lab values.

## Related

- [[host-server-configuration-reviews]] - the methodology this room executes (Phase 1 situational awareness
  = hostname/uname/id/role; Phase 2 category enumeration = users/files/services/cron/creds/network).
- [[privesc-module-plan]] - next up in the module: exploiting these findings (SUID, sudo/GTFOBins, cron,
  PATH, capabilities) on Linux, then Windows privesc.
- [[directory]] - the Windows/AD counterpart where enumeration (Kerberos user enum) kicked off the chain.
