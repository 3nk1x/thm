# Network Reconnaissance & Protocols (TryHackMe)

- **Path:** Jr Penetration Tester → Network Reconnaissance / Network Security
- **Rooms:** Passive Reconnaissance · Active Reconnaissance · Protocols and Servers · Protocols and Servers 2
- **Completed:** 2026-10-06
- **Worked from:** own Windows PC over THM OpenVPN (not the AttackBox)

Reference for the recon toolset and the five cleartext protocols, plus the attacks against them.

## Passive Reconnaissance (no packets to the target)

Observe from public sources only — stealthy, low-risk, step 1 of every engagement.

| Tool | Purpose | Example |
|---|---|---|
| `whois` / RDAP | Domain registration (registrar, dates, name servers) | `curl -s https://rdap.verisign.com/com/v1/domain/tryhackme.com` |
| `nslookup` / `dig` | DNS records (A, AAAA, MX, TXT, NS, SOA) | `nslookup -type=TXT thmlabs.com <ip>` |
| DNSDumpster | Subdomain discovery (aggregated public DNS) | web: dnsdumpster.com |
| crt.sh | Subdomains via Certificate Transparency logs | web: search `%.tryhackme.com` |
| Shodan.io | Internet-exposed devices/services, ports, banners | web / facet pages |

- **Passive** = WHOIS, DNS, crt.sh, Shodan, social media, Google Dorking (no contact).
  **Active** = port/vuln scanning, pinging, *or any direct contact with a person*.
- Query public resolvers (`<ip>`) to keep lookups off your ISP's logs.
- TryHackMe facts found: registered ***(find it yourself)***, registrar ***(find it yourself)***,
  name servers ***(find it yourself)***. Apache is #1 country ***(find it yourself)***; nginx top port
  ***(find it yourself)***, Apache 3rd port ***(find it yourself)***.

## Active Reconnaissance (direct contact — leaves logs)

| Tool | Reveals | Key notes |
|---|---|---|
| Browser DevTools | headers, JS source, certs (SANs) | Sources tab → read `script.js` etc.; Console `Object.keys(x).length` |
| `ping` | reachability + TTL (OS hint) | TTL ~64 Linux, ~128 Windows; Windows uses `-n`, Linux `-c` |
| `traceroute`/`tracert` | routers/hops on the path | works by incrementing TTL; `*` = router suppresses ICMP |
| `telnet` / `ncat` | banner grabbing (service + version) | connect to a port, read/ send protocol commands |

- **Banner grabbing**: HTTP needs a nudge (`GET / HTTP/1.1` + `host:`); FTP/SMTP/POP3 greet you first.
- Version strings (`Apache/2.4.61`, `vsFTPd`, `Postfix`) → look up CVEs. Defenders hide these.
- `curl -I http://IP` = clean HTTP header grab.

## Protocols and Servers (five cleartext protocols)

All send data — **including credentials — in cleartext**. Speak them by hand with `ncat IP PORT`.

| Protocol | Port | Key commands | Secure form (port) |
|---|---|---|---|
| HTTP | 80 | `GET /path HTTP/1.1` + `host: x` + blank line | HTTPS (443) |
| FTP | 21 | `USER` / `PASS`; needs a real client for files (2 channels) | FTPS 990 / SFTP 22 |
| SMTP | 25 | `HELO`/`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `.` | SMTPS 465 / STARTTLS 587 |
| POP3 | 110 | `USER`/`PASS`, `STAT`, `LIST`, `RETR n`, `DELE n` | POP3S 995 |
| IMAP | 143 | `cN LOGIN user pass`, `LIST "" "*"`, `EXAMINE INBOX` | IMAPS 993 |

- **STAT reply** = `+OK <count> <size>` (ours was `+OK 0 0` = empty inbox).
- **FTP active vs passive**: active = *server* opens data channel back (breaks behind NAT);
  passive = *client* opens both (firewall-friendly). Over VPN use passive (curl does this).
- **Email path**: MUA → MSA → MTA → MDA → MUA. SMTP sends; POP3/IMAP receive.
  POP3 = download-and-delete (one device); IMAP = stays on server, syncs everywhere.
- **Email spoofing works** because SMTP never verifies `MAIL FROM` — no built-in sender auth
  (SPF/DKIM/DMARC bolted on later).

## Protocols and Servers 2 (attacks + encryption)

- **CIA ↔ DAD**: Confidentiality↔Disclosure (sniffing), Integrity↔Alteration (MITM),
  Availability↔Destruction (DoS).
- **Sniffing** (confidentiality/disclosure): capture cleartext creds.
  `sudo tcpdump port 110 -A` (tcpdump filters by **port**); Wireshark display filter = **protocol name** (`imap`, `pop`, `telnet`).
- **MITM** (integrity/alteration): get in the middle (ARP/DNS spoof, rogue AP, BGP hijack);
  beat TLS via SSL stripping or fake/rogue-CA certs. Defences: HSTS, Cert Transparency, pinning, DANE.
  Tools: Bettercap (3 ways to invoke), Ettercap (3 interfaces), mitmproxy, Responder (Windows/AD).
- **TLS**: implicit TLS (dedicated port, encrypted from byte 1) vs STARTTLS (upgrade on same port,
  strippable). **DoT** = DNS over TLS (853); DoH = DNS over HTTPS (443).
- **SSH** (replaces Telnet): confidentiality + integrity + server identity. Port 22.
  Key auth > password; `ssh-keygen -t ed25519`, public key → `~/.ssh/authorized_keys`.
  File transfer: **SFTP** (preferred) / SCP (deprecated) / rsync-over-ssh. `scp SOURCE TARGET`.
- **Password attacks**: guessing, dictionary, brute force, credential stuffing, spraying, hybrid.
  **Hydra**: `hydra -l lazie -P /usr/share/wordlists/rockyou.txt 10.x imap`
  (`-l`/`-L` user, `-p`/`-P` pass, `-s` port, `-t` threads, `-f` stop at first, `-V` verbose).
  Hydra = live services; **hashcat/John** = offline hash cracking.
  Mitigations: lockout, rate-limit, CAPTCHA, MFA, passkeys, breached-password checks.

## Practical workflow on own Windows PC (gotchas we hit)

- **nmap/ncat over VPN**: must use `nmap -sT -Pn` (connect scan + skip ping). `nc` doesn't exist → use `ncat`.
- **VPN drops on idle.** Symptom: `Reply from <ip>: Destination net unreachable` (a gateway
  error, NOT the target) + DCO adapter `Media disconnected`. Reconnect:
  `& "C:\Program Files\OpenVPN\bin\openvpn-gui.exe" --command connect thm`, wait ~10s for a `192.168.180.x` IP.
  Ping outcomes: `net/host unreachable`=routing/VPN down · `Request timed out`=host up, ICMP firewalled · `Reply ... TTL=`=success.
- **PowerShell quirks**:
  - Quoted exe path at line start needs the call operator: `& "C:\path\tool.exe" args`.
  - `curl` is an alias for `Invoke-WebRequest` → use **`curl.exe`** for the real curl (same for `wget.exe`).
- **scp** = `scp SOURCE TARGET` (both required); `user@ip:file` = remote side, `.` = local folder.
  Don't run it from `C:\Windows\System32` (no write perms) — `cd ~` first.
- Password prompts show nothing as you type (normal); right-click pastes in PowerShell to avoid typos.

## Nmap — Live Host Discovery (who's up?)

Default behaviour: Nmap ping-sweeps to find live hosts, then port-scans only those.
`-sn` = host discovery only (no port scan). Privileged (root/sudo) vs unprivileged changes
which probes Nmap can send.

**Target specification**
- List: `nmap a.b.c.d example.com` · Range: `<ip>-20` (6 IPs) · `10.10.0-255.101-125` (256×25=6400)
- Subnet: `IP/24`=256, `/25`=128, `/26`=64, `/27`=32, `/28`=16, `/29`=8, `/30`=4
- `/29` of `<ip>` = block `.8–.15`; first scanned = `<ip>`
- `-iL hosts.txt` (from file) · `-sL` (list scan: what it *would* scan, no probes) · `-n` (no DNS)

**Discovery probe flags**

| Flag | Scan | Notes |
|---|---|---|
| `-PR` | ARP ping | same subnet ONLY (L2, can't cross a router); best for local/post-exploit |
| `-PE` | ICMP Echo (type 8→0) | often firewalled (Windows blocks by default) |
| `-PP` | ICMP Timestamp (13→14) | alt when echo blocked |
| `-PM` | ICMP Address Mask (17→18) | usually all blocked |
| `-PS<port>` | TCP SYN ping | **no privilege needed** (falls back to full handshake); default port 80 |
| `-PA<port>` | TCP ACK ping | **needs root** (crafts raw ACK → expects RST) |
| `-PU<port>` | UDP ping | closed UDP port → ICMP port-unreachable = host up |
| `-R` / `-n` | force rDNS on all / no DNS | hostnames leak roles (dc01, mail, jenkins) |

Port syntax joins the flag: `-PS23` (telnet), `-PS21-25`, `-PS80,443,8080`. Masscan = faster
equivalent: `masscan <ip>/24 -p443`.

**KEY LESSON (proven live on the <ip>/24 lab):** no single probe is complete.
Same subnet: `-PE`→3 hosts, `-PP`→2, `-PM`→0, **TCP multi-port→4**. The Windows host
`<ip>` blocked ICMP (invisible to ping) but answered on RDP/3389 → TCP discovery found it.
**If a host "looks down," switch probe types before believing it.** ARP never lies on-subnet
(hosts can't block ARP); ICMP undercounts; TCP catches firewalled hosts.

**Env gotcha:** this room runs on its own `10.200.x` network — the general Premium VPN
(`192.168.180.x`) does NOT route to it. Download the room-specific `.ovpn`, install it into
`C:\Users\viore\OpenVPN\config\`, connect by its profile name. Own PC lands on `10.200.5.x`
(a subnet away from `10.200.6.x` targets) → ICMP/TCP discovery works, but **ARP (`-PR`) needs
the AttackBox** (it's placed on the target segment).

## Nmap — Basic Port Scans (which ports are open?)

After host discovery, scan ports. **Port states (6):** open ⭐, closed, filtered,
unfiltered (`-sA` only), open|filtered, closed|filtered. `open` = listening service = attack surface.

**Scan types**

| Flag | Scan | How it works | Privilege |
|---|---|---|---|
| `-sT` | TCP Connect | full handshake SYN→SYN/ACK→ACK, then RST | **none** (OS connect) |
| `-sS` | TCP SYN ("half-open"/stealth) | SYN→SYN/ACK→**RST** (never completes) | **root/raw** |
| `-sU` | UDP | closed→ICMP port-unreachable; open→usually silent | **root/raw** |
| `-sA` | TCP ACK | maps firewall rules (unfiltered vs filtered) | root/raw |

- `-sS` is the **default when privileged**; `-sT` is the only option when unprivileged.
- **SYN/ACKs received = number of open ports** (only open TCP ports reply SYN/ACK).
- **UDP is inverted:** silence may = open (`open|filtered`); the ICMP *error* confirms closed. `-sU` is SLOW — always scope (`--top-ports 10`, `-p53,161`). Combine: `nmap -sS -sU ...`.
- Service names come from nmap's table: 53=`domain` (not "dns"), 3389=`ms-wbt-server`, 161=`snmp`.

**Port scoping & performance**

| Flag | Effect |
|---|---|
| `-p22,80,443` / `-p1-1023` / `-p-` | list / range / ALL 65535 |
| `-F` / `--top-ports 10` | fast top-100 / top-N |
| `-r` | consecutive order (not random) |
| `-T0..-T5` | paranoid→insane; default `-T3`; **`-T4` for CTFs**, `-T1` for stealth |
| `--min-rate`/`--max-rate <n>` | packets/sec floor/ceiling |
| `--min-parallelism=64` | ≥64 concurrent probes |

**OWN-PC / VPN reality:** `-sS`/`-sU`/`-sA` need raw packets → on Windows over the DCO tunnel
they hit `pcap_activate(eth2) FAILED` + non-admin block. Use **`-sT -Pn`** (connect scan + skip
the raw-packet ping that also triggers the pcap error). Speed up the laggy link with
`-T4 --min-parallelism 50`. Scope tight: targeted `-p` finished in 0.6s vs 137s for top-1000.
`-sS`/`-sU` are AttackBox/Kali territory; answers there match `-sT`'s anyway.

## Flags collected

| Room / task | Flag |
|---|---|
| Passive Recon — thmlabs.com TXT | `THM{…}` |
| Protocols & Servers — HTTP `/flag.thm` | `THM{…}` |
| Protocols & Servers — FTP `ftp_flag.thm` | `THM{…}` |
| Protocols & Servers — SMTP banner | `THM{…}` |
| Protocols & Servers 2 — IMAP pass (lazie) | `<redacted-pw>` |

Other answers: Active Recon web questions = ***(find it yourself)***; ping replies = ***(find it yourself)***;
port 80 = ***(find it yourself)***; port 21 = ***(find it yourself)***; POP3 STAT = ***(find it yourself)***
(an empty inbox reads `+OK <count> <size>`).
