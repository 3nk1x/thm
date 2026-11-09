# Net Sec Challenge (TryHackMe)

Room: Net Sec Challenge (Jr Penetration Tester → Network Security module capstone)
Completed: 2026-10-28 | Target: <ip> | Tools: nmap, ncat, Python (ftplib), socket.io client
Solved headless from the Windows PC over the THM OpenVPN tunnel.

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | Highest open port < 10,000 | *(find it yourself)* |
| 2 | Open port above 10,100 | *(find it yourself)* |
| 3 | How many TCP ports are open | *(find it yourself)* |
| 4 | Port 80 service version value | `THM{…}` |
| 5 | Flag in the SSH server header | `THM{…}` |
| 6 | FTP server version (nonstandard port) | *(find it yourself)* |
| 7 | Flag in eddie/quinn FTP account file | `THM{…}` |
| 8 | Flag from the 8081 covert-scan challenge | `THM{…}` |

## Open ports (full SYN scan)

```
22/tcp    open  ssh         OpenSSH 8.2p1  (banner: THM{…})
80/tcp    open  http        Server: THM{…}
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
8081/tcp  open  http        Node.js/Express + socket.io  (covert-scan challenge)
10001/tcp open  (no banner)
10121/tcp open  ftp         vsFTPd 3.0.5
```

Total open TCP = ***(find it yourself)***. Highest under 10,000 = ***(find it yourself)***. The port above 10,100 = ***(find it yourself)***.

## Steps

1. **Connectivity.** Target unreachable at first — the OpenVPN client was on a stale room config
   with no route to `<ip>/12`. Reconnected the `thm.ovpn` (ap-south-1) profile; route came up.
2. **Banner flags (no scan needed).**
   - SSH: `printf '\n' | ncat -w4 <ip> 22` → `SSH-2.0-OpenSSH_8.2p1 THM{…}`.
   - HTTP: `curl -sI http://<ip>/` → `Server: THM{…}`.
3. **Full port scan.** `nmap -Pn -sS -p- --min-rate 1800 -T4 <ip>` → the 7 open ports above.
4. **FTP (port 10121).** Banner `220 (vsFTPd 3.0.5)`. Anonymous denied. Brute-forced eddie/quinn
   with rockyou (threaded `ftplib`): `eddie:<redacted-pw>` (home empty), `quinn:<redacted-pw>` →
   `ftp_flag.txt` = `THM{…}`.
5. **8081 covert-scan challenge** (the hard one — see below) → `THM{…}`.

## The 8081 IDS-evasion challenge (how it actually works)

Browsing `http://<ip>:8081` shows a "Chance of scan being detected" meter fed by socket.io. The
Node server sniffs traffic and the flag is pushed as a `won-exercise` socket event once you scan the
host **without the detector counting your probes**.

Reverse-engineered behaviour (via a scripted socket.io listener watching the `packet-count` events):

- The meter counts **SYN probes to closed ports** (ordinary scan noise). Idle = 0.
- Probing **open** ports did **not** increment it (looks like legitimate traffic).
- Therefore any SYN/connect scan of the range maxes the meter to 100 (thousands of closed ports);
  staying "green" by scanning only a handful of ports never triggered the win. Decoys (`-D`) didn't
  help (my real IP still sends every packet) and fragmentation (`-f`) was still counted.
- **Winning move: a NULL scan.** `nmap -Pn -sN -p- <ip>` sends packets with no SYN flag, so the
  SYN-watching detector never counts them — the meter stayed at **0** through a full-range scan and
  the server released `won-exercise: THM{…}`. (`-sF` Xmas/`-sX` would work the same.)

## Lessons

- **Ping ≠ reachability.** "Destination net unreachable" from a non-THM gateway meant the lab route
  wasn't installed — always check `Get-NetRoute` for the lab subnet before blaming the scan.
- **Windows + OpenVPN DCO blocks raw packets.** nmap's `-sS`/`-sN`/`-D`/`-f` need npcap capture,
  which the DCO adapter doesn't expose. Forcing `disable-dco` + `windows-driver tap-windows6` in the
  `.ovpn` put the tunnel on a capturable TAP adapter and raw scans worked.
- **The Network Security module's whole point in one puzzle:** SYN/connect scans are loud; **NULL,
  FIN and Xmas scans evade SYN-based IDS/firewalls.** That's the intended 8081 solution.
- Over a lossy VPN, SYN scans are far faster/more reliable than connect scans for a drop-happy host;
  cap RTT (`--max-rtt-timeout`) or raise `--min-rate` rather than letting connect() time out per port.
```
