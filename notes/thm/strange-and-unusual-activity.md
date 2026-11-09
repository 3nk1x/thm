# Strange & Unusual Activity (TryHackMe, Downtime Challenge 07)

- **Event/module:** Strange & Unusual Activity ("Downtime" / ShowDowntime) blue-team CTF, 22 to 26 Oct 2026.
  Mission 07 of 8 (Challenge 4 of 5). **Network forensics** over Zeek logs in a SIEM. Difficulty: Medium.
- **Date:** 2026-10-24.
- **Status:** SOLVED. All 5 answers correct; +1 Tombstone raffle ticket (+90 team points).
- **Lab:** Kibana web interface at `http://<ip>:5601`, data view `zeek-*`, 24h of traffic from
  **07 October 2025** on the `<ip>/24` corporate network. Reached over the THM VPN from the Windows PC.
  Worked **headless** by tunnelling Elasticsearch queries through Kibana's console-proxy API (see Method).

## Reconstructed activity (compromised host `<ip>`)

1. **C2 over DNS/HTTPS:** host `<ip>` repeatedly resolved **`edge-metrics-sync.net`**, a domain
   dressed up as a telemetry/metrics endpoint. It was the **only fake domain** in the DNS top-list - tied for
   most-queried (289) alongside genuine services (`connectivitycheck.gstatic.com`, `incoming.telemetry.mozilla.org`,
   `registry.npmjs.org`, paypal/discord/office365, etc.), which is exactly how a beacon hides: blend into the
   telemetry noise.
2. **Resolved C2 IP:** every one of the 289 lookups answered **`<ip>`** (TEST-NET-3, RFC 5737
   documentation range - a planted stand-in for a real external C2, not routable Internet space).
3. **Beacon:** `zeek-conn` held exactly **289** TCP connections `<ip> -> <ip>` (one per DNS
   lookup). Inter-callback gaps spread **uniformly 248 to 354 s, mean 299.66 s** -> a **300 s base interval
   with +/-50 s jitter** (~16.7%).
4. **Exfiltration:** 288 of the callbacks were tiny check-ins; **one** connection sent **54,078,822 bytes**
   (`orig_bytes`, ~51 MB) outbound against a 320 B reply. Total outbound to the C2 was 54,505,171 B, so that
   single transfer was ~99% of it - the beacon's one large exfil burst.

## Answers

| # | Question | Answer |
|---|---|---|
| 1 | C2 domain | *(find it yourself)* |
| 2 | Callback interval (seconds) | *(find it yourself)* |
| 3 | Compromised host IP | `<ip>` |
| 4 | Number of check-ins (callbacks) | *(find it yourself)* |
| 5 | Largest single outbound transfer (bytes) | *(find it yourself)* |

## Method (headless, via Kibana console-proxy)

Elasticsearch `:9200` was firewalled; only Kibana `:5601` was reachable, with **no auth**. Kibana proxies raw
ES queries, so drive it from PowerShell with `Invoke-RestMethod`:

```powershell
$base="http://<ip>:5601"; $h=@{"kbn-xsrf"="true"}
function ESQ($path,$body){ Invoke-RestMethod -Uri "$base/api/console/proxy?path=$([uri]::EscapeDataString($path))&method=POST" `
  -Method Post -Headers $h -Body $body -ContentType "application/json" }

# indices: zeek-conn (5345) + zeek-dns (3995). query is a keyword field; id.resp_h/id.orig_h are ip (nested under id)
# 1) top DNS names -> spot edge-metrics-sync.net (fake among real services)
ESQ "zeek-dns/_search" '{"size":0,"aggs":{"q":{"terms":{"field":"query","size":50}}}}'
# 2) who queried it + what it resolved to
ESQ "zeek-dns/_search" '{"size":0,"query":{"term":{"query":"edge-metrics-sync.net"}},"aggs":{"src":{"terms":{"field":"id.orig_h"}},"ans":{"terms":{"field":"answers"}}}}'
# 3) callbacks + max outbound + all ts for interval math
$q='{"bool":{"filter":[{"term":{"id.orig_h":"<ip>"}},{"term":{"id.resp_h":"<ip>"}}]}}'
ESQ "zeek-conn/_search" ('{"size":0,"query":'+$q+',"track_total_hits":true,"aggs":{"ob":{"stats":{"field":"orig_bytes"}}}}')
# pull ts asc, delta = ts[i]-ts[i-1]; mean(deltas) = 299.66 ~ 300
```

## Lessons learned

- **The beacon hides in the telemetry, so compare, do not eyeball.** `edge-metrics-sync.net` was tied for the
  single most-queried domain; it only stood out once laid beside the rest of the top-50, which were all real
  services. A terms aggregation on the DNS `query` field surfaces the one plausible-sounding fake. (The room's
  own note: "not every malicious connection looks unusual on its own... compare the traffic.")
- **RFC 5737 / RFC 1918 ranges are tells.** The C2 resolved to `<ip>` = TEST-NET-3 documentation
  space. In a real hunt a C2 in `<ip>/24`, `<ip>/24` or `<ip>/24` is a planted lab
  artifact; treat any "external" address from those blocks as the flagged indicator.
- **Beacon interval = mean of the deltas, not the modal gap.** Jitter smears the per-gap histogram (no single
  value dominated; gaps ran 248 to 354 s), but the **mean of inter-callback deltas = total span / (n-1) =
  299.66 s** cleanly recovers the configured **300 s** base. Compute the mean; do not hunt for a repeated exact
  value when jitter is on.
- **Separate the exfil from the check-ins.** `stats` on `orig_bytes` showed max 54,078,822 vs a sum of
  54,505,171 - one connection is the whole story. "Largest single outbound transfer" = `max(orig_bytes)` on the
  host->C2 connections, not the sum and not `resp_bytes`.
- **No Elasticsearch? Tunnel through Kibana.** With `:9200` firewalled and `:5601` open and unauthenticated,
  `POST /api/console/proxy?path=...&method=POST` (header `kbn-xsrf: true`) runs arbitrary ES DSL - full
  aggregations headless from the PC, no clicking through Discover. `query` was a bare `keyword` (no
  `.keyword` subfield); `id.orig_h`/`id.resp_h` are `ip` fields nested under `id`.

## Related

- [[downtime-event]] - event tracker (Challenge 07 of 8; only Dead Endpoint left).
- [[repossessed]] - the SOC Sim, where the same actor exfiltrated to C2 `<ip>`; same playbook
  (beacon + archive + large outbound burst), here seen purely from the network side with no endpoint telemetry.
- [[the-waiting-room]] - Challenge 05, the other network-forensics mission (pcap vs Zeek/SIEM here).
- [[tryhackme-learning-buddy]] / [[ctf-workspace-dir]].
