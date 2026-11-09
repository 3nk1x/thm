# Walking An Application — Manual Web Review (TryHackMe)

- **Path:** Jr Penetration Tester → Web Application Security Fundamentals
- **Room:** Walking An Application (Acme IT Support site)
- **Completed:** 2026-10-07
- **Target:** <ip> (10.49.x, general THM VPN)

Manually reviewing a web app with **only the browser's built-in tools** — no scanners.
Core thesis: **automated tools miss things; a human walking the app finds them.**

## Methodology — map the app first

Browse every page, note endpoint + purpose (login, signup, reset, dashboard, upload, etc.).
Interactive features = where the vulns live. Example endpoints found:
`/`, `/news`, `/news/article?id=N`, `/contact`, `/customers/login`, `/customers/signup`,
`/customers/reset`, `/customers` (dashboard), `/customers/ticket/new` (create ticket + file upload),
`/customers/account`, `/customers/logout`.

## The techniques (and what each surfaces)

| Technique | How | Finds |
|---|---|---|
| **View Source** (`Ctrl+U`, or `view-source:`) | read raw HTML/CSS/JS | dev **comments** (leaked URLs/notes), hidden **links**, framework + **version** |
| **Directory listing** | visit an asset dir (e.g. `/assets/`) | if listing is on → backup files, source, `flag.txt` |
| **Inspector** (Elements) | right-click → Inspect; edit live CSS/HTML | reveal **CSS-hidden** content (set `display:none` on a paywall `div`) |
| **Debugger / Sources** | Pretty-print JS, set **breakpoints** | pause JS to stop it hiding things (freeze a flash/redirect); read obfuscated logic |
| **Network** | watch requests; submit a form | **AJAX** endpoints + their **Response** bodies (`/contact-msg`), headers, cookies |
| **Storage** | Application/Storage tab | cookies (session tokens), Local/Session storage, and cookie **security flags** |

## Security findings this room demonstrates

- **HTML comments are dangerous** — a dev comment leaked a beta URL (`/new-home-beta`).
- **Hidden links** in source (`/secret-page`) expose "private" areas.
- **Directory listing enabled** → `/assets/flag.txt` readable (misconfiguration).
- **Outdated framework** (THM Framework v1.2): changelog v1.3 noted a backup left
  `/tmp.zip` in the webroot → downloaded it → source leak. **Keep software updated.**
- **CSS-only "paywall"** — content is in the HTML, only *visually* hidden (`display:block`).
  Client-side hiding ≠ access control.
- **Secrets in JS** — obfuscated `flash.min.js` built a flag and injected it; a breakpoint
  reveals it. Obfuscation ≠ security.
- **Insecure session cookie** — `Set-Cookie: session=...; path=/` with **no `HttpOnly`,
  no `Secure`, no `SameSite`**. HttpOnly=false → JS can read it (`document.cookie`) →
  XSS-stealable session. (Harden: HttpOnly + Secure + SameSite.)

## Flags

| Source | Flag |
|---|---|
| HTML comment (`/new-home-beta`) | `THM{…}` |
| Secret link (`/secret-page`) | `THM{…}` |
| Directory listing (`/assets/flag.txt`) | `THM{…}` |
| Framework (`/tmp.zip` → `flag.txt`) | `THM{…}` |
| Paywall (Inspector, base64-PNG in CSS) | `THM{…}` |
| Red box (Debugger breakpoint on `flash['remove']()`) | `THM{…}` |
| AJAX (`/contact-msg` Response) | `THM{…}` |
| Cookie HttpOnly value | *(find it yourself)* |
| Ticket-creation endpoint | *(find it yourself)* |

## How I pulled these without a GUI (for reference)

- Source/links/dir-listing/`tmp.zip`: `curl` + `grep` + `unzip`.
- Paywall: the flag was a **base64 PNG** in `div.imgflag`'s `background-image` → decoded
  (`base64 -d`) and viewed the image.
- Red box: ran obfuscated `flash.min.js` through **Node** with a fake `document` to capture
  what it set as the box's `innerHTML` (built char-by-char).
- AJAX: `curl -X POST /contact-msg`. Cookie: read `Set-Cookie` from the signup response.
