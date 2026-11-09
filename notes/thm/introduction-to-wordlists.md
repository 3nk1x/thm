# Introduction to Wordlists (TryHackMe)

- **Path:** Jr Penetration Tester - module "Password Attacks" (Premium room).
- **Room:** Introduction to Wordlists (~60 min) - build targeted wordlists via OSINT and use them
  with ffuf and Hydra.
- **Date:** 2026-10-13.
- **Target:** `<ip>`, vhosts `tryfinanceme.local` and `social.tryfinanceme.local`
  (both map to that IP; add to `/etc/hosts`, or send a `Host:` header).
- **Status:** SOLVED. Most of the room was worked live from the Windows PC over the THM VPN using a
  Python client with explicit `Host:` headers. The `words_clean.txt` count was finalised with the
  genuine CeWL on the AttackBox (a Python replica came within 5), giving the authoritative 161.

## Answers

| Task | Question | Answer |
|---|---|---|
| 2 | Tool to generate a wordlist from known patterns | *(find it yourself)* |
| 3 | Unique emails scraped by CeWL | *(find it yourself)* |
| 3 | PDF files found | *(find it yourself)* |
| 3 | Emails extracted from the PDFs | *(find it yourself)* |
| 3 | Last username in `users_from_emails.txt` | *(find it yourself)* |
| 4 | Words in `words_clean.txt` after cleaning | *(find it yourself)* |
| 4 | 10th password in `pass_helios.txt` | *(find it yourself)* |
| 4 | `sort` flag to remove duplicates | *(find it yourself)* |
| 4 | crunch template char for a digit | *(find it yourself)* |
| 5 | HTTP status ffuf reports for `helios/` | *(find it yourself)* |
| 5 | Username Hydra discovers | *(find it yourself)* |
| 5 | Flag | `THM{…}` |

## Task 2 - Wordlists (theory)

A wordlist is a text file of candidate strings (passwords, usernames, directory/file names,
subdomains) fed into tools for automated guessing. Uses: password cracking (John, Hashcat), login
brute forcing (Hydra, Medusa), directory enumeration (ffuf, Gobuster, DirBuster), subdomain
discovery (DNS tools). Sources: pre-made lists (`rockyou.txt` ~14.3M lines, SecLists), custom
OSINT-derived lists, and generators like **crunch** (exhausts a pattern/charset).

## Task 3 - gathering (OSINT)

Three categories of custom keyword: company-specific, technology-specific, generic. Methods: WHOIS,
subdomain/cert search (crt.sh, theHarvester, Sublist3r), site crawling (CeWL), tech fingerprinting
(Wappalyzer/BuiltWith/headers).

Findings on this target:

- **CeWL crawl of `tryfinanceme.local`** yields 4 unique emails: `careers@`, `contact@`, `ir@`,
  `security@` (`@tryfinanceme.com`). (CeWL command: `cewl -d 2 -m 3 --lowercase --with-numbers -e
  --email_file emails.txt -w cewl_words.txt http://tryfinanceme.local`.)
- **`/docs/` holds 1 PDF**: `2025-Analyst-Handbook.pdf`.
- **Emails inside the PDF** (4 unique, from `strings`/grep): `alex.johnson`, `careers`,
  `maria.chen`, `security` (`@tryfinanceme.com`). Two are new vs. the site (`alex.johnson`,
  `maria.chen`).
- **`users_from_emails.txt`** = local parts of the `sort -u`'d PDF emails:
  `alex.johnson`, `careers`, `maria.chen`, `security`. Alphabetically last = **`security`**.
- **`social.tryfinanceme.local`** lists employee names in `<h3 class="profile-name">` tags
  (Alex Johnson, Kevin Zhang, Maria Chen, ...). These feed three username formats:
  `first.last` (alex.johnson), `flast` (ajohnson), `firstl` (alexj).

## Task 4 - creating and cleaning

Cleaning pipeline (password/keyword list):

```
cat cewl_words.txt raw_words.txt | sort -u > words_raw.txt
cat words_raw.txt | tr '[:upper:]' '[:lower:]' | tr -d '\r' \
  | grep -P '^[a-z0-9][a-z0-9._-]{4,}$' | sort -u > words_clean.txt
```

- `sort -u` deduplicates (the `-u` flag).
- The grep keeps tokens that start alphanumeric and are >= 5 chars of `[a-z0-9._-]`.
- Result here: **161** words (from a 217-line `cewl_words.txt` plus the PDF strings). Head:
  `about, access, account, accuracy, advanced, analysis, analyst, analytics, analyze, assessment`.
  Includes `helios`, the keyword that leads to the hidden directory.

Pattern-based password list with crunch:

```
crunch 11 11 -t Helios20%%! -o pass_helios.txt
```

- `%` is crunch's digit placeholder; `@` lowercase, `,` uppercase, `^` symbol.
- `%%` expands `00`-`99` in order, so 100 passwords `Helios2000!` .. `Helios2099!`.
- 10th line = **`Helios2009!`** (line 1 is `Helios2000!`).

Username list: `cat users_first.last.txt users_flast.txt users_firstl.txt users_from_emails.txt |
sort -u > users.txt`.

## Task 5 - using the wordlist

**Directory discovery (ffuf):**

```
ffuf -w words_clean.txt -u http://tryfinanceme.local/FUZZ -e .php,.html,/ -mc 200,301,302
```

The keyword `helios` (scraped in Task 3) surfaces the hidden directory. Status codes observed:
`/helios` -> **301** (redirect to add the slash), `helios/` -> **200** (the login page). The
answer for the `helios/` entry is **200**.

**Login brute force (Hydra) against `http://tryfinanceme.local/helios/login.php`:**

```
hydra -L users.txt -P pass_helios.txt -f -V -t 4 tryfinanceme.local \
  http-post-form '/helios/login.php:username=^USER^&password=^PASS^:S=THM{'
```

- `S=THM{` is a **success** condition (response contains `THM{`), not a failure marker - this lab
  prints the flag on success, so matching on the flag prefix is the cleanest signal.
- Result: **`alex.johnson` : `<redacted-pw>`**.
- Logging in at `http://tryfinanceme.local/helios/` with those creds shows the flag:
  **`THM{…}`**.

## Lessons learned

- Targeted OSINT wordlists beat generic ones: the single scraped keyword `helios` found the hidden
  directory, and a 100-line crunch list (from a known `Helios20NN!` pattern) cracked the login in
  seconds, where rockyou would be overkill.
- CeWL harvests not just visible text but `<title>`, `<meta>` description/keywords, and alt text;
  the word `account` only came from a meta description. Matching that detail mattered to reproduce
  `words_clean.txt` exactly.
- Hydra's form triplet can match on success (`S=`) or failure (`F=`). When the app emits a unique
  success token (here the flag), `S=` is the most reliable.
- `helios` (no slash) returns 301 and `helios/` returns 200; ffuf's `-e /` tests the slashed form,
  so the reported code for `helios/` is 200.
- Cleaning (lowercase, dedup, length/charset filter) is what makes a scraped list usable; raw CeWL
  plus PDF strings is noisy.
- Related credential-attack notes: [hydra](hydra.md),
  [owasp-2025-iaaa-failures](owasp-2025-iaaa-failures.md), [phishing-basics](phishing-basics.md).

## Reproduction notes

Run from a VPN-connected host. Derived evidence (the downloaded PDF and the word-count replication
script) was kept in the session scratchpad, not in this repo, per the evidence-handling rule.

The `words_clean.txt` count must come from real CeWL, not a replica: a Python reproduction gave 156
(head matched the room's sample exactly) but the checker wanted **161**. Getting CeWL running on
the AttackBox took untangling a broken Kali package on Ruby 3.3:

1. `apt-get install -y cewl` (already present as 6.1), then install its gems:
   `gem install spider nokogiri mime mime-types mini_exiftool rubyzip` (note it needs both `mime`
   and `mime-types`).
2. The launcher does `require 'cewl_lib'`, but Ruby 3.3 dropped `.` from `$LOAD_PATH`, so pass the
   lib dir with `-I`. But `cewl_lib.rb` lives in `/usr/lib/ruby/vendor_ruby`, and adding that whole
   dir pulls in the system Ruby's rubygems and breaks gem loading (nokogiri "not installed").
   Fix: copy just `cewl_lib.rb` to a clean dir and point `-I` there:
   `mkdir -p /tmp/cl && cp /usr/lib/ruby/vendor_ruby/cewl_lib.rb /tmp/cl/`
   then `ruby -I /tmp/cl /usr/bin/cewl ...`.
3. Real CeWL then produced a 217-line `cewl_words.txt`; the clean pipeline yields `wc -l
   words_clean.txt` = 161.
